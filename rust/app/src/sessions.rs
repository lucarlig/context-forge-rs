// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use axum::http::HeaderValue;
use rmcp::model::RequestId;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    access::Principal,
    events::{HISTORY_BUDGET, Journal, JournalMode, PassiveEvents, Replay, parse_cursor},
    mcp::{RedisSessionDirectory, SessionSettings},
    redis_events::RedisEventJournal,
    redis_sessions::RedisListener,
    upstream::{UpstreamAssociation, UpstreamEndpoint, UpstreamTransport},
};

const MAX_SESSIONS: usize = 4096;
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_JOURNALS: usize = 128;
const MAX_NOTIFICATION_SCOPES: usize = 32;
const MAX_UPSTREAM_ASSOCIATIONS: usize = 128;

pub(crate) struct Sessions {
    settings: SessionSettings,
    registry: Mutex<Registry>,
    event_budget: Arc<Semaphore>,
}

struct Registry {
    entries: HashMap<HeaderValue, Arc<Session>>,
    last_sweep: Instant,
}

pub(crate) struct Session {
    owner: Option<String>,
    server: Option<String>,
    lifetime: Arc<SessionLifetime>,
    listener_open: AtomicBool,
    pending: Mutex<HashMap<RequestId, CancellationToken>>,
    journals: Mutex<VecDeque<Arc<Journal>>>,
    passive: Mutex<HashMap<Option<[u8; 32]>, Arc<PassiveEvents>>>,
    redis: Option<(Arc<RedisSessionDirectory>, HeaderValue)>,
    get_stream_enabled: bool,
    event_budget: Arc<Semaphore>,
    event_capacity: usize,
    event_ttl: Duration,
    upstreams: Mutex<HashMap<UpstreamKey, Arc<UpstreamAssociation>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct UpstreamKey {
    gateway: String,
    endpoint: String,
    transport: UpstreamTransport,
    authorization: Option<[u8; 32]>,
    upstream_credentials: Option<[u8; 32]>,
}

pub(crate) struct SessionLifetime {
    ttl: Duration,
    last_seen: Mutex<Instant>,
    shutdown: CancellationToken,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionError {
    Missing,
    InvalidHeader,
    NotFound,
    Forbidden,
    Capacity,
    Remote(Uuid),
    Unavailable,
}

#[derive(Clone, Copy)]
pub(crate) enum SessionAccess {
    Get,
    Post,
    Delete,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PendingError {
    DuplicateId,
    Capacity,
}

pub(crate) fn new_session_id() -> HeaderValue {
    HeaderValue::from_str(&Uuid::new_v4().simple().to_string())
        .expect("UUID consists of visible ASCII")
}

impl Sessions {
    pub(crate) fn new(settings: SessionSettings) -> Self {
        Self {
            settings,
            registry: Mutex::new(Registry {
                entries: HashMap::new(),
                last_sweep: Instant::now(),
            }),
            event_budget: Arc::new(Semaphore::new(HISTORY_BUDGET)),
        }
    }

    pub(crate) fn get_stream_enabled(&self) -> bool {
        self.settings.get_stream_enabled
    }

    pub(crate) fn redis(&self) -> Option<&Arc<RedisSessionDirectory>> {
        self.settings.redis.as_ref()
    }

    pub(crate) fn local_exists(&self, id: &HeaderValue) -> bool {
        self.registry
            .lock()
            .expect("session map lock")
            .entries
            .contains_key(id)
    }

    pub(crate) fn affinity_forward_timeout(&self) -> Duration {
        self.settings.affinity_forward_timeout
    }

    fn sweep(&self, registry: &mut Registry) {
        let interval = Duration::from_secs(30)
            .min(self.settings.event_ttl)
            .min(self.settings.ttl);
        if registry.last_sweep.elapsed() >= interval {
            registry.entries.retain(|_, session| {
                if !session.lifetime.active(false) {
                    return false;
                }
                session
                    .journals
                    .lock()
                    .expect("journal registry lock")
                    .retain(|journal| !journal.is_expired());
                for journal in session
                    .passive
                    .lock()
                    .expect("passive events lock")
                    .values()
                    .filter_map(|journal| journal.local())
                {
                    journal.prune();
                }
                true
            });
            registry.last_sweep = Instant::now();
        }
    }

    pub(crate) async fn create(
        &self,
        owner: Option<&str>,
        server: Option<&str>,
    ) -> Result<(HeaderValue, Arc<Session>), SessionError> {
        let (id, session) = self.create_local(owner, server)?;
        if let Some(redis) = &self.settings.redis
            && let Err(error) = redis.register(&id, owner, server, self.settings.ttl).await
        {
            session.lifetime.shutdown.cancel();
            self.registry
                .lock()
                .expect("session map lock")
                .entries
                .remove(&id);
            return Err(error);
        }
        Ok((id, session))
    }

    fn create_local(
        &self,
        owner: Option<&str>,
        server: Option<&str>,
    ) -> Result<(HeaderValue, Arc<Session>), SessionError> {
        let mut registry = self.registry.lock().expect("session map lock");
        self.sweep(&mut registry);
        let entries = &mut registry.entries;
        if entries.len() == MAX_SESSIONS {
            entries.retain(|_, session| session.lifetime.active(false));
            if entries.len() == MAX_SESSIONS {
                return Err(SessionError::Capacity);
            }
        }
        loop {
            let id = new_session_id();
            if let std::collections::hash_map::Entry::Vacant(entry) = entries.entry(id.clone()) {
                let session = Arc::new(Session {
                    owner: owner.map(str::to_owned),
                    server: server.map(str::to_owned),
                    lifetime: Arc::new(SessionLifetime {
                        ttl: self.settings.ttl,
                        last_seen: Mutex::new(Instant::now()),
                        shutdown: self.settings.shutdown.child_token(),
                    }),
                    listener_open: AtomicBool::new(false),
                    pending: Mutex::new(HashMap::new()),
                    journals: Mutex::new(VecDeque::new()),
                    passive: Mutex::new(HashMap::new()),
                    redis: self
                        .settings
                        .redis
                        .as_ref()
                        .map(|redis| (redis.clone(), id.clone())),
                    get_stream_enabled: self.settings.get_stream_enabled,
                    event_budget: self.event_budget.clone(),
                    event_capacity: self.settings.event_capacity,
                    event_ttl: self.settings.event_ttl,
                    upstreams: Mutex::new(HashMap::new()),
                });
                entry.insert(session.clone());
                return Ok((id, session));
            }
        }
    }

    pub(crate) async fn access(
        &self,
        id: Option<&HeaderValue>,
        owner: Option<&str>,
        server: Option<&str>,
        access: SessionAccess,
    ) -> Result<Arc<Session>, SessionError> {
        let id = id.ok_or(SessionError::Missing)?;
        if let Some(redis) = &self.settings.redis {
            redis
                .access(id, owner, server, self.settings.ttl, access)
                .await?;
        }
        let delete = matches!(access, SessionAccess::Delete);
        let session = self.access_local(id, owner, server, delete);
        if matches!(session, Err(SessionError::NotFound))
            && !delete
            && let Some(redis) = &self.settings.redis
        {
            let _ = redis
                .access(id, owner, server, self.settings.ttl, SessionAccess::Delete)
                .await;
        }
        session
    }

    pub(crate) async fn listen(
        &self,
        id: &HeaderValue,
        session: Arc<Session>,
    ) -> Result<Option<Listener>, SessionError> {
        if session
            .listener_open
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(None);
        }
        let mut listener = Listener {
            session,
            shared: None,
        };
        if let Some(redis) = &self.settings.redis {
            let Some(shared) = redis
                .claim_listener(id, &listener.session.lifetime.shutdown)
                .await?
            else {
                return Ok(None);
            };
            listener.shared = Some(shared);
        }
        Ok(Some(listener))
    }

    pub(crate) fn shared_events(
        &self,
        redis: &Arc<RedisSessionDirectory>,
        id: &HeaderValue,
        authorization: Option<[u8; 32]>,
    ) -> Result<RedisEventJournal, SessionError> {
        RedisEventJournal::new(
            redis.clone(),
            id,
            authorization,
            self.settings.event_ttl,
            self.settings.event_capacity,
        )
    }

    pub(crate) async fn listen_shared(
        &self,
        redis: &Arc<RedisSessionDirectory>,
        id: &HeaderValue,
    ) -> Result<Option<RedisListener>, SessionError> {
        redis.claim_listener(id, &self.settings.shutdown).await
    }

    fn access_local(
        &self,
        id: &HeaderValue,
        owner: Option<&str>,
        server: Option<&str>,
        delete: bool,
    ) -> Result<Arc<Session>, SessionError> {
        let mut registry = self.registry.lock().expect("session map lock");
        self.sweep(&mut registry);
        let entries = &mut registry.entries;
        let session = entries.get(id).cloned().ok_or(SessionError::NotFound)?;
        let authorized = session.owner.as_deref() == owner && session.server.as_deref() == server;
        if !session.lifetime.active(authorized && !delete) {
            entries.remove(id);
            return Err(SessionError::NotFound);
        }
        if !authorized {
            return Err(SessionError::Forbidden);
        }
        if delete {
            session.lifetime.shutdown.cancel();
            entries.remove(id);
        }
        Ok(session)
    }
}

impl Session {
    pub(crate) fn upstream(
        &self,
        gateway: &str,
        endpoint: UpstreamEndpoint<'_>,
        authorization: Option<[u8; 32]>,
    ) -> Option<Arc<UpstreamAssociation>> {
        let key = UpstreamKey {
            gateway: gateway.to_owned(),
            endpoint: endpoint.url.to_owned(),
            transport: endpoint.transport,
            authorization,
            upstream_credentials: endpoint.credential_fingerprint(),
        };
        let mut upstreams = self
            .upstreams
            .lock()
            .expect("upstream session registry lock");
        if let Some(upstream) = upstreams.get(&key) {
            return Some(upstream.clone());
        }
        if upstreams.len() >= MAX_UPSTREAM_ASSOCIATIONS {
            return None;
        }
        let association = Arc::new(UpstreamAssociation::new(self.lifetime.clone()));
        upstreams.insert(key, association.clone());
        Some(association)
    }

    pub(crate) fn start_journal(
        &self,
        principal: Option<&Principal>,
        permission: Option<&'static str>,
    ) -> Option<Arc<Journal>> {
        if self.event_capacity == 0 {
            return None;
        }
        let mut journals = self.journals.lock().expect("journal registry lock");
        journals.retain(|journal| !journal.is_expired());
        if journals.len() >= MAX_JOURNALS {
            let completed = journals.iter().position(|journal| journal.is_finished())?;
            journals.remove(completed);
        }
        let journal = Arc::new(Journal::new(
            principal.map(Principal::authorization_fingerprint),
            JournalMode::Response { permission },
            self.event_capacity,
            self.event_ttl,
            self.event_budget.clone(),
        ));
        journals.push_back(journal.clone());
        Some(journal)
    }

    pub(crate) fn replay(&self, cursor: &str) -> Option<(Arc<Journal>, Replay)> {
        let (key, sequence) = parse_cursor(cursor)?;
        let journal = self
            .journals
            .lock()
            .expect("journal registry lock")
            .iter()
            .find(|journal| journal.key == key && !journal.is_expired())
            .cloned();
        let journal = journal.or_else(|| {
            self.passive
                .lock()
                .expect("passive events lock")
                .values()
                .filter_map(|journal| journal.local())
                .find(|journal| journal.key == key)
                .cloned()
        })?;
        let reader = journal.resume(sequence)?;
        Some((journal, reader))
    }

    pub(crate) fn passive_journal(
        &self,
        authorization: Option<[u8; 32]>,
    ) -> Option<Arc<PassiveEvents>> {
        if !self.get_stream_enabled || self.event_capacity == 0 {
            return None;
        }
        let mut streams = self.passive.lock().expect("passive events lock");
        if let Some(stream) = streams.get(&authorization) {
            return Some(stream.clone());
        }
        if streams.len() >= MAX_NOTIFICATION_SCOPES {
            return None;
        }
        let stream = if let Some((redis, id)) = &self.redis {
            PassiveEvents::Redis(
                RedisEventJournal::new(
                    redis.clone(),
                    id,
                    authorization,
                    self.event_ttl,
                    self.event_capacity,
                )
                .ok()?,
            )
        } else {
            PassiveEvents::Local(Arc::new(Journal::new(
                authorization,
                JournalMode::Passive,
                self.event_capacity,
                self.event_ttl,
                self.event_budget.clone(),
            )))
        };
        let stream = Arc::new(stream);
        streams.insert(authorization, stream.clone());
        Some(stream)
    }

    pub(crate) fn track(self: Arc<Self>, id: RequestId) -> Result<PendingRequest, PendingError> {
        let mut pending = self.pending.lock().expect("pending request map lock");
        if pending.len() >= MAX_PENDING_REQUESTS {
            return Err(PendingError::Capacity);
        }
        let std::collections::hash_map::Entry::Vacant(entry) = pending.entry(id.clone()) else {
            return Err(PendingError::DuplicateId);
        };
        let token = entry.insert(self.lifetime.shutdown.child_token()).clone();
        drop(pending);
        Ok(PendingRequest {
            session: self,
            id,
            token,
        })
    }

    pub(crate) fn cancel_request(&self, id: &RequestId) {
        if let Some(token) = self
            .pending
            .lock()
            .expect("pending request map lock")
            .get(id)
        {
            token.cancel();
        }
    }
}

impl SessionLifetime {
    fn active(&self, touch: bool) -> bool {
        let mut last_seen = self.last_seen.lock().expect("session timestamp lock");
        if last_seen.elapsed() >= self.ttl {
            self.shutdown.cancel();
        }
        if self.shutdown.is_cancelled() {
            return false;
        }
        if touch {
            *last_seen = Instant::now();
        }
        true
    }

    pub(crate) async fn wait_until_closed(&self) {
        while self.active(false) {
            let remaining = self.ttl.saturating_sub(
                self.last_seen
                    .lock()
                    .expect("session timestamp lock")
                    .elapsed(),
            );
            tokio::select! {
                () = self.shutdown.cancelled() => return,
                () = tokio::time::sleep(remaining) => {}
            }
        }
    }
}

pub(crate) struct PendingRequest {
    session: Arc<Session>,
    id: RequestId,
    pub(crate) token: CancellationToken,
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        self.session
            .pending
            .lock()
            .expect("pending request map lock")
            .remove(&self.id);
    }
}

pub(crate) struct Listener {
    session: Arc<Session>,
    shared: Option<RedisListener>,
}

impl Listener {
    pub(crate) async fn wait_until_closed(&self) {
        let session_closed = self.session.lifetime.wait_until_closed();
        if let Some(shared) = &self.shared {
            tokio::select! {
                () = session_closed => {},
                () = shared.wait_until_lost() => {},
            }
        } else {
            session_closed.await;
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.session.listener_open.store(false, Ordering::Release);
    }
}
