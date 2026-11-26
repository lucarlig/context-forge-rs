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
    events::{HISTORY_BUDGET, Journal, Replay, parse_cursor},
    mcp::SessionSettings,
};

const MAX_SESSIONS: usize = 4096;
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_JOURNALS: usize = 128;

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
    ttl: Duration,
    last_seen: Mutex<Instant>,
    shutdown: CancellationToken,
    listener_open: AtomicBool,
    pending: Mutex<HashMap<RequestId, CancellationToken>>,
    journals: Mutex<VecDeque<Arc<Journal>>>,
    event_budget: Arc<Semaphore>,
    event_capacity: usize,
    event_ttl: Duration,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionError {
    Missing,
    InvalidHeader,
    NotFound,
    Forbidden,
    Capacity,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PendingError {
    DuplicateId,
    Capacity,
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

    fn sweep(&self, registry: &mut Registry) {
        let interval = Duration::from_secs(30)
            .min(self.settings.event_ttl)
            .min(self.settings.ttl);
        if registry.last_sweep.elapsed() >= interval {
            registry.entries.retain(|_, session| {
                if !session.active(false) {
                    return false;
                }
                session
                    .journals
                    .lock()
                    .expect("journal registry lock")
                    .retain(|journal| !journal.is_expired());
                true
            });
            registry.last_sweep = Instant::now();
        }
    }

    pub(crate) fn create(
        &self,
        owner: Option<&str>,
        server: Option<&str>,
    ) -> Result<(HeaderValue, Arc<Session>), SessionError> {
        let mut registry = self.registry.lock().expect("session map lock");
        self.sweep(&mut registry);
        let entries = &mut registry.entries;
        if entries.len() == MAX_SESSIONS {
            entries.retain(|_, session| session.active(false));
            if entries.len() == MAX_SESSIONS {
                return Err(SessionError::Capacity);
            }
        }
        loop {
            let id = HeaderValue::from_str(&Uuid::new_v4().simple().to_string())
                .expect("UUID consists of visible ASCII");
            if let std::collections::hash_map::Entry::Vacant(entry) = entries.entry(id.clone()) {
                let session = Arc::new(Session {
                    owner: owner.map(str::to_owned),
                    server: server.map(str::to_owned),
                    ttl: self.settings.ttl,
                    last_seen: Mutex::new(Instant::now()),
                    shutdown: self.settings.shutdown.child_token(),
                    listener_open: AtomicBool::new(false),
                    pending: Mutex::new(HashMap::new()),
                    journals: Mutex::new(VecDeque::new()),
                    event_budget: self.event_budget.clone(),
                    event_capacity: self.settings.event_capacity,
                    event_ttl: self.settings.event_ttl,
                });
                entry.insert(session.clone());
                return Ok((id, session));
            }
        }
    }

    pub(crate) fn access(
        &self,
        id: Option<&HeaderValue>,
        owner: Option<&str>,
        server: Option<&str>,
        delete: bool,
    ) -> Result<Arc<Session>, SessionError> {
        let id = id.ok_or(SessionError::Missing)?;
        let mut registry = self.registry.lock().expect("session map lock");
        self.sweep(&mut registry);
        let entries = &mut registry.entries;
        let session = entries.get(id).cloned().ok_or(SessionError::NotFound)?;
        let authorized = session.owner.as_deref() == owner && session.server.as_deref() == server;
        if !session.active(authorized && !delete) {
            entries.remove(id);
            return Err(SessionError::NotFound);
        }
        if !authorized {
            return Err(SessionError::Forbidden);
        }
        if delete {
            session.shutdown.cancel();
            entries.remove(id);
        }
        Ok(session)
    }
}

impl Session {
    pub(crate) fn start_journal(
        &self,
        principal: Option<&Principal>,
        needs_tool_execution: bool,
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
            needs_tool_execution,
            self.event_capacity,
            self.event_ttl,
            self.event_budget.clone(),
        ));
        journals.push_back(journal.clone());
        Some(journal)
    }

    pub(crate) fn replay(&self, cursor: &str) -> Option<(Arc<Journal>, Replay)> {
        let (key, sequence) = parse_cursor(cursor)?;
        let journals = self.journals.lock().expect("journal registry lock");
        let journal = journals
            .iter()
            .find(|journal| journal.key == key && !journal.is_expired())?;
        Some((journal.clone(), journal.resume(sequence)?))
    }

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

    pub(crate) fn listen(self: Arc<Self>) -> Option<Listener> {
        self.listener_open
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Listener(self))
    }

    pub(crate) fn track(self: Arc<Self>, id: RequestId) -> Result<PendingRequest, PendingError> {
        let mut pending = self.pending.lock().expect("pending request map lock");
        if pending.len() >= MAX_PENDING_REQUESTS {
            return Err(PendingError::Capacity);
        }
        let std::collections::hash_map::Entry::Vacant(entry) = pending.entry(id.clone()) else {
            return Err(PendingError::DuplicateId);
        };
        let token = entry.insert(self.shutdown.child_token()).clone();
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

pub(crate) struct Listener(Arc<Session>);

impl Listener {
    pub(crate) async fn wait_until_closed(&self) {
        self.0.wait_until_closed().await;
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.0.listener_open.store(false, Ordering::Release);
    }
}
