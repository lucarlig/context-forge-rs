// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use axum::http::HeaderValue;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::mcp::SessionSettings;

const MAX_SESSIONS: usize = 4096;

pub(crate) struct Sessions {
    settings: SessionSettings,
    entries: Mutex<HashMap<HeaderValue, Arc<Session>>>,
}

pub(crate) struct Session {
    owner: Option<String>,
    server: Option<String>,
    ttl: Duration,
    last_seen: Mutex<Instant>,
    shutdown: CancellationToken,
    listener_open: AtomicBool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionError {
    Missing,
    InvalidHeader,
    NotFound,
    Forbidden,
    Capacity,
}

impl Sessions {
    pub(crate) fn new(settings: SessionSettings) -> Self {
        Self {
            settings,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn get_stream_enabled(&self) -> bool {
        self.settings.get_stream_enabled
    }

    pub(crate) fn create(
        &self,
        owner: Option<&str>,
        server: Option<&str>,
    ) -> Result<HeaderValue, SessionError> {
        let mut entries = self.entries.lock().expect("session map lock");
        if entries.len() == MAX_SESSIONS {
            entries.retain(|_, session| session.active(false));
            if entries.len() == MAX_SESSIONS {
                return Err(SessionError::Capacity);
            }
        }
        let id = loop {
            let id = HeaderValue::from_str(&Uuid::new_v4().simple().to_string())
                .expect("UUID consists of visible ASCII");
            if let std::collections::hash_map::Entry::Vacant(entry) = entries.entry(id.clone()) {
                entry.insert(Arc::new(Session {
                    owner: owner.map(str::to_owned),
                    server: server.map(str::to_owned),
                    ttl: self.settings.ttl,
                    last_seen: Mutex::new(Instant::now()),
                    shutdown: self.settings.shutdown.child_token(),
                    listener_open: AtomicBool::new(false),
                }));
                break id;
            }
        };
        Ok(id)
    }

    pub(crate) fn access(
        &self,
        id: Option<&HeaderValue>,
        owner: Option<&str>,
        server: Option<&str>,
        delete: bool,
    ) -> Result<Arc<Session>, SessionError> {
        let id = id.ok_or(SessionError::Missing)?;
        let mut entries = self.entries.lock().expect("session map lock");
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

    async fn wait_until_closed(&self) {
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
