// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::http::HeaderValue;
use uuid::Uuid;

const MAX_SESSIONS: usize = 4096;

pub(crate) struct Sessions {
    ttl: Duration,
    entries: Mutex<HashMap<HeaderValue, Session>>,
}

struct Session {
    owner: Option<String>,
    server: Option<String>,
    last_seen: Instant,
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
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn create(
        &self,
        owner: Option<&str>,
        server: Option<&str>,
    ) -> Result<HeaderValue, SessionError> {
        let mut entries = self.entries.lock().expect("session map lock");
        if entries.len() == MAX_SESSIONS {
            entries.retain(|_, session| session.last_seen.elapsed() < self.ttl);
            if entries.len() == MAX_SESSIONS {
                return Err(SessionError::Capacity);
            }
        }
        let id = loop {
            let id = HeaderValue::from_str(&Uuid::new_v4().simple().to_string())
                .expect("UUID consists of visible ASCII");
            if let std::collections::hash_map::Entry::Vacant(entry) = entries.entry(id.clone()) {
                entry.insert(Session {
                    owner: owner.map(str::to_owned),
                    server: server.map(str::to_owned),
                    last_seen: Instant::now(),
                });
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
    ) -> Result<(), SessionError> {
        let id = id.ok_or(SessionError::Missing)?;
        let mut entries = self.entries.lock().expect("session map lock");
        let session = entries.get_mut(id).ok_or(SessionError::NotFound)?;
        if session.last_seen.elapsed() >= self.ttl {
            entries.remove(id);
            return Err(SessionError::NotFound);
        }
        if session.owner.as_deref() != owner || session.server.as_deref() != server {
            return Err(SessionError::Forbidden);
        }
        if delete {
            entries.remove(id);
        } else {
            session.last_seen = Instant::now();
        }
        Ok(())
    }
}
