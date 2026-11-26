// SPDX-License-Identifier: Apache-2.0
//! Shared passive event journals. Redis Pub/Sub wakes readers; the journal owns delivery order.

use std::{collections::VecDeque, sync::Arc, time::Duration};

use axum::{http::HeaderValue, response::sse::Event};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use futures_util::{FutureExt, StreamExt};
use redis::{RedisResult, aio::PubSubStream};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    redis_sessions::{RedisSessionDirectory, session_key, ttl_millis},
    sessions::SessionError,
};

const JOURNAL_BYTES: usize = 8 * 1024 * 1024;

const APPEND: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
local used = tonumber(redis.call('GET', KEYS[3]))
if redis.call('EXISTS', KEYS[2]) == 0 then used = 0 end
if not used then
  redis.call('DEL', KEYS[2])
  used = 0
end
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local entry = ARGV[1] .. ':' .. string.format('%.0f', now + tonumber(ARGV[3])) .. ':' .. ARGV[2]
local count = redis.call('RPUSH', KEYS[2], entry)
used = used + string.len(entry)
while count > tonumber(ARGV[4]) or used > tonumber(ARGV[5]) do
  local evicted = redis.call('LPOP', KEYS[2])
  used = used - string.len(evicted)
  count = count - 1
end
redis.call('PEXPIRE', KEYS[2], ARGV[3])
redis.call('SET', KEYS[3], used, 'PX', ARGV[3])
redis.call('PUBLISH', KEYS[1] .. ':events', 'event')
return 1
"#;

const READ: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return {0, '', {}} end
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local frames = {}
local bytes = 0
local after = ARGV[1]
local found = after == ''
local tail = ''
for _, entry in ipairs(redis.call('LRANGE', KEYS[2], 0, -1)) do
  local sep = string.find(entry, ':', 34, true)
  local expires = sep and tonumber(string.sub(entry, 34, sep - 1))
  if expires and expires > now then
    local id = string.sub(entry, 1, 32)
    if found then
      if #frames == 16 or (#frames > 0 and bytes + string.len(entry) > 1048576) then break end
      bytes = bytes + string.len(entry)
      table.insert(frames, {id, string.sub(entry, sep + 1)})
    elseif id == after then
      found = true
    end
    tail = id
  end
end
if found then return {1, after, frames} end
if ARGV[2] == 'initial' or tail == '' then return {1, tail, {}} end
return {0, '', {}}
"#;

pub(crate) struct RedisEventJournal {
    directory: Arc<RedisSessionDirectory>,
    session: String,
    key: String,
    session_prefix: String,
    scope_prefix: String,
    retention: Duration,
    capacity: usize,
}

impl RedisEventJournal {
    pub(crate) fn new(
        directory: Arc<RedisSessionDirectory>,
        id: &HeaderValue,
        authorization: Option<[u8; 32]>,
        retention: Duration,
        capacity: usize,
    ) -> Result<Self, SessionError> {
        let session = session_key(id)?;
        let mut digest = Sha256::new();
        digest.update(id.as_bytes());
        if let Some(authorization) = authorization {
            digest.update(authorization);
        }
        let scope = BASE64_URL_SAFE_NO_PAD.encode(digest.finalize());
        let session_prefix = format!("r:{}:", id.to_str().map_err(|_| SessionError::NotFound)?);
        let scope_prefix = format!("{session_prefix}{scope}:");
        let key = format!("{session}:passive:{scope}");
        Ok(Self {
            directory,
            session,
            key,
            session_prefix,
            scope_prefix,
            retention,
            capacity,
        })
    }

    pub(crate) async fn publish(&self, data: &str) -> RedisResult<()> {
        if self.capacity == 0 || data.len() > JOURNAL_BYTES - 64 {
            return Ok(());
        }
        self.directory
            .query::<u8>(
                redis::cmd("EVAL")
                    .arg(APPEND)
                    .arg(3)
                    .arg(&self.session)
                    .arg(&self.key)
                    .arg(format!("{}:bytes", self.key))
                    .arg(Uuid::new_v4().simple().to_string())
                    .arg(data)
                    .arg(ttl_millis(self.retention))
                    .arg(self.capacity)
                    .arg(JOURNAL_BYTES),
            )
            .await?;
        Ok(())
    }

    fn cursor<'a>(&self, cursor: &'a str) -> Result<Option<&'a str>, SessionError> {
        if let Some(id) = cursor.strip_prefix(&self.scope_prefix) {
            return Ok((id.len() == 32 && Uuid::parse_str(id).is_ok()).then_some(id));
        }
        if cursor.starts_with(&self.session_prefix) {
            return Err(SessionError::Forbidden);
        }
        Ok(None)
    }

    pub(crate) fn after(
        &self,
        cursor: Option<&str>,
        allowed: bool,
    ) -> Result<String, SessionError> {
        let resume = cursor
            .map(|cursor| self.cursor(cursor))
            .transpose()?
            .flatten();
        if !allowed && resume.is_some() {
            return Err(SessionError::Forbidden);
        }
        Ok(cursor
            .map_or("", |_| resume.unwrap_or("unknown"))
            .to_owned())
    }

    pub(crate) async fn listen(
        self,
        after: String,
        allowed: bool,
    ) -> Result<RedisEventReader, SessionError> {
        // Subscribe before reading history so a concurrent append always wakes the reader.
        let signals = self
            .directory
            .subscribe(&format!("{}:events", self.session))
            .await
            .map_err(|error| {
                tracing::warn!(%error, "MCP event subscription unavailable");
                SessionError::Unavailable
            })?;
        let mut reader = RedisEventReader {
            journal: self,
            signals,
            after,
            frames: VecDeque::new(),
            allowed,
            read: allowed,
        };
        if allowed
            && !reader.fill(true).await.map_err(|error| {
                tracing::warn!(%error, "MCP event history unavailable");
                SessionError::Unavailable
            })?
        {
            return Err(SessionError::NotFound);
        }
        Ok(reader)
    }
}

pub(crate) struct RedisEventReader {
    journal: RedisEventJournal,
    signals: PubSubStream,
    after: String,
    frames: VecDeque<(String, String)>,
    allowed: bool,
    read: bool,
}

impl RedisEventReader {
    async fn fill(&mut self, initial: bool) -> RedisResult<bool> {
        let (valid, after, frames): (u8, String, Vec<(String, String)>) = self
            .journal
            .directory
            .query(
                redis::cmd("EVAL")
                    .arg(READ)
                    .arg(2)
                    .arg(&self.journal.session)
                    .arg(&self.journal.key)
                    .arg(&self.after)
                    .arg(if initial { "initial" } else { "next" }),
            )
            .await?;
        self.after = after;
        self.frames = frames.into();
        self.read = !self.frames.is_empty();
        Ok(valid == 1)
    }

    pub(crate) async fn next(&mut self) -> Option<Event> {
        loop {
            if let Some(signal) = self.signals.next().now_or_never() {
                if signal?.get_payload_bytes() == b"closed" {
                    return None;
                }
                self.read = self.allowed;
            }
            if let Some((id, data)) = self.frames.pop_front() {
                let event = Event::default()
                    .id(format!("{}{id}", self.journal.scope_prefix))
                    .event("message")
                    .data(data);
                self.after = id;
                return Some(event);
            }
            if self.read {
                match self.fill(false).await {
                    Ok(true) => continue,
                    Ok(false) => return None,
                    Err(error) => {
                        tracing::warn!(%error, "MCP event history unavailable");
                        return None;
                    }
                }
            }
            let signal = self.signals.next().await?;
            if signal.get_payload_bytes() == b"closed" {
                return None;
            }
            self.read = self.allowed;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::RedisSettings,
        sessions::{SessionAccess, new_session_id},
    };

    #[tokio::test]
    #[ignore = "requires a disposable Redis or Valkey database in REDIS_URL"]
    async fn redis_events_bound_history_and_discard_evicted_cursors() {
        let directory = Arc::new(
            RedisSessionDirectory::new(&RedisSettings {
                url: std::env::var("REDIS_URL").unwrap(),
                connect_timeout: Duration::from_secs(2),
                response_timeout: Duration::from_secs(2),
            })
            .unwrap(),
        );
        let id = new_session_id();
        let ttl = Duration::from_secs(10);
        directory.register(&id, None, None, ttl).await.unwrap();
        let journal = || RedisEventJournal::new(directory.clone(), &id, None, ttl, 2).unwrap();
        journal().publish("first").await.unwrap();
        let previous = journal().listen(String::new(), true).await.unwrap();
        let first = previous.frames[0].0.clone();
        drop(previous);
        journal().publish("second").await.unwrap();
        journal().publish("third").await.unwrap();

        let reader = journal().listen(first, true).await.unwrap();
        assert!(reader.frames.is_empty());
        let tail = reader.after;
        let reader = journal().listen(String::new(), true).await.unwrap();
        assert_eq!(
            reader
                .frames
                .iter()
                .map(|(_, payload)| payload.as_str())
                .collect::<Vec<_>>(),
            ["second", "third"]
        );
        assert_eq!(reader.frames[1].0, tail);
        directory
            .access(&id, None, None, ttl, SessionAccess::Delete)
            .await
            .unwrap();
    }
}
