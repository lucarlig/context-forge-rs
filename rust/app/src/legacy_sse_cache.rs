// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, sync::Arc, time::Duration};

use redis::cmd;
use serde_json::Value;
use tokio::time::sleep;
use uuid::Uuid;

use crate::redis_sessions::RedisSessionDirectory;

const REGISTER: &str = r#"
if redis.call('EXISTS', KEYS[1]) ~= 0 then return 0 end
redis.call('HSET', KEYS[1], 'owner', ARGV[1], 'server', ARGV[2], 'bytes', 0)
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
"#;

const ACCESS: &str = r#"
local session = redis.call('HMGET', KEYS[1], 'owner', 'server', 'bytes')
if not session[1] or session[2] ~= ARGV[2] then return 0 end
if session[1] ~= ARGV[1] and ARGV[3] ~= '1' then return 1 end
if not ARGV[4] then return 2 end
local size = string.len(ARGV[4])
if redis.call('LLEN', KEYS[2]) >= tonumber(ARGV[5])
    or tonumber(session[3]) + size > tonumber(ARGV[6]) then return 3 end
local time = redis.call('TIME')
local expires = time[1] * 1000 + math.floor(time[2] / 1000) + tonumber(ARGV[7])
local entry = string.format('%.0f', expires) .. ':' .. ARGV[4]
redis.call('RPUSH', KEYS[2], entry)
redis.call('HINCRBY', KEYS[1], 'bytes', size)
redis.call('PEXPIRE', KEYS[2], redis.call('PTTL', KEYS[1]))
return 2
"#;

const POP: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return {0, ''} end
local time = redis.call('TIME')
local now = time[1] * 1000 + math.floor(time[2] / 1000)
while true do
    local entry = redis.call('LPOP', KEYS[2])
    if not entry then return {1, ''} end
    local split = string.find(entry, ':', 1, true)
    local message = string.sub(entry, split + 1)
    redis.call('HINCRBY', KEYS[1], 'bytes', -string.len(message))
    if tonumber(string.sub(entry, 1, split - 1)) > now then return {2, message} end
end
"#;

const MAX_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_MESSAGES: usize = 128;
const IDLE_POLL: Duration = Duration::from_millis(250);
type CacheResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub(crate) struct Scope<'a> {
    pub(crate) owner: Option<&'a str>,
    pub(crate) server: Option<&'a str>,
    pub(crate) admin: bool,
}

pub(crate) enum Access {
    Missing,
    Denied,
    Allowed,
    Full,
}

fn access_code(code: u8) -> CacheResult<Access> {
    match code {
        0 => Ok(Access::Missing),
        1 => Ok(Access::Denied),
        2 => Ok(Access::Allowed),
        3 => Ok(Access::Full),
        _ => Err("invalid SSE cache reply".into()),
    }
}

pub(crate) struct RedisQueue {
    redis: Arc<RedisSessionDirectory>,
    id: Uuid,
}

impl RedisQueue {
    pub(crate) fn new(redis: Arc<RedisSessionDirectory>, id: Uuid) -> Self {
        Self { redis, id }
    }

    fn key(&self) -> String {
        format!("context-forge-rs:sse:{{{}}}", self.id.simple())
    }

    pub(crate) async fn register(&self, scope: Scope<'_>, ttl: Duration) -> CacheResult<()> {
        let result: u8 = self
            .redis
            .query(
                cmd("EVAL")
                    .arg(REGISTER)
                    .arg(1)
                    .arg(self.key())
                    .arg(scope.owner.unwrap_or_default())
                    .arg(scope.server.unwrap_or_default())
                    .arg(ttl_millis(ttl)),
            )
            .await?;
        if result != 1 {
            return Err("SSE session already exists".into());
        }
        Ok(())
    }

    pub(crate) async fn access(
        &self,
        scope: Scope<'_>,
        message: Option<&Value>,
        message_ttl: Duration,
    ) -> CacheResult<Access> {
        let (key, queue) = self.keys();
        let mut command = cmd("EVAL");
        command
            .arg(ACCESS)
            .arg(2)
            .arg(key)
            .arg(queue)
            .arg(scope.owner.unwrap_or_default())
            .arg(scope.server.unwrap_or_default())
            .arg(u8::from(scope.admin));
        if let Some(message) = message {
            command
                .arg(message.to_string())
                .arg(MAX_MESSAGES)
                .arg(MAX_QUEUE_BYTES)
                .arg(ttl_millis(message_ttl));
        }
        access_code(self.redis.query(&command).await?)
    }

    pub(crate) async fn receive(&self) -> CacheResult<Option<Value>> {
        let (key, queue) = self.keys();
        let mut command = cmd("EVAL");
        command.arg(POP).arg(2).arg(key).arg(queue);
        loop {
            let (code, message): (u8, Vec<u8>) = self.redis.query(&command).await?;
            match code {
                0 => return Ok(None),
                1 => sleep(IDLE_POLL).await,
                2 => return Ok(Some(serde_json::from_slice(&message)?)),
                _ => return Err("invalid SSE cache reply".into()),
            }
        }
    }

    pub(crate) async fn remove(&self) {
        let (key, queue) = self.keys();
        if let Err(error) = self.redis.query::<u8>(cmd("DEL").arg(key).arg(queue)).await {
            tracing::debug!(%error, "legacy SSE cache cleanup failed");
        }
    }

    fn keys(&self) -> (String, String) {
        let key = self.key();
        let queue = format!("{key}:messages");
        (key, queue)
    }
}

fn ttl_millis(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1)
}
