// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use axum::http::HeaderValue;
use redis::{
    AsyncConnectionConfig, FromRedisValue,
    aio::{MultiplexedConnection, PubSubStream},
};
use tokio::{
    sync::Mutex,
    time::{Instant, interval_at, timeout},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    config::RedisSettings,
    sessions::{SessionAccess, SessionError},
};

const SESSION_KEY_PREFIX: &str = "context-forge-rs:mcp:session:";
pub(crate) const DEFAULT_AFFINITY_TTL: Duration = Duration::from_secs(300);
pub(crate) const DEFAULT_LISTENER_TTL: Duration = Duration::from_secs(30);

const REGISTER: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
local time = redis.call('TIME')
local now = time[1] * 1000 + math.floor(time[2] / 1000)
redis.call('HSET', KEYS[1], 'worker', ARGV[1], 'owner', ARGV[2], 'server', ARGV[3],
    'affinity_until', now + tonumber(ARGV[5]))
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return 1
"#;

const ACCESS: &str = r#"
local record = redis.call('HMGET', KEYS[1], 'worker', 'owner', 'server', 'affinity_until')
if not record[1] then return {0, ''} end
if record[2] ~= ARGV[2] or record[3] ~= ARGV[3] then return {1, ''} end
local function now_millis()
  local time = redis.call('TIME')
  return time[1] * 1000 + math.floor(time[2] / 1000)
end
if record[1] ~= ARGV[1] then
  if ARGV[5] == 'locate-post' and record[4] and tonumber(record[4]) <= now_millis() then
    return {0, ''}
  end
  return {2, record[1]}
end
if ARGV[5] == 'delete' then
  redis.call('DEL', KEYS[1])
  redis.call('PUBLISH', KEYS[1] .. ':events', 'closed')
elseif ARGV[5] == 'touch' or ARGV[5] == 'renew' then
  redis.call('PEXPIRE', KEYS[1], ARGV[4])
  if ARGV[5] == 'renew' then
    redis.call('HSET', KEYS[1], 'affinity_until', now_millis() + tonumber(ARGV[6]))
  end
end
return {3, record[1]}
"#;

const CLAIM_LISTENER: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return 2 end
if redis.call('SET', KEYS[2], ARGV[1], 'NX', 'PX', ARGV[2]) then return 1 end
return 0
"#;

const RENEW_LISTENER: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('GET', KEYS[2]) ~= ARGV[1] then return 0 end
return redis.call('PEXPIRE', KEYS[2], ARGV[2])
"#;

const RELEASE_LISTENER: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
return redis.call('DEL', KEYS[1])
"#;

/// Records ownership of process-local MCP sessions in the shared Redis cache.
pub struct RedisSessionDirectory {
    client: redis::Client,
    config: AsyncConnectionConfig,
    worker: String,
    affinity_ttl: Option<Duration>,
    listener_ttl: Duration,
    connection: Mutex<Option<(Uuid, MultiplexedConnection)>>,
    socket_timeout: Duration,
}

impl RedisSessionDirectory {
    pub fn new(settings: &RedisSettings) -> redis::RedisResult<Self> {
        let client = redis::Client::open(settings.url.as_str())?;
        let config = AsyncConnectionConfig::new()
            .set_connection_timeout(Some(settings.connect_timeout))
            .set_response_timeout(Some(settings.response_timeout));
        Ok(Self {
            client,
            config,
            worker: Uuid::new_v4().simple().to_string(),
            affinity_ttl: Some(DEFAULT_AFFINITY_TTL),
            listener_ttl: DEFAULT_LISTENER_TTL,
            connection: Mutex::new(None),
            socket_timeout: settings
                .connect_timeout
                .saturating_add(settings.response_timeout),
        })
    }

    pub(crate) fn with_leases(mut self, affinity: Option<Duration>, listener: Duration) -> Self {
        self.affinity_ttl = affinity;
        self.listener_ttl = listener;
        self
    }

    pub(crate) fn affinity_enabled(&self) -> bool {
        self.affinity_ttl.is_some()
    }

    pub(crate) async fn register(
        &self,
        id: &HeaderValue,
        owner: Option<&str>,
        server: Option<&str>,
        ttl: Duration,
    ) -> Result<(), SessionError> {
        let key = session_key(id)?;
        let mut command = redis::cmd("EVAL");
        command
            .arg(REGISTER)
            .arg(1)
            .arg(key)
            .arg(&self.worker)
            .arg(owner.unwrap_or_default())
            .arg(server.unwrap_or_default())
            .arg(ttl_millis(ttl))
            .arg(ttl_millis(self.affinity_ttl.unwrap_or_default()));
        match self.query::<u8>(&command).await {
            Ok(1) => Ok(()),
            Ok(_) => Err(SessionError::Unavailable),
            Err(error) => Err(unavailable(error)),
        }
    }

    pub(crate) async fn access(
        &self,
        id: &HeaderValue,
        owner: Option<&str>,
        server: Option<&str>,
        ttl: Duration,
        access: SessionAccess,
    ) -> Result<(), SessionError> {
        self.lookup(
            id,
            owner,
            server,
            ttl,
            match access {
                SessionAccess::Post if self.affinity_enabled() => "renew",
                SessionAccess::Get | SessionAccess::Post => "touch",
                SessionAccess::Delete => "delete",
            },
        )
        .await
    }

    pub(crate) async fn locate(
        &self,
        id: &HeaderValue,
        owner: Option<&str>,
        server: Option<&str>,
        post: bool,
    ) -> Result<(), SessionError> {
        let operation = if post { "locate-post" } else { "locate" };
        self.lookup(id, owner, server, Duration::ZERO, operation)
            .await
    }

    async fn lookup(
        &self,
        id: &HeaderValue,
        owner: Option<&str>,
        server: Option<&str>,
        ttl: Duration,
        operation: &str,
    ) -> Result<(), SessionError> {
        let key = session_key(id)?;
        let mut command = redis::cmd("EVAL");
        command
            .arg(ACCESS)
            .arg(1)
            .arg(key)
            .arg(&self.worker)
            .arg(owner.unwrap_or_default())
            .arg(server.unwrap_or_default())
            .arg(ttl_millis(ttl))
            .arg(operation)
            .arg(ttl_millis(self.affinity_ttl.unwrap_or_default()));
        let (status, worker): (u8, String) = self.query(&command).await.map_err(unavailable)?;
        match status {
            0 => Err(SessionError::NotFound),
            1 => Err(SessionError::Forbidden),
            2 => Uuid::parse_str(&worker).map_or(Err(SessionError::Unavailable), |worker| {
                Err(SessionError::Remote(worker))
            }),
            3 => Ok(()),
            _ => Err(SessionError::Unavailable),
        }
    }

    pub(crate) async fn claim_listener(
        self: &Arc<Self>,
        id: &HeaderValue,
        shutdown: &CancellationToken,
    ) -> Result<Option<RedisListener>, SessionError> {
        let session = session_key(id)?;
        let key = format!("{session}:listener");
        let token = Uuid::new_v4().simple().to_string();
        let acquired = self
            .query::<u8>(
                redis::cmd("EVAL")
                    .arg(CLAIM_LISTENER)
                    .arg(2)
                    .arg(&session)
                    .arg(&key)
                    .arg(&token)
                    .arg(ttl_millis(self.listener_ttl)),
            )
            .await
            .map_err(unavailable)?;
        match acquired {
            0 => return Ok(None),
            1 => {}
            2 => return Err(SessionError::NotFound),
            _ => return Err(SessionError::Unavailable),
        }

        let listener = RedisListener {
            stop: shutdown.child_token(),
            lost: CancellationToken::new(),
        };
        let directory = self.clone();
        let stop = listener.stop.clone();
        let lost = listener.lost.clone();
        tokio::spawn(async move {
            directory
                .keep_listener(session, key, token, stop, lost)
                .await;
        });
        Ok(Some(listener))
    }

    async fn keep_listener(
        &self,
        session: String,
        key: String,
        token: String,
        stop: CancellationToken,
        lost: CancellationToken,
    ) {
        let period = (self.listener_ttl / 3).max(Duration::from_secs(1));
        let mut interval = interval_at(Instant::now() + period, period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut failures = 0;
        let mut renew = redis::cmd("EVAL");
        renew
            .arg(RENEW_LISTENER)
            .arg(2)
            .arg(session)
            .arg(&key)
            .arg(&token)
            .arg(ttl_millis(self.listener_ttl));
        loop {
            tokio::select! {
                biased;
                () = stop.cancelled() => break,
                _ = interval.tick() => {}
            }
            let result = tokio::select! {
                biased;
                () = stop.cancelled() => break,
                result = self.query::<u8>(&renew) => result,
            };
            match result {
                Ok(1) => failures = 0,
                _ => {
                    failures += 1;
                    if failures == 2 {
                        lost.cancel();
                        break;
                    }
                }
            }
        }
        let _ = self
            .query::<u8>(
                redis::cmd("EVAL")
                    .arg(RELEASE_LISTENER)
                    .arg(1)
                    .arg(key)
                    .arg(token),
            )
            .await;
    }

    pub(crate) fn worker_id(&self) -> &str {
        &self.worker
    }

    pub(crate) async fn subscribe(&self, channel: &str) -> redis::RedisResult<PubSubStream> {
        timeout(self.socket_timeout, async {
            let mut subscription = self.client.get_async_pubsub().await?;
            subscription.subscribe(channel).await?;
            Ok(subscription.into_on_message())
        })
        .await
        .map_err(|_| {
            redis::RedisError::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Redis subscription timed out",
            ))
        })?
    }

    pub(crate) async fn publish(&self, channel: &str, payload: &[u8]) -> redis::RedisResult<usize> {
        self.query(redis::cmd("PUBLISH").arg(channel).arg(payload))
            .await
    }

    pub(crate) async fn query<T: FromRedisValue>(
        &self,
        command: &redis::Cmd,
    ) -> redis::RedisResult<T> {
        let (generation, mut connection) = {
            let mut cached = self.connection.lock().await;
            if let Some(connection) = cached.as_ref() {
                connection.clone()
            } else {
                let connection = self
                    .client
                    .get_multiplexed_async_connection_with_config(&self.config)
                    .await?;
                let shared = (Uuid::new_v4(), connection);
                *cached = Some(shared.clone());
                shared
            }
        };
        let result = command.query_async(&mut connection).await;
        if result.as_ref().is_err_and(|error| error.is_io_error()) {
            let mut cached = self.connection.lock().await;
            if cached
                .as_ref()
                .is_some_and(|(current, _)| *current == generation)
            {
                cached.take();
            }
        }
        result
    }
}

pub(crate) struct RedisListener {
    stop: CancellationToken,
    lost: CancellationToken,
}

impl RedisListener {
    pub(crate) async fn wait_until_lost(&self) {
        tokio::select! {
            () = self.stop.cancelled() => {},
            () = self.lost.cancelled() => {},
        }
    }
}

impl Drop for RedisListener {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

pub(crate) fn session_key(id: &HeaderValue) -> Result<String, SessionError> {
    let bytes = id.as_bytes();
    if bytes.len() != 32
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(SessionError::NotFound);
    }
    let id = id.to_str().map_err(|_| SessionError::NotFound)?;
    Ok(format!("{SESSION_KEY_PREFIX}{id}"))
}

pub(crate) fn ttl_millis(ttl: Duration) -> i64 {
    ttl.as_millis().clamp(1, (i64::MAX / 2) as u128) as i64
}

fn unavailable(error: redis::RedisError) -> SessionError {
    tracing::warn!(%error, "MCP session directory unavailable");
    SessionError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a disposable Redis or Valkey database in REDIS_URL"]
    async fn shared_directory_scopes_ownership_and_expiration() {
        let settings = RedisSettings {
            url: std::env::var("REDIS_URL").unwrap(),
            connect_timeout: Duration::from_secs(2),
            response_timeout: Duration::from_secs(2),
        };
        let first = RedisSessionDirectory::new(&settings).unwrap();
        let second = RedisSessionDirectory::new(&settings).unwrap();
        let id = HeaderValue::from_str(&Uuid::new_v4().simple().to_string()).unwrap();
        let owner = Some("fixture@example.test");
        let server = Some("virtual");
        let ttl = Duration::from_secs(10);
        first.register(&id, owner, server, ttl).await.unwrap();

        assert_eq!(
            second
                .access(&id, owner, server, ttl, SessionAccess::Delete)
                .await,
            Err(SessionError::Remote(
                Uuid::parse_str(&first.worker).unwrap()
            )),
        );
        assert_eq!(
            second
                .access(&id, None, server, ttl, SessionAccess::Post)
                .await,
            Err(SessionError::Forbidden),
        );
        assert_eq!(
            first
                .access(&id, owner, None, ttl, SessionAccess::Post)
                .await,
            Err(SessionError::Forbidden),
        );

        let key = session_key(&id).unwrap();
        let modified: u32 = first
            .query(redis::cmd("HSET").arg(&key).arg("affinity_until").arg(1))
            .await
            .unwrap();
        assert_eq!(modified, 0);
        assert_eq!(
            second.locate(&id, owner, server, true).await,
            Err(SessionError::NotFound)
        );
        let remote = Err(SessionError::Remote(
            Uuid::parse_str(&first.worker).unwrap(),
        ));
        assert_eq!(second.locate(&id, owner, server, false).await, remote);
        first
            .access(&id, owner, server, ttl, SessionAccess::Get)
            .await
            .unwrap();
        assert_eq!(
            second.locate(&id, owner, server, true).await,
            Err(SessionError::NotFound)
        );
        assert_eq!(
            second.locate(&id, None, server, false).await,
            Err(SessionError::Forbidden)
        );

        first
            .access(
                &id,
                owner,
                server,
                Duration::from_secs(30),
                SessionAccess::Post,
            )
            .await
            .unwrap();
        assert_eq!(second.locate(&id, owner, server, true).await, remote);
        let remaining: i64 = first.query(redis::cmd("PTTL").arg(&key)).await.unwrap();
        assert!((10_000..=30_000).contains(&remaining));
        first
            .access(&id, owner, server, ttl, SessionAccess::Delete)
            .await
            .unwrap();
        assert_eq!(
            second
                .access(&id, owner, server, ttl, SessionAccess::Post)
                .await,
            Err(SessionError::NotFound),
        );
    }

    #[tokio::test]
    #[ignore = "requires a disposable Redis or Valkey database in REDIS_URL"]
    async fn listener_renews_and_releases_only_its_own_claim() {
        let settings = RedisSettings {
            url: std::env::var("REDIS_URL").unwrap(),
            connect_timeout: Duration::from_secs(2),
            response_timeout: Duration::from_secs(2),
        };
        let first = Arc::new(
            RedisSessionDirectory::new(&settings)
                .unwrap()
                .with_leases(None, Duration::from_secs(3)),
        );
        let second = Arc::new(RedisSessionDirectory::new(&settings).unwrap());
        let id = HeaderValue::from_str(&Uuid::new_v4().simple().to_string()).unwrap();
        let shutdown = CancellationToken::new();
        let ttl = Duration::from_secs(30);
        first.register(&id, None, None, ttl).await.unwrap();
        let listener = first.claim_listener(&id, &shutdown).await.unwrap().unwrap();
        assert!(
            second
                .claim_listener(&id, &shutdown)
                .await
                .unwrap()
                .is_none()
        );
        let key = format!("{}:listener", session_key(&id).unwrap());
        tokio::time::sleep(Duration::from_millis(3300)).await;
        let remaining: i64 = first.query(redis::cmd("PTTL").arg(&key)).await.unwrap();
        assert!((1..=3000).contains(&remaining));

        second
            .query::<()>(
                redis::cmd("SET")
                    .arg(&key)
                    .arg("replacement")
                    .arg("PX")
                    .arg(10_000),
            )
            .await
            .unwrap();
        timeout(Duration::from_secs(4), listener.wait_until_lost())
            .await
            .unwrap();
        drop(listener);
        let current: String = second.query(redis::cmd("GET").arg(&key)).await.unwrap();
        assert_eq!(current, "replacement");
        second
            .query::<u8>(redis::cmd("DEL").arg(&key))
            .await
            .unwrap();
        let listener = first.claim_listener(&id, &shutdown).await.unwrap().unwrap();
        drop(listener);
        timeout(Duration::from_secs(2), async {
            loop {
                let exists: bool = first.query(redis::cmd("EXISTS").arg(&key)).await.unwrap();
                if !exists {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("listener lease should be removed on disconnect");
        first
            .access(&id, None, None, ttl, SessionAccess::Delete)
            .await
            .unwrap();
    }
}
