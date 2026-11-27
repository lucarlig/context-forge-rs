// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    time::{Duration, Instant},
};

use redis::{
    AsyncConnectionConfig, Client, ClientTlsConfig, TlsCertificates, aio::MultiplexedConnection,
};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::{Admission, Lockout, WINDOW};
use crate::config::{flag, parse, value};

const RETRY_DELAY: Duration = Duration::from_secs(30);
const ADMIT: &str = r#"
local limit, interval, threshold, lockout_ttl = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
local window_count = #KEYS / 2
if threshold >= 0 then
    for index = window_count + 1, #KEYS do
        if tonumber(redis.call('GET', KEYS[index]) or '0') >= threshold then
            return {2, 0}
        end
    end
end
local time = redis.call('TIME')
local now = tonumber(time[1]) + tonumber(time[2]) / 1000000
local exceeded = false
local remaining = 0
for index = 1, window_count do
    local key = KEYS[index]
    redis.call('ZREMRANGEBYSCORE', key, '-inf', now - interval)
    local count = redis.call('ZCARD', key)
    if count < limit then
        redis.call('ZADD', key, now, ARGV[5])
        redis.call('EXPIRE', key, interval * 2)
        if index == 1 then remaining = limit - count - 1 end
    else
        exceeded = true
        if threshold >= 0 then
            local violations = KEYS[window_count + index]
            redis.call('INCR', violations)
            redis.call('EXPIRE', violations, lockout_ttl)
        end
    end
end
if exceeded then return {1, 0} end
return {0, remaining}
"#;

pub(super) struct RedisBuckets {
    client: Client,
    config: AsyncConnectionConfig,
    connection: Mutex<Connection>,
}

#[derive(Default)]
struct Connection {
    shared: Option<(Uuid, MultiplexedConnection)>,
    retry_at: Option<Instant>,
}

impl RedisBuckets {
    pub(super) fn from_env() -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        if !flag("RATE_LIMITING_REDIS_ENABLED")?.unwrap_or(true) {
            return Ok(None);
        }
        let dedicated_url = value("RATELIMITER_REDIS_URL", "")?;
        let dedicated = !dedicated_url.is_empty();
        if !dedicated && value("CACHE_TYPE", "memory")? != "redis" {
            return Ok(None);
        }
        let url = if dedicated {
            dedicated_url
        } else {
            value("REDIS_URL", "")?
        };
        if url.is_empty() {
            return Ok(None);
        }
        let (connect, response) = if dedicated {
            (
                "RATELIMITER_REDIS_SOCKET_CONNECT_TIMEOUT",
                "RATELIMITER_REDIS_SOCKET_TIMEOUT",
            )
        } else {
            ("REDIS_SOCKET_CONNECT_TIMEOUT", "REDIS_SOCKET_TIMEOUT")
        };
        let timeout = |name: &str| -> Result<Duration, Box<dyn Error + Send + Sync>> {
            Duration::try_from_secs_f64(parse(name, 2.0)?)
                .map_err(|_| format!("invalid {name}").into())
        };
        let config = AsyncConnectionConfig::new()
            .set_connection_timeout(Some(timeout(connect)?))
            .set_response_timeout(Some(timeout(response)?));
        let client = redis_client(&url, dedicated)
            .map_err(|_| "invalid rate limiter Redis configuration")?;
        Ok(Some(Self {
            client,
            config,
            connection: Mutex::default(),
        }))
    }

    pub(super) async fn check(
        &self,
        keys: &[String],
        limit: usize,
        lockout: Option<Lockout>,
    ) -> Option<Admission> {
        let (generation, mut connection) = self.connect().await?;
        let mut command = redis::cmd("EVAL");
        command.arg(ADMIT).arg(keys.len() * 2).arg(keys);
        for key in keys {
            command.arg(format!(
                "ratelimit:violations:{}",
                key.strip_prefix("ratelimit:").expect("rate limit key")
            ));
        }
        command
            .arg(limit)
            .arg(WINDOW.as_secs())
            .arg(lockout.map_or_else(|| "-1".to_owned(), |lockout| lockout.threshold.to_string()))
            .arg(lockout.map_or(0, |lockout| lockout.period().as_secs()))
            .arg(Uuid::new_v4().simple().to_string());
        match command.query_async::<(u8, usize)>(&mut connection).await {
            Ok((0, remaining)) => Some(Admission::Allowed(remaining)),
            Ok((1, _)) => Some(Admission::Exceeded),
            Ok((2, _)) => Some(Admission::Locked),
            _ => {
                let mut state = self.connection.lock().await;
                if state
                    .shared
                    .as_ref()
                    .is_some_and(|(current, _)| *current == generation)
                {
                    state.shared = None;
                    state.retry_at = Some(Instant::now() + RETRY_DELAY);
                    tracing::warn!("Redis rate limit check failed, using memory");
                }
                None
            }
        }
    }

    async fn connect(&self) -> Option<(Uuid, MultiplexedConnection)> {
        let mut state = self.connection.lock().await;
        if let Some(connection) = &state.shared {
            return Some(connection.clone());
        }
        if state.retry_at.is_some_and(|time| Instant::now() < time) {
            return None;
        }
        match self
            .client
            .get_multiplexed_async_connection_with_config(&self.config)
            .await
        {
            Ok(connection) => {
                let shared = (Uuid::new_v4(), connection);
                state.retry_at = None;
                state.shared = Some(shared.clone());
                Some(shared)
            }
            Err(_) => {
                state.retry_at = Some(Instant::now() + RETRY_DELAY);
                tracing::warn!("could not connect to rate limiter Redis, using memory");
                None
            }
        }
    }
}

fn redis_client(url: &str, dedicated: bool) -> Result<Client, Box<dyn Error + Send + Sync>> {
    if !url.starts_with("rediss://") {
        return Ok(Client::open(url)?);
    }
    let prefix = if dedicated && flag("RATELIMITER_REDIS_SSL")?.unwrap_or(false) {
        "RATELIMITER_REDIS_SSL"
    } else {
        "REDIS_SSL"
    };
    let pem = |name: &str| -> Result<Option<Vec<u8>>, Box<dyn Error + Send + Sync>> {
        let path = value(&format!("{prefix}_{name}"), "")?;
        if path.is_empty() {
            Ok(None)
        } else {
            Ok(Some(std::fs::read(path)?))
        }
    };
    let root_cert = pem("CA_CERTS")?;
    let client_tls = match (pem("CERTFILE")?, pem("KEYFILE")?) {
        (Some(client_cert), Some(client_key)) => Some(ClientTlsConfig {
            client_cert,
            client_key,
        }),
        (None, None) => None,
        _ => return Err("incomplete Redis client TLS identity".into()),
    };
    if root_cert.is_none() && client_tls.is_none() {
        return Ok(Client::open(url)?);
    }
    Ok(Client::build_with_tls(
        url,
        TlsCertificates {
            root_cert,
            client_tls,
        },
    )?)
}
