// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, time::Instant};

use axum::http::HeaderValue;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

use super::*;
use crate::oauth_client::A2aOAuthError;
use crate::{config::RedisSettings, redis_sessions::RedisSessionDirectory};

const MAX_ENTRIES: usize = 1024;
const REFRESH_MARGIN: u64 = 300;
const FAILURE_TTL: u64 = 10;
const REDIS_PAUSE: Duration = Duration::from_secs(30);

type Entry = Arc<tokio::sync::Mutex<Option<(Instant, CachedExchange)>>>;

pub(super) enum ExchangeMode {
    Cached,
    Refresh,
}

#[derive(Default)]
pub(super) struct ExchangedTokens {
    local: Mutex<HashMap<String, Entry>>,
    redis: Option<SharedExchanges>,
}

#[derive(Clone)]
enum CachedExchange {
    Bearer(HeaderValue),
    Failed,
    A2aFailed(A2aOAuthError),
}

impl CachedExchange {
    fn into_authorization(self) -> Result<HeaderValue, UpstreamError> {
        match self {
            Self::Bearer(authorization) => Ok(authorization),
            Self::Failed | Self::A2aFailed(_) => Err(UpstreamError::InvalidCredentials),
        }
    }
}

impl ExchangedTokens {
    pub(super) fn set_redis(&mut self, settings: Option<&RedisSettings>) {
        self.redis = settings.and_then(|settings| match RedisSessionDirectory::new(settings) {
            Ok(connection) => Some(SharedExchanges {
                connection,
                health: Mutex::default(),
            }),
            Err(_) => {
                tracing::warn!("invalid Redis connection for OAuth exchange cache");
                None
            }
        });
    }

    pub(super) async fn authorization(
        &self,
        connection: ExchangeConnection<'_>,
        principal: &Principal,
        subject: &str,
        mode: ExchangeMode,
    ) -> Result<HeaderValue, UpstreamError> {
        let subject_lifetime = || {
            principal
                .expires_at
                .and_then(|expiry| {
                    u64::try_from(expiry.saturating_sub(Timestamp::now().as_second())).ok()
                })
                .filter(|lifetime| *lifetime > 0)
                .ok_or(UpstreamError::InvalidCredentials)
        };
        let key = cache_key(connection.gateway_id, connection.version, principal);
        let entry = self.entry(&key)?;
        let mut entry = entry.lock().await;
        subject_lifetime()?;
        let shared = self.redis.as_ref().zip(connection.cipher);
        match mode {
            ExchangeMode::Cached => {
                let read = match shared {
                    Some((redis, cipher)) => redis.read(&key, cipher).await,
                    None => Err(()),
                };
                subject_lifetime()?;
                if let Ok(Some(cached)) = read {
                    return cached.into_authorization();
                }
                if read.is_err()
                    && let Some((until, cached)) = &*entry
                    && *until > Instant::now()
                {
                    return cached.clone().into_authorization();
                }
            }
            ExchangeMode::Refresh => {
                *entry = None;
                if let Some((redis, _)) = shared {
                    let _ = redis.query::<u64>(redis::cmd("DEL").arg(&key)).await;
                }
                subject_lifetime()?;
            }
        }
        let exchange = connection
            .config
            .exchange_subject(connection.upstream, connection.tls, subject)
            .await;
        let expiry = subject_lifetime()?;
        let (cached, usable) = match &exchange {
            Ok(token) => (
                CachedExchange::Bearer(token.authorization.clone()),
                token.expires_in - REFRESH_MARGIN.min(token.expires_in / 2),
            ),
            Err(_) => (CachedExchange::Failed, FAILURE_TTL),
        };
        let ttl = usable.min(expiry);
        if let Some(until) = Instant::now().checked_add(Duration::from_secs(ttl)) {
            if let Some((redis, cipher)) = shared {
                redis.write(&key, &cached, ttl, cipher).await;
            }
            *entry = Some((until, cached));
        }
        subject_lifetime()?;
        exchange.map(|token| token.authorization)
    }

    fn entry(&self, key: &str) -> Result<Entry, UpstreamError> {
        let mut entries = self.local.lock().map_err(|_| UpstreamError::Transport)?;
        if let Some(entry) = entries.get(key) {
            return Ok(entry.clone());
        }
        if entries.len() >= MAX_ENTRIES
            && let Some(removable) = entries
                .iter()
                .find(|(_, entry)| Arc::strong_count(entry) == 1)
                .map(|(key, _)| key.clone())
        {
            entries.remove(&removable);
        }
        let entry = Entry::default();
        if entries.len() < MAX_ENTRIES {
            entries.insert(key.to_owned(), entry.clone());
        }
        Ok(entry)
    }

    pub(super) async fn a2a_authorization(
        &self,
        key: &str,
        cipher: Option<&CredentialCipher>,
        request: impl Future<Output = Result<(HeaderValue, u64), A2aOAuthError>>,
    ) -> Result<HeaderValue, A2aOAuthError> {
        let entry = self.entry(key).map_err(|_| A2aOAuthError::Request)?;
        let mut entry = entry.lock().await;
        let shared = self.redis.as_ref().zip(cipher);
        let read = match shared {
            Some((redis, cipher)) => redis.read(key, cipher).await,
            None => Err(()),
        };
        let cached = match read {
            Ok(cached) => cached,
            Err(()) => entry
                .as_ref()
                .filter(|(until, _)| *until > Instant::now())
                .map(|(_, cached)| cached.clone()),
        };
        if let Some(cached) = cached {
            return match cached {
                CachedExchange::Bearer(header) => Ok(header),
                CachedExchange::A2aFailed(error) => Err(error),
                CachedExchange::Failed => Err(A2aOAuthError::Request),
            };
        }
        let result = request.await;
        let (cached, ttl) = match &result {
            Ok((header, expires)) => (
                CachedExchange::Bearer(header.clone()),
                expires - REFRESH_MARGIN.min(expires / 2),
            ),
            Err(error) => (CachedExchange::A2aFailed(*error), FAILURE_TTL),
        };
        if ttl > 0
            && let Some(until) = Instant::now().checked_add(Duration::from_secs(ttl))
        {
            if let Some((redis, cipher)) = shared {
                redis.write(key, &cached, ttl, cipher).await;
            }
            *entry = Some((until, cached));
        }
        result.map(|(authorization, _)| authorization)
    }
}

fn cache_key(id: &str, version: i32, principal: &Principal) -> String {
    format!(
        "cf:oauth-exchange:v1:{}:{version}:{}",
        BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(id.as_bytes())),
        BASE64_URL_SAFE_NO_PAD.encode(principal.credential_hash()),
    )
}

struct SharedExchanges {
    connection: RedisSessionDirectory,
    health: Mutex<(u8, Option<Instant>)>,
}

#[derive(Deserialize, Serialize)]
struct StoredExchange<T> {
    until: i64,
    authorization: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    a2a_failure: Option<A2aOAuthError>,
}

impl SharedExchanges {
    async fn query<T: redis::FromRedisValue>(&self, command: &redis::Cmd) -> Result<T, ()> {
        if self
            .health
            .lock()
            .is_ok_and(|health| health.1.is_some_and(|until| until > Instant::now()))
        {
            return Err(());
        }
        let result = self.connection.query(command).await;
        if let Ok(mut health) = self.health.lock() {
            if result.is_ok() {
                *health = (0, None);
            } else {
                if health.1.is_some_and(|until| until <= Instant::now()) {
                    *health = (0, None);
                }
                health.0 = health.0.saturating_add(1);
                if health.0 == 3 {
                    health.1 = Some(Instant::now() + REDIS_PAUSE);
                    tracing::warn!("Redis unavailable for OAuth exchange cache");
                }
            }
        }
        result.map_err(|_| ())
    }

    async fn read(
        &self,
        key: &str,
        cipher: &CredentialCipher,
    ) -> Result<Option<CachedExchange>, ()> {
        let sealed: Option<String> = self.query(redis::cmd("GET").arg(key)).await?;
        Ok(sealed
            .filter(|sealed| sealed.len() <= 64 * 1024)
            .and_then(|sealed| {
                cipher
                    .open_scoped::<StoredExchange<String>>(&sealed, key.as_bytes())
                    .ok()
            })
            .and_then(|exchange| {
                let authorization = exchange.authorization.map(Zeroizing::new);
                if exchange.until <= Timestamp::now().as_second() {
                    return None;
                }
                if let Some(authorization) = authorization {
                    let mut header = HeaderValue::from_str(&authorization).ok()?;
                    header.set_sensitive(true);
                    Some(CachedExchange::Bearer(header))
                } else if let Some(error) = exchange.a2a_failure {
                    Some(CachedExchange::A2aFailed(error))
                } else {
                    Some(CachedExchange::Failed)
                }
            }))
    }

    async fn write(&self, key: &str, cached: &CachedExchange, ttl: u64, cipher: &CredentialCipher) {
        let authorization = match cached {
            CachedExchange::Bearer(header) => match header.to_str() {
                Ok(header) => Some(header),
                Err(_) => return,
            },
            CachedExchange::Failed | CachedExchange::A2aFailed(_) => None,
        };
        let until = Timestamp::now().as_second().saturating_add(ttl as i64);
        let exchange = StoredExchange {
            until,
            authorization,
            a2a_failure: match cached {
                CachedExchange::A2aFailed(error) => Some(*error),
                _ => None,
            },
        };
        if let Ok(sealed) = cipher.seal_scoped(&exchange, key.as_bytes()) {
            let _ = self
                .query::<()>(redis::cmd("SET").arg(key).arg(sealed).arg("EX").arg(ttl))
                .await;
        }
    }
}

pub(super) struct ExchangeConnection<'a> {
    pub(super) gateway_id: &'a str,
    pub(super) version: i32,
    pub(super) upstream: &'a UpstreamClient,
    pub(super) config: &'a OAuthConfig,
    pub(super) tls: Option<&'a TlsMaterial>,
    pub(super) cipher: Option<&'a CredentialCipher>,
}
