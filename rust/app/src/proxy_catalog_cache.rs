// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use redis::cmd;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::{config::ProxyCatalogSettings, redis_sessions::RedisSessionDirectory};

const PREFIX: &str = "context-forge-rs:{proxy-catalog}:";
const COLLECTORS: &str = "context-forge-rs:{proxy-catalog}:collectors";
const SNAPSHOTS: &str = "context-forge-rs:{proxy-catalog}:snapshots";
const SIZES: &str = "context-forge-rs:{proxy-catalog}:sizes";
const MAX_PAGES: usize = 10_000;

const RESERVE: &str = r#"
local prior = redis.call('GET', KEYS[3])
if prior and redis.call('EXISTS', ARGV[4] .. prior) == 1 then return {2, prior} end
if redis.call('EXISTS', KEYS[2]) == 1 then return {0, ''} end
local time = redis.call('TIME')
local now = time[1] * 1000 + math.floor(time[2] / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then return {0, ''} end
redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[2])
redis.call('ZADD', KEYS[1], now + tonumber(ARGV[2]), ARGV[1])
return {1, ARGV[1]}
"#;

const RELEASE: &str = r#"
if redis.call('GET', KEYS[2]) == ARGV[1] then redis.call('DEL', KEYS[2]) end
return redis.call('ZREM', KEYS[1], ARGV[1])
"#;

const SAVE: &str = r#"
if redis.call('GET', KEYS[5]) ~= ARGV[1] then return 0 end
local now = tonumber(redis.call('TIME')[1])
local expiry = tonumber(ARGV[2])
if expiry <= now then return 0 end
local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now)
for _, id in ipairs(expired) do redis.call('HDEL', KEYS[2], id) end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[4]) then return 2 end
local bytes = tonumber(ARGV[3])
for _, size in ipairs(redis.call('HVALS', KEYS[2])) do bytes = bytes + tonumber(size) end
if bytes > tonumber(ARGV[5]) then return 2 end
redis.call('HSET', KEYS[3], 'manifest', ARGV[6])
for i = 7, #ARGV do redis.call('HSET', KEYS[3], tostring(i - 7), ARGV[i]) end
redis.call('EXPIREAT', KEYS[3], expiry)
redis.call('SET', KEYS[4], ARGV[1], 'EXAT', expiry)
redis.call('ZADD', KEYS[1], expiry, ARGV[1])
redis.call('HSET', KEYS[2], ARGV[1], ARGV[3])
return 1
"#;

pub(crate) struct ProxyCatalogCache {
    settings: ProxyCatalogSettings,
    permits: Arc<Semaphore>,
}

pub(crate) enum Reservation {
    Local { _permit: OwnedSemaphorePermit },
    Shared(Lease),
    Reuse(Uuid),
}

pub(crate) struct Lease {
    redis: Arc<RedisSessionDirectory>,
    scope: String,
    pub(crate) id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub(crate) scope: [u8; 32],
    pub(crate) expires: i64,
    pub(crate) pages: usize,
}

pub(crate) struct SnapshotPage {
    pub(crate) manifest: Manifest,
    pub(crate) items: Vec<Value>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("MCP proxy catalog collectors are busy")]
    Busy,
    #[error("MCP proxy snapshot storage is unavailable")]
    Unavailable,
    #[error("Direct-proxy MCP catalog exceeds the snapshot byte limit")]
    SnapshotLimit,
    #[error("MCP proxy snapshot storage limit reached")]
    StorageLimit,
}

impl ProxyCatalogCache {
    pub(crate) fn new(settings: ProxyCatalogSettings) -> Self {
        let permits = Arc::new(Semaphore::new(settings.max_collectors));
        Self { settings, permits }
    }

    pub(crate) fn max_snapshot_bytes(&self) -> usize {
        self.settings.max_snapshot_bytes
    }

    pub(crate) fn is_shared(&self) -> bool {
        self.settings.redis.is_some()
    }

    pub(crate) async fn reserve(
        &self,
        scope: &[u8; 32],
        timeout: Duration,
    ) -> Result<Reservation, StoreError> {
        let Some(redis) = &self.settings.redis else {
            let permit = self
                .permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| StoreError::Busy)?;
            return Ok(Reservation::Local { _permit: permit });
        };
        let scope = BASE64_URL_SAFE_NO_PAD.encode(scope);
        let id = Uuid::new_v4();
        let millis = u64::try_from(timeout.saturating_add(Duration::from_secs(2)).as_millis())
            .unwrap_or(u64::MAX)
            .clamp(1, i64::MAX as u64);
        let (code, prior): (u8, String) = redis
            .query(
                cmd("EVAL")
                    .arg(RESERVE)
                    .arg(3)
                    .arg(COLLECTORS)
                    .arg(lock_key(&scope))
                    .arg(scope_key(&scope))
                    .arg(id.simple().to_string())
                    .arg(millis)
                    .arg(self.settings.max_collectors)
                    .arg(format!("{PREFIX}snapshot:")),
            )
            .await
            .map_err(cache_error)?;
        match code {
            0 => Err(StoreError::Busy),
            1 => Ok(Reservation::Shared(Lease {
                redis: redis.clone(),
                scope,
                id,
            })),
            2 => Uuid::parse_str(&prior)
                .map(Reservation::Reuse)
                .map_err(|_| StoreError::Unavailable),
            _ => Err(StoreError::Unavailable),
        }
    }

    pub(crate) async fn save(
        &self,
        lease: &Lease,
        manifest: &Manifest,
        items: &[Value],
        page_size: usize,
    ) -> Result<(), StoreError> {
        if manifest.pages > MAX_PAGES {
            return Err(StoreError::SnapshotLimit);
        }
        let expires = manifest.expires;
        let manifest = serde_json::to_string(manifest).map_err(|_| StoreError::Unavailable)?;
        let pages = items
            .chunks(page_size)
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StoreError::Unavailable)?;
        let bytes = manifest
            .len()
            .saturating_add(pages.iter().map(String::len).sum::<usize>());
        if bytes > self.settings.max_snapshot_bytes {
            return Err(StoreError::SnapshotLimit);
        }
        let code: u8 = lease
            .redis
            .query(
                cmd("EVAL")
                    .arg(SAVE)
                    .arg(5)
                    .arg(SNAPSHOTS)
                    .arg(SIZES)
                    .arg(snapshot_key(lease.id))
                    .arg(scope_key(&lease.scope))
                    .arg(lock_key(&lease.scope))
                    .arg(lease.id.simple().to_string())
                    .arg(expires)
                    .arg(bytes)
                    .arg(self.settings.max_snapshots)
                    .arg(self.settings.max_total_bytes)
                    .arg(manifest)
                    .arg(pages),
            )
            .await
            .map_err(cache_error)?;
        match code {
            1 => Ok(()),
            2 => Err(StoreError::StorageLimit),
            _ => Err(StoreError::Unavailable),
        }
    }

    pub(crate) async fn page(
        &self,
        snapshot: Uuid,
        page: usize,
    ) -> Result<Option<SnapshotPage>, StoreError> {
        let redis = self
            .settings
            .redis
            .as_ref()
            .ok_or(StoreError::Unavailable)?;
        let (manifest, items): (Option<String>, Option<String>) = redis
            .query(
                cmd("HMGET")
                    .arg(snapshot_key(snapshot))
                    .arg("manifest")
                    .arg(page),
            )
            .await
            .map_err(cache_error)?;
        let (Some(manifest), Some(items)) = (manifest, items) else {
            return Ok(None);
        };
        Ok(Some(SnapshotPage {
            manifest: serde_json::from_str(&manifest).map_err(|_| StoreError::Unavailable)?,
            items: serde_json::from_str(&items).map_err(|_| StoreError::Unavailable)?,
        }))
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let redis = self.redis.clone();
            let lock = lock_key(&self.scope);
            let id = self.id.simple().to_string();
            handle.spawn(async move {
                if let Err(error) = redis
                    .query::<u8>(
                        cmd("EVAL")
                            .arg(RELEASE)
                            .arg(2)
                            .arg(COLLECTORS)
                            .arg(lock)
                            .arg(id),
                    )
                    .await
                {
                    tracing::debug!(%error, "proxy catalog collector lease cleanup failed");
                }
            });
        }
    }
}

fn scope_key(scope: &str) -> String {
    format!("{PREFIX}scope:{scope}")
}

fn lock_key(scope: &str) -> String {
    format!("{PREFIX}collecting:{scope}")
}

fn snapshot_key(id: Uuid) -> String {
    format!("{PREFIX}snapshot:{}", id.simple())
}

fn cache_error(error: redis::RedisError) -> StoreError {
    tracing::warn!(%error, "proxy catalog Redis operation failed");
    StoreError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedisSettings;
    use jiff::Timestamp;
    use serde_json::json;

    #[tokio::test]
    #[ignore = "requires a disposable Redis or Valkey database in REDIS_URL"]
    async fn redis_proxy_catalog_retains_pages_across_workers() {
        let redis = RedisSettings {
            url: std::env::var("REDIS_URL").unwrap(),
            connect_timeout: Duration::from_secs(2),
            response_timeout: Duration::from_secs(2),
        };
        let cache = || {
            ProxyCatalogCache::new(ProxyCatalogSettings {
                redis: Some(Arc::new(RedisSessionDirectory::new(&redis).unwrap())),
                ..ProxyCatalogSettings::default()
            })
        };
        let first = cache();
        let second = cache();
        let mut scope = [0; 32];
        scope[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        let timeout = Duration::from_secs(3);
        let Reservation::Shared(lease) = first.reserve(&scope, timeout).await.unwrap() else {
            panic!("first collection gets a Redis lease");
        };
        assert!(matches!(
            second.reserve(&scope, timeout).await,
            Err(StoreError::Busy)
        ));
        let manifest = Manifest {
            scope,
            expires: Timestamp::now().as_second() + 30,
            pages: 2,
        };
        first
            .save(
                &lease,
                &manifest,
                &[json!({"name":"one"}), json!({"name":"two"})],
                1,
            )
            .await
            .unwrap();
        let page = second.page(lease.id, 1).await.unwrap().unwrap();
        assert_eq!(page.manifest.scope, scope);
        assert_eq!(page.items, vec![json!({"name":"two"})]);
        let Reservation::Reuse(id) = second.reserve(&scope, timeout).await.unwrap() else {
            panic!("a repeated request reuses the stored snapshot");
        };
        assert_eq!(id, lease.id);
    }
}
