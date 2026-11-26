// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use jiff::Timestamp;
use serde_json::Value;
use tokio::time::sleep;
use uuid::Uuid;

use crate::{
    database::Database,
    legacy_sse_cache::{Access, CacheResult, IDLE_POLL, MAX_MESSAGES, MAX_QUEUE_BYTES, Scope},
};

const MIGRATION: &str = include_str!("../migrations/003_legacy_sse.sql");

const REGISTER: &str = "
    INSERT INTO context_forge_sse_sessions (id, owner_email, server_id, expires_at)
    VALUES ($1, $2, $3, $4)";
const LOOKUP: &str = "
    SELECT CAST(owner_email AS TEXT), CAST(server_id AS TEXT) FROM context_forge_sse_sessions
    WHERE id = $1 AND expires_at > $2";
const CLAIM_SEQUENCE: &str = "
    UPDATE context_forge_sse_sessions SET next_sequence = next_sequence + 1
    WHERE id = $1 AND expires_at > $2
    RETURNING CAST(owner_email AS TEXT), CAST(server_id AS TEXT), next_sequence";
const PRUNE_MESSAGES: &str = "
    DELETE FROM context_forge_sse_messages WHERE session_id = $1 AND expires_at <= $2";
const QUEUE_MESSAGE: &str = "
    INSERT INTO context_forge_sse_messages (session_id, sequence, payload, bytes, expires_at)
    SELECT $1, $2, $3, $4, $5
    FROM (
        SELECT COUNT(*) AS queued, COALESCE(SUM(bytes), 0) AS bytes_total
        FROM context_forge_sse_messages WHERE session_id = $1
    ) AS capacity
    WHERE capacity.queued < $6 AND capacity.bytes_total + $4 <= $7";
const HEAD: &str = "
    SELECT m.sequence, m.payload, m.expires_at
    FROM context_forge_sse_sessions s
    LEFT JOIN context_forge_sse_messages m ON m.session_id = s.id
    WHERE s.id = $1 AND s.expires_at > $2
    ORDER BY m.sequence LIMIT 1";
const REMOVE_MESSAGE: &str = "
    DELETE FROM context_forge_sse_messages WHERE session_id = $1 AND sequence = $2";
const REMOVE_SESSION: &str = "DELETE FROM context_forge_sse_sessions WHERE id = $1";
const PRUNE_SESSIONS: &str = "DELETE FROM context_forge_sse_sessions WHERE expires_at <= $1";

type Owner = (Option<String>, Option<String>);
type Sequence = (Option<String>, Option<String>, i64);
type QueueHead = (Option<i64>, Option<String>, Option<i64>);

pub(crate) struct DatabaseQueue {
    database: Database,
    id: String,
}

impl Database {
    pub async fn migrate_legacy_sse(&self) -> Result<(), sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
                sqlx::raw_sql(MIGRATION).execute(&mut *transaction).await?;
                transaction.commit().await
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682068)")
                    .execute(&mut *transaction)
                    .await?;
                sqlx::raw_sql(MIGRATION).execute(&mut *transaction).await?;
                transaction.commit().await
            }
        }
    }
}

impl DatabaseQueue {
    pub(crate) fn new(database: Database, id: Uuid) -> Self {
        Self {
            database,
            id: id.to_string(),
        }
    }

    pub(crate) async fn register(&self, scope: Scope<'_>, ttl: Duration) -> CacheResult<()> {
        let now = Timestamp::now().as_millisecond();
        let expires = expiry(now, ttl);
        macro_rules! register {
            ($pool:expr) => {{
                sqlx::query(PRUNE_SESSIONS).bind(now).execute($pool).await?;
                sqlx::query(REGISTER)
                    .bind(&self.id)
                    .bind(scope.owner)
                    .bind(scope.server)
                    .bind(expires)
                    .execute($pool)
                    .await?;
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => register!(pool),
            Database::Postgres(pool) => register!(pool),
        }
        Ok(())
    }

    pub(crate) async fn access(
        &self,
        scope: Scope<'_>,
        message: Option<&Value>,
        ttl: Duration,
    ) -> CacheResult<Access> {
        let now = Timestamp::now().as_millisecond();
        let Some(message) = message else {
            macro_rules! lookup {
                ($pool:expr) => {
                    sqlx::query_as::<_, Owner>(LOOKUP)
                        .bind(&self.id)
                        .bind(now)
                        .fetch_optional($pool)
                        .await?
                };
            }
            let record = match &self.database {
                Database::Sqlite(pool) => lookup!(pool),
                Database::Postgres(pool) => lookup!(pool),
            };
            return Ok(match record {
                Some((owner, server)) => check_scope(scope, owner.as_deref(), server.as_deref()),
                None => Access::Missing,
            });
        };

        // Updating the session locks its queue while assigning a sequence and checking capacity.
        let payload = message.to_string();
        let size = payload.len() as i64;
        let expires = expiry(now, ttl);
        macro_rules! enqueue {
            ($pool:expr) => {{
                let mut transaction = $pool.begin().await?;
                let record = sqlx::query_as::<_, Sequence>(CLAIM_SEQUENCE)
                    .bind(&self.id)
                    .bind(now)
                    .fetch_optional(&mut *transaction)
                    .await?;
                let Some((owner, server, sequence)) = record else {
                    transaction.rollback().await?;
                    return Ok(Access::Missing);
                };
                let access = check_scope(scope, owner.as_deref(), server.as_deref());
                if !matches!(access, Access::Allowed) {
                    transaction.rollback().await?;
                    return Ok(access);
                }
                sqlx::query(PRUNE_MESSAGES)
                    .bind(&self.id)
                    .bind(now)
                    .execute(&mut *transaction)
                    .await?;
                let queued = sqlx::query(QUEUE_MESSAGE)
                    .bind(&self.id)
                    .bind(sequence)
                    .bind(&payload)
                    .bind(size)
                    .bind(expires)
                    .bind(MAX_MESSAGES as i64)
                    .bind(MAX_QUEUE_BYTES as i64)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected()
                    == 1;
                transaction.commit().await?;
                if queued {
                    Access::Allowed
                } else {
                    Access::Full
                }
            }};
        }
        Ok(match &self.database {
            Database::Sqlite(pool) => enqueue!(pool),
            Database::Postgres(pool) => enqueue!(pool),
        })
    }

    pub(crate) async fn receive(&self) -> CacheResult<Option<Value>> {
        let mut idle = IDLE_POLL;
        loop {
            let now = Timestamp::now().as_millisecond();
            macro_rules! head {
                ($pool:expr) => {
                    sqlx::query_as::<_, QueueHead>(HEAD)
                        .bind(&self.id)
                        .bind(now)
                        .fetch_optional($pool)
                        .await?
                };
            }
            let entry = match &self.database {
                Database::Sqlite(pool) => head!(pool),
                Database::Postgres(pool) => head!(pool),
            };
            match entry {
                None => return Ok(None),
                Some((Some(sequence), Some(message), Some(expires))) => {
                    macro_rules! remove {
                        ($pool:expr) => {
                            sqlx::query(REMOVE_MESSAGE)
                                .bind(&self.id)
                                .bind(sequence)
                                .execute($pool)
                                .await?
                                .rows_affected()
                                == 1
                        };
                    }
                    let removed = match &self.database {
                        Database::Sqlite(pool) => remove!(pool),
                        Database::Postgres(pool) => remove!(pool),
                    };
                    if removed && expires > now {
                        return Ok(Some(serde_json::from_str(&message)?));
                    }
                }
                Some((None, None, None)) => {
                    sleep(idle).await;
                    idle = (idle * 2).min(Duration::from_secs(1));
                }
                _ => return Err("invalid database entry for SSE message".into()),
            }
        }
    }

    pub(crate) async fn remove(&self) {
        let result = match &self.database {
            Database::Sqlite(pool) => sqlx::query(REMOVE_SESSION)
                .bind(&self.id)
                .execute(pool)
                .await
                .map(|_| ()),
            Database::Postgres(pool) => sqlx::query(REMOVE_SESSION)
                .bind(&self.id)
                .execute(pool)
                .await
                .map(|_| ()),
        };
        if let Err(error) = result {
            tracing::debug!(%error, "legacy SSE database cleanup failed");
        }
    }
}

fn check_scope(scope: Scope<'_>, owner: Option<&str>, server: Option<&str>) -> Access {
    if scope.server != server {
        Access::Missing
    } else if scope.owner != owner && !scope.admin {
        Access::Denied
    } else {
        Access::Allowed
    }
}

fn expiry(now: i64, ttl: Duration) -> i64 {
    now.saturating_add(i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX).max(1))
}
