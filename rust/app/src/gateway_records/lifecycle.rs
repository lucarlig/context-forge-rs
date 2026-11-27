// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use jiff::Timestamp;
use uuid::Uuid;

use super::*;

macro_rules! due_gateways {
    ($expires:literal, $retry:literal, $now:literal, $lock:literal) => {
        concat!(
            "SELECT id FROM gateways WHERE status IN ('deleting', 'pending')
             AND (lifecycle_claim_expires_at IS NULL OR ",
            $expires,
            " <= ",
            $now,
            ")
             AND (status = 'deleting' OR next_retry_at IS NULL OR ",
            $retry,
            " <= ",
            $now,
            ")
             ORDER BY CASE WHEN status = 'deleting' THEN 0 ELSE 1 END, id LIMIT $2",
            $lock
        )
    };
}

const CLAIMED_GATEWAY: &str = concat!(gateway_select!(), " WHERE g.id = $1");

impl Database {
    pub(crate) async fn finish_deferred_gateway(
        &self,
        record: &GatewayRecord,
    ) -> Result<bool, sqlx::Error> {
        let now = Timestamp::now().to_string();
        macro_rules! finish {
            ($tx:ident, $lock:literal, $date:literal) => {{
                if lock_gateway!($tx, record, $lock).is_none() {
                    return Ok(false);
                }
                finish_gateway_initialization!($tx, record, &now, $date);
                $tx.commit().await?;
                Ok(true)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                finish!(tx, "", "$3")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                finish!(tx, " FOR UPDATE", "CAST(CAST($3 AS TEXT) AS TIMESTAMPTZ)")
            }
        }
    }

    pub(crate) async fn queue_gateway_deletion(
        &self,
        expected: &GatewayRecord,
    ) -> Result<bool, sqlx::Error> {
        macro_rules! queue {
            ($tx:ident, $lock:literal) => {{
                let Some(id) = lock_gateway!($tx, expected, $lock) else {
                    return Ok(false);
                };
                sqlx::query("UPDATE gateways SET status = 'deleting', reachable = FALSE,
                    status_message = 'Gateway deletion accepted and pending cleanup',
                    next_retry_at = NULL, last_error = NULL, updated_at = CURRENT_TIMESTAMP,
                    lifecycle_claimed_by = NULL, lifecycle_claimed_at = NULL, lifecycle_claim_expires_at = NULL
                    WHERE id = $1")
                    .bind(id).execute(&mut *$tx).await?;
                $tx.commit().await?;
                Ok(true)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                queue!(tx, "")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                queue!(tx, " FOR UPDATE")
            }
        }
    }

    pub(crate) async fn claim_gateway_lifecycle(
        &self,
        lease: Duration,
        limit: usize,
    ) -> Result<Vec<GatewayRecord>, sqlx::Error> {
        let claimed_at = Timestamp::now();
        let expires_at = claimed_at
            .saturating_add(lease)
            .unwrap_or(Timestamp::MAX)
            .to_string();
        let claimed_at = claimed_at.to_string();
        let claim = Uuid::new_v4().simple().to_string();
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        macro_rules! claim {
            ($tx:ident, $select:expr, $now:literal, $expires:literal) => {{
                let ids = sqlx::query_scalar::<_, String>($select)
                    .bind(&claimed_at)
                    .bind(limit)
                    .fetch_all(&mut *$tx)
                    .await?;
                let mut records = Vec::with_capacity(ids.len());
                for id in ids {
                    sqlx::query(concat!(
                        "UPDATE gateways SET lifecycle_claimed_by = $2,
                        lifecycle_claimed_at = ",
                        $now,
                        ", lifecycle_claim_expires_at = ",
                        $expires,
                        " WHERE id = $1"
                    ))
                    .bind(&id)
                    .bind(&claim)
                    .bind(&claimed_at)
                    .bind(&expires_at)
                    .execute(&mut *$tx)
                    .await?;
                    records.push(
                        sqlx::query_as::<_, GatewayRecord>(CLAIMED_GATEWAY)
                            .bind(id)
                            .fetch_one(&mut *$tx)
                            .await?,
                    );
                }
                $tx.commit().await?;
                Ok(records)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                claim!(
                    tx,
                    due_gateways!(
                        "julianday(lifecycle_claim_expires_at)",
                        "julianday(next_retry_at)",
                        "julianday($1)",
                        ""
                    ),
                    "$3",
                    "$4"
                )
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                claim!(
                    tx,
                    due_gateways!(
                        "lifecycle_claim_expires_at",
                        "next_retry_at",
                        "CAST(CAST($1 AS TEXT) AS TIMESTAMPTZ)",
                        " FOR UPDATE SKIP LOCKED"
                    ),
                    "CAST(CAST($3 AS TEXT) AS TIMESTAMPTZ)",
                    "CAST(CAST($4 AS TEXT) AS TIMESTAMPTZ)"
                )
            }
        }
    }

    pub(crate) async fn retry_gateway_lifecycle(
        &self,
        record: &GatewayRecord,
        error: &str,
    ) -> Result<(), sqlx::Error> {
        let attempts = record.registration_attempts.saturating_add(1);
        let exponent = attempts.saturating_sub(1).clamp(0, 9) as u32;
        let delay = Duration::from_secs((1u64 << exponent).min(300));
        let retry = Timestamp::now()
            .saturating_add(delay)
            .unwrap_or(Timestamp::MAX)
            .to_string();
        macro_rules! write {
            ($pool:ident, $date:literal) => {{
                sqlx::query(concat!("UPDATE gateways SET registration_attempts = $4,
                    next_retry_at = ", $date, ", status_message = $6, last_error = $6,
                    lifecycle_claimed_by = NULL, lifecycle_claimed_at = NULL, lifecycle_claim_expires_at = NULL
                    WHERE id = $1 AND status = 'pending' AND lifecycle_claimed_by = $2 AND version = $3"))
                    .bind(&record.id).bind(record.lifecycle_claimed_by.as_deref()).bind(record.version)
                    .bind(attempts).bind(&retry).bind(error)
                    .execute($pool).await?;
            }};
        }
        match self {
            Self::Sqlite(pool) => write!(pool, "$5"),
            Self::Postgres(pool) => write!(pool, "CAST(CAST($5 AS TEXT) AS TIMESTAMPTZ)"),
        };
        Ok(())
    }
}
