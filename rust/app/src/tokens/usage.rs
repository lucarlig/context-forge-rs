// SPDX-License-Identifier: Apache-2.0

use jiff::Timestamp;
use serde_json::{Value, json};

use super::*;

pub(crate) struct TokenRequest<'a> {
    pub(crate) endpoint: &'a str,
    pub(crate) method: &'a str,
    pub(crate) peer: Option<&'a str>,
    pub(crate) agent: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub(crate) struct TokenIdentity {
    pub(crate) id: String,
    pub(crate) jti: String,
    pub(crate) user_email: String,
}

pub(crate) enum TokenReservation {
    Allowed(Option<TokenUsageRecord>),
    Limited(&'static str),
    Inactive,
}

pub(crate) enum TokenUsageRecord {
    Log(i64),
    Quota(i64),
}

macro_rules! statistics {
    ($cutoff:literal) => {
        concat!(
            "SELECT COUNT(*), CAST(COALESCE(SUM(CASE WHEN status_code BETWEEN 1 AND 399
             THEN 1 ELSE 0 END),0) AS BIGINT),
             CAST(COALESCE(SUM(CASE WHEN blocked THEN 1 ELSE 0 END),0) AS BIGINT),
             CAST(COALESCE(AVG(NULLIF(response_time_ms,0)),0) AS DOUBLE PRECISION)
             FROM token_usage_logs WHERE token_jti=$1 AND ",
            $cutoff
        )
    };
}

macro_rules! endpoints {
    ($cutoff:literal) => {
        concat!(
            "SELECT endpoint,COUNT(*) AS total FROM token_usage_logs
             WHERE token_jti=$1 AND endpoint IS NOT NULL AND endpoint<>'' AND ",
            $cutoff,
            " GROUP BY endpoint ORDER BY total DESC, endpoint LIMIT 5"
        )
    };
}

impl Database {
    pub(crate) async fn token_usage_statistics(
        &self,
        jti: &str,
        days: i64,
    ) -> Result<Value, sqlx::Error> {
        let cutoff = timestamp_before(Timestamp::now(), days.saturating_mul(86400))?;
        macro_rules! select {
            ($pool:ident,$cutoff:literal) => {
                tokio::try_join!(
                    sqlx::query_as::<_, (i64, i64, i64, f64)>(statistics!($cutoff))
                        .bind(jti)
                        .bind(&cutoff)
                        .fetch_one($pool),
                    sqlx::query_as::<_, (String, i64)>(endpoints!($cutoff))
                        .bind(jti)
                        .bind(&cutoff)
                        .fetch_all($pool),
                )?
            };
        }
        let ((total, successful, blocked, average), endpoints) = match self {
            Self::Sqlite(pool) => select!(pool, "julianday(timestamp)>=julianday($2)"),
            Self::Postgres(pool) => {
                select!(pool, "timestamp>=CAST(CAST($2 AS TEXT) AS TIMESTAMPTZ)")
            }
        };
        Ok(json!({
            "period_days":days,"total_requests":total,"successful_requests":successful,"blocked_requests":blocked,
            "success_rate":if total==0 {0.0} else {successful as f64/total as f64},
            "average_response_time_ms":(average * 100.0).round_ties_even() / 100.0,"top_endpoints":endpoints,
        }))
    }

    pub(crate) async fn reserve_token_request(
        &self,
        token: &TokenIdentity,
        request: TokenRequest<'_>,
        log_requests: bool,
    ) -> Result<TokenReservation, sqlx::Error> {
        let now = Timestamp::now();
        macro_rules! reserve {
            ($tx:ident,$lock:literal,$cutoff:literal,$outdated:literal,$date:literal) => {{
                let row=sqlx::query_as::<_,(bool,Option<String>,Option<String>)>(concat!(
                    "SELECT t.is_active,CAST(t.usage_limits AS TEXT),CAST(t.expires_at AS TEXT)
                    FROM email_api_tokens t WHERE id=$1 AND jti=$2
                      AND NOT EXISTS(SELECT 1 FROM token_revocations r WHERE r.jti=t.jti)",$lock))
                    .bind(&token.id).bind(&token.jti).fetch_optional(&mut *$tx).await?;
                let Some((true,limits,expiry))=row else {
                    return Ok(TokenReservation::Inactive);
                };
                if expiry.as_deref().is_some_and(|value|date(value).is_none_or(|value|value<=now)) {
                    return Ok(TokenReservation::Inactive);
                }
                let limits=limits.as_deref().and_then(|encoded|serde_json::from_str::<Value>(encoded).ok()).unwrap_or_default();
                let mut limited=None;
                let mut has_quota=false;
                for (key,seconds,reason) in [
                    ("requests_per_hour",3600,"Hourly request limit exceeded"),
                    ("requests_per_day",86400,"Daily request limit exceeded"),
                ] {
                    if let Some(limit)=positive_limit(&limits[key]) {
                        has_quota=true;
                        let count:i64=sqlx::query_scalar(concat!(
                            "SELECT
                             (SELECT COUNT(*) FROM token_usage_logs WHERE token_jti=$1 AND NOT blocked AND ",$cutoff,")
                             + (SELECT COUNT(*) FROM cf_token_quota_events WHERE token_jti=$1 AND ",$cutoff,")"))
                            .bind(&token.jti).bind(timestamp_before(now,seconds)?).fetch_one(&mut *$tx).await?;
                        if count>=limit {
                            limited=Some(reason);
                            break;
                        }
                    }
                }
                let record=if log_requests {
                    let endpoint:String=request.endpoint.chars().take(255).collect();
                    let method:String=request.method.chars().take(10).collect();
                    let id=sqlx::query_scalar::<_,i64>("INSERT INTO token_usage_logs
                        (token_jti,user_email,endpoint,method,ip_address,user_agent,blocked,block_reason,status_code,timestamp)
                        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP) RETURNING CAST(id AS BIGINT)")
                        .bind(&token.jti).bind(&token.user_email).bind(endpoint).bind(method)
                        .bind(request.peer).bind(request.agent).bind(limited.is_some()).bind(limited)
                        .bind(limited.map(|_|429_i32)).fetch_one(&mut *$tx).await?;
                    Some(TokenUsageRecord::Log(id))
                } else if has_quota && limited.is_none() {
                    sqlx::query(concat!("DELETE FROM cf_token_quota_events WHERE token_jti=$1 AND ",$outdated))
                        .bind(&token.jti).bind(timestamp_before(now,86400)?).execute(&mut *$tx).await?;
                    let id=sqlx::query_scalar::<_,i64>("INSERT INTO cf_token_quota_events(token_jti)
                        VALUES($1) RETURNING CAST(id AS BIGINT)")
                        .bind(&token.jti).fetch_one(&mut *$tx).await?;
                    Some(TokenUsageRecord::Quota(id))
                } else {
                    None
                };
                if limited.is_none() {
                    sqlx::query(concat!("UPDATE email_api_tokens SET last_used=",$date," WHERE id=$1"))
                        .bind(&token.id).bind(now.to_string()).execute(&mut *$tx).await?;
                }
                $tx.commit().await?;
                Ok(limited.map_or(TokenReservation::Allowed(record),TokenReservation::Limited))
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                reserve!(
                    tx,
                    "",
                    "julianday(timestamp)>=julianday($2)",
                    "julianday(timestamp)<julianday($2)",
                    "$2"
                )
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                reserve!(
                    tx,
                    " FOR UPDATE",
                    "timestamp>=CAST(CAST($2 AS TEXT) AS TIMESTAMPTZ)",
                    "timestamp<CAST(CAST($2 AS TEXT) AS TIMESTAMPTZ)",
                    "CAST(CAST($2 AS TEXT) AS TIMESTAMPTZ)"
                )
            }
        }
    }

    pub(crate) async fn finish_token_request(
        &self,
        record: TokenUsageRecord,
        status: u16,
        elapsed_ms: i32,
    ) -> Result<(), sqlx::Error> {
        let blocked = matches!(status, 401 | 403 | 429);
        macro_rules! finish {
            ($pool:ident,$id:literal)=>{{
                match record {
                    TokenUsageRecord::Log(id) => {
                        sqlx::query(concat!(
                    "UPDATE token_usage_logs SET status_code=$2,response_time_ms=$3,blocked=$4 WHERE ",$id))
                    .bind(id).bind(i32::from(status)).bind(elapsed_ms).bind(blocked).execute($pool).await?;
                    }
                    TokenUsageRecord::Quota(id) if blocked => {
                        sqlx::query(concat!("DELETE FROM cf_token_quota_events WHERE ",$id))
                            .bind(id).execute($pool).await?;
                    }
                    TokenUsageRecord::Quota(_) => {}
                }
            }}
        }
        match self {
            Self::Sqlite(pool) => finish!(pool, "id=$1"),
            Self::Postgres(pool) => finish!(pool, "CAST(id AS BIGINT)=$1"),
        };
        Ok(())
    }
}

fn timestamp_before(now: Timestamp, seconds: i64) -> Result<String, sqlx::Error> {
    Timestamp::from_second(now.as_second().saturating_sub(seconds))
        .map(|timestamp| timestamp.to_string())
        .map_err(|error| sqlx::Error::Encode(Box::new(error)))
}

fn date(value: &str) -> Option<Timestamp> {
    let iso = value.replacen(' ', "T", 1);
    iso.parse().or_else(|_| format!("{iso}Z").parse()).ok()
}

fn positive_limit(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .filter(|value| *value > 0)
}
