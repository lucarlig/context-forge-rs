// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(in crate::local_auth) enum ResetRequest {
    Limited,
    Accepted,
    Issued(Option<String>),
}

#[derive(sqlx::FromRow)]
pub(in crate::local_auth) struct ResetToken {
    pub(in crate::local_auth) user_email: String,
    pub(in crate::local_auth) expires_at: String,
    pub(in crate::local_auth) used: bool,
}

impl Database {
    pub(in crate::local_auth) async fn request_local_password_reset(
        &self,
        email: &str,
        hash: &str,
        client: &Client,
        reset: &ResetSettings,
    ) -> Result<ResetRequest, sqlx::Error> {
        let timestamp = Timestamp::now().as_second();
        let date = |seconds| {
            Timestamp::from_second(seconds)
                .map(|date| date.to_string())
                .map_err(|error| sqlx::Error::Encode(Box::new(error)))
        };
        let cutoff = date(timestamp - reset.window)?;
        let expiry = date(timestamp + reset.lifetime)?;
        macro_rules! request {
            ($tx:ident,$cutoff:literal,$not_expired:literal,$expiry:literal) => {{
                let count:i64=sqlx::query_scalar(concat!(
                    "SELECT COUNT(*) FROM email_auth_events WHERE user_email=$1 AND event_type='PASSWORD_RESET_REQUESTED'
                    AND ",$cutoff)).bind(email).bind(cutoff).fetch_one(&mut *$tx).await?;
                let limited=count>=reset.limit;
                sqlx::query("INSERT INTO email_auth_events(timestamp,user_email,event_type,success,ip_address,user_agent)
                        VALUES(CURRENT_TIMESTAMP,$1,$2,$3,$4,$5)")
                    .bind(email).bind(if limited {"PASSWORD_RESET_RATE_LIMITED"} else {"PASSWORD_RESET_REQUESTED"})
                    .bind(!limited).bind(client.address.as_deref()).bind(client.user_agent.as_deref()).execute(&mut *$tx).await?;
                if limited {
                    $tx.commit().await?;
                    return Ok(ResetRequest::Limited);
                }
                let recipient=sqlx::query_scalar::<_,Option<String>>("SELECT full_name FROM email_users
                        WHERE email=$1 AND is_active=TRUE AND password_hash IS NOT NULL")
                    .bind(email).fetch_optional(&mut *$tx).await?;
                let Some(name)=recipient else {
                    $tx.commit().await?;
                    return Ok(ResetRequest::Accepted);
                };
                sqlx::query(concat!("UPDATE password_reset_tokens SET used_at=CURRENT_TIMESTAMP
                    WHERE user_email=$1 AND used_at IS NULL AND ",$not_expired))
                    .bind(email).execute(&mut *$tx).await?;
                sqlx::query(concat!("INSERT INTO password_reset_tokens
                    (id,user_email,token_hash,created_at,expires_at,ip_address,user_agent)
                    VALUES($1,$2,$3,CURRENT_TIMESTAMP,",$expiry,",$5,$6)"))
                    .bind(Uuid::new_v4().to_string()).bind(email).bind(hash).bind(expiry)
                    .bind(client.address.as_deref()).bind(client.user_agent.as_deref()).execute(&mut *$tx).await?;
                $tx.commit().await?;
                Ok(ResetRequest::Issued(name))
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                request!(
                    tx,
                    "julianday(timestamp)>=julianday($2)",
                    "julianday(expires_at)>julianday(CURRENT_TIMESTAMP)",
                    "$4"
                )
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682073)")
                    .execute(&mut *tx)
                    .await?;
                request!(
                    tx,
                    "timestamp>=CAST(CAST($2 AS TEXT) AS TIMESTAMPTZ)",
                    "expires_at>CURRENT_TIMESTAMP",
                    "CAST(CAST($4 AS TEXT) AS TIMESTAMPTZ)"
                )
            }
        }
    }

    pub(in crate::local_auth) async fn local_password_reset(
        &self,
        hash: &str,
    ) -> Result<Option<ResetToken>, sqlx::Error> {
        macro_rules! select {
            ($pool:ident) => {
                sqlx::query_as("SELECT user_email,CAST(expires_at AS TEXT) AS expires_at,
                    (used_at IS NOT NULL) AS used FROM password_reset_tokens WHERE token_hash=$1")
                    .bind(hash).fetch_optional($pool).await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool),
            Self::Postgres(pool) => select!(pool),
        }
    }
}
