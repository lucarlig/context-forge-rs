// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Debug, thiserror::Error)]
pub(crate) enum TokenWriteError {
    #[error("token name is already registered")]
    Duplicate,
    #[error("token changed concurrently")]
    Changed,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

macro_rules! token_insert {
    ($open:literal, $close:literal, $expiry:literal) => {
        concat!(
            "INSERT INTO email_api_tokens (id,user_email,name,jti,token_hash,server_id,team_id,description,
                resource_scopes,ip_restrictions,time_restrictions,usage_limits,tags,expires_at,is_active)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,",
            $open,"$9",$close,",",$open,"$10",$close,",",$open,"$11",$close,",",
            $open,"$12",$close,",",$open,"$13",$close,",",$expiry,",$15)"
        )
    };
}

macro_rules! token_update {
    ($open:literal, $close:literal) => {
        concat!(
            "UPDATE email_api_tokens SET name=$2,description=$3,server_id=$4,resource_scopes=",
            $open,
            "$5",
            $close,
            ",ip_restrictions=",
            $open,
            "$6",
            $close,
            ",time_restrictions=",
            $open,
            "$7",
            $close,
            ",usage_limits=",
            $open,
            "$8",
            $close,
            ",tags=",
            $open,
            "$9",
            $close,
            ",is_active=$10 WHERE id=$1"
        )
    };
}

const ACTIVE_NAME_CONFLICT: &str = "
    SELECT EXISTS(SELECT 1 FROM email_api_tokens WHERE user_email=$1 AND name=$2
        AND team_id IS NOT DISTINCT FROM $3 AND id<>$4)";

impl Database {
    pub(crate) async fn issue_managed_token(
        &self,
        record: &ApiTokenRecord,
    ) -> Result<ApiTokenRecord, TokenWriteError> {
        macro_rules! insert {
            ($tx:ident,$open:literal,$close:literal,$expiry:literal) => {{
                let duplicate = sqlx::query_scalar::<_, bool>(ACTIVE_NAME_CONFLICT)
                    .bind(&record.user_email)
                    .bind(&record.name)
                    .bind(record.team_id.as_deref())
                    .bind(&record.id)
                    .fetch_one(&mut *$tx)
                    .await?;
                if duplicate {
                    return Err(TokenWriteError::Duplicate);
                }
                sqlx::query(token_insert!($open, $close, $expiry))
                    .bind(&record.id)
                    .bind(&record.user_email)
                    .bind(&record.name)
                    .bind(&record.jti)
                    .bind(&record.token_hash)
                    .bind(record.server_id.as_deref())
                    .bind(record.team_id.as_deref())
                    .bind(record.description.as_deref())
                    .bind(record.resource_scopes.as_deref())
                    .bind(record.ip_restrictions.as_deref())
                    .bind(record.time_restrictions.as_deref())
                    .bind(record.usage_limits.as_deref())
                    .bind(record.tags.as_deref())
                    .bind(record.expires_at.as_deref())
                    .bind(record.is_active)
                    .execute(&mut *$tx)
                    .await?;
                let stored = sqlx::query_as(TOKEN_BY_ID)
                    .bind(&record.id)
                    .fetch_one(&mut *$tx)
                    .await?;
                $tx.commit().await?;
                Ok(stored)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                insert!(tx, "json(", ")", "$14")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682072)")
                    .execute(&mut *tx)
                    .await?;
                insert!(
                    tx,
                    "CAST(",
                    " AS JSON)",
                    "CAST(CAST($14 AS TEXT) AS TIMESTAMPTZ)"
                )
            }
        }
    }

    pub(crate) async fn update_managed_token(
        &self,
        prior: &ApiTokenRecord,
        record: &ApiTokenRecord,
    ) -> Result<ApiTokenRecord, TokenWriteError> {
        macro_rules! update {
            ($tx:ident,$lock:literal,$open:literal,$close:literal) => {{
                let exists: Option<String> = sqlx::query_scalar(concat!(
                    "SELECT t.id FROM email_api_tokens t WHERE t.id=$1 AND t.name=$2 AND t.is_active=$3
                        AND t.description IS NOT DISTINCT FROM $4 AND t.server_id IS NOT DISTINCT FROM $5
                        AND CAST(t.resource_scopes AS TEXT) IS NOT DISTINCT FROM $6
                        AND CAST(t.ip_restrictions AS TEXT) IS NOT DISTINCT FROM $7
                        AND CAST(t.time_restrictions AS TEXT) IS NOT DISTINCT FROM $8
                        AND CAST(t.usage_limits AS TEXT) IS NOT DISTINCT FROM $9
                        AND CAST(t.tags AS TEXT) IS NOT DISTINCT FROM $10
                        AND NOT EXISTS(SELECT 1 FROM token_revocations r WHERE r.jti=t.jti)",$lock))
                    .bind(&prior.id).bind(&prior.name).bind(prior.is_active).bind(prior.description.as_deref())
                    .bind(prior.server_id.as_deref()).bind(prior.resource_scopes.as_deref())
                    .bind(prior.ip_restrictions.as_deref()).bind(prior.time_restrictions.as_deref())
                    .bind(prior.usage_limits.as_deref()).bind(prior.tags.as_deref()).fetch_optional(&mut *$tx).await?;
                if exists.is_none() {
                    return Err(TokenWriteError::Changed);
                }
                if prior.name!=record.name && sqlx::query_scalar::<_,bool>(ACTIVE_NAME_CONFLICT)
                    .bind(&record.user_email).bind(&record.name).bind(record.team_id.as_deref()).bind(&record.id)
                    .fetch_one(&mut *$tx).await?
                {
                    return Err(TokenWriteError::Duplicate);
                }
                sqlx::query(token_update!($open,$close))
                    .bind(&record.id).bind(&record.name).bind(record.description.as_deref()).bind(record.server_id.as_deref())
                    .bind(record.resource_scopes.as_deref()).bind(record.ip_restrictions.as_deref())
                    .bind(record.time_restrictions.as_deref()).bind(record.usage_limits.as_deref())
                    .bind(record.tags.as_deref()).bind(record.is_active).execute(&mut *$tx).await?;
                let updated=sqlx::query_as(TOKEN_BY_ID).bind(&record.id).fetch_one(&mut *$tx).await?;
                $tx.commit().await?;
                Ok(updated)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                update!(tx, "", "json(", ")")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682072)")
                    .execute(&mut *tx)
                    .await?;
                update!(tx, " FOR UPDATE", "CAST(", " AS JSON)")
            }
        }
    }

    pub(crate) async fn revoke_managed_token(
        &self,
        record: &ApiTokenRecord,
        actor: &str,
        reason: Option<&str>,
    ) -> Result<(), TokenWriteError> {
        macro_rules! revoke {
            ($tx:ident) => {{
                let changed=sqlx::query("UPDATE email_api_tokens SET is_active=FALSE WHERE id=$1 AND jti=$2")
                    .bind(&record.id).bind(&record.jti).execute(&mut *$tx).await?;
                if changed.rows_affected()!=1 {
                    return Err(TokenWriteError::Changed);
                }
                sqlx::query("INSERT INTO token_revocations(jti,revoked_by,reason,token_expiry)
                    SELECT jti,$2,$3,expires_at FROM email_api_tokens WHERE id=$1 ON CONFLICT (jti) DO NOTHING")
                    .bind(&record.id).bind(actor).bind(reason).execute(&mut *$tx).await?;
                $tx.commit().await?;
                Ok(())
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                revoke!(tx)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                revoke!(tx)
            }
        }
    }
}
