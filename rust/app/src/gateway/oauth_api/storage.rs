// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use super::*;
use crate::database::observed;

#[derive(sqlx::FromRow)]
pub(super) struct OAuthGateway {
    pub(super) id: String,
    pub(super) version: i32,
    pub(super) name: String,
    pub(super) url: String,
    visibility: String,
    pub(super) team_id: Option<String>,
    owner_email: Option<String>,
    pub(super) oauth_config: Option<String>,
}

impl OAuthGateway {
    pub(super) fn visible(&self, principal: &Principal) -> bool {
        principal.is_global_admin()
            || access::catalog_scope(Some(principal)).visible(
                &self.visibility,
                self.team_id.as_deref(),
                self.owner_email.as_deref(),
            )
    }

    pub(super) fn visible_in(&self, email: &str, visibility: &TeamVisibility) -> bool {
        *visibility == TeamVisibility::Admin
            || crate::catalog::CatalogScope {
                email: Some(email),
                visibility,
            }
            .visible(
                &self.visibility,
                self.team_id.as_deref(),
                self.owner_email.as_deref(),
            )
    }

    pub(super) fn resource_origin(&self) -> Option<String> {
        resource_origin(&self.url)
    }
}

#[derive(sqlx::FromRow)]
pub(super) struct TokenStatus {
    gateway_id: String,
    expires_at: Option<String>,
    updated_at: Option<String>,
    scopes: Option<String>,
}

impl TokenStatus {
    pub(super) fn state(&self, now: Timestamp) -> &'static str {
        match self.expires_at.as_deref().and_then(parse_time) {
            Some(expiry) if expiry <= now => "expired",
            Some(expiry) if expiry.as_second() - now.as_second() < 300 => "near_expiry",
            _ => "valid",
        }
    }

    pub(super) fn metadata(&self, now: Timestamp) -> Value {
        let status = self.state(now);
        json!({
            "status":status,"authorized":status!="expired",
            "scopes":self.scopes.as_deref().and_then(|encoded|serde_json::from_str::<Value>(encoded).ok()),
            "expires_at":iso(self.expires_at.as_deref()),
            "updated_at":iso(self.updated_at.as_deref()),
        })
    }
}

fn iso(value: Option<&str>) -> Option<String> {
    value.map(|time| time.replacen(' ', "T", 1))
}

impl Database {
    pub(super) async fn oauth_gateways(
        &self,
        ids: &[String],
    ) -> Result<Vec<OAuthGateway>, sqlx::Error> {
        let ids = json!(ids).to_string();
        macro_rules! select {
            ($pool:ident,$array:literal) => {
                sqlx::query_as(concat!("SELECT id,version,name,url,visibility,team_id,owner_email,CAST(oauth_config AS TEXT) AS oauth_config
                    FROM gateways WHERE id IN (",$array,")")).bind(ids).fetch_all(observed($pool)).await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool, "SELECT value FROM json_each($1)"),
            Self::Postgres(pool) => select!(
                pool,
                "SELECT json_array_elements_text(CAST(CAST($1 AS TEXT) AS JSON))"
            ),
        }
    }

    pub(super) async fn oauth_statuses(
        &self,
        email: &str,
        ids: &[String],
    ) -> Result<HashMap<String, TokenStatus>, sqlx::Error> {
        let ids = json!(ids).to_string();
        macro_rules! select {
            ($pool:ident,$array:literal) => {
                sqlx::query_as::<_,TokenStatus>(concat!("SELECT gateway_id,CAST(expires_at AS TEXT) AS expires_at,
                    CAST(updated_at AS TEXT) AS updated_at,CAST(scopes AS TEXT) AS scopes
                    FROM oauth_tokens WHERE app_user_email=$1 AND gateway_id IN (",$array,")"))
                    .bind(email).bind(ids).fetch_all(observed($pool)).await?
            };
        }
        let rows = match self {
            Self::Sqlite(pool) => select!(pool, "SELECT value FROM json_each($2)"),
            Self::Postgres(pool) => select!(
                pool,
                "SELECT json_array_elements_text(CAST(CAST($2 AS TEXT) AS JSON))"
            ),
        };
        Ok(rows
            .into_iter()
            .map(|row| (row.gateway_id.clone(), row))
            .collect())
    }
}

#[derive(sqlx::FromRow)]
pub(super) struct OAuthState {
    pub(super) gateway_id: String,
    pub(super) gateway_version: i32,
    pub(super) code_verifier: Option<String>,
    pub(super) app_user_email: Option<String>,
    pub(super) redirect_uri: Option<String>,
    pub(super) browser_binding_hash: Option<String>,
}

pub(super) struct NewOAuthState<'a> {
    pub(super) gateway_id: &'a str,
    pub(super) gateway_version: i32,
    pub(super) state: &'a str,
    pub(super) verifier: &'a str,
    pub(super) email: &'a str,
    pub(super) redirect_uri: &'a str,
    pub(super) team_id: Option<&'a str>,
    pub(super) browser_binding_hash: &'a str,
}

pub(super) struct OAuthTokenWrite<'a> {
    pub(super) gateway_id: &'a str,
    pub(super) gateway_version: i32,
    pub(super) email: &'a str,
    pub(super) subject: &'a str,
    pub(super) access_token: &'a str,
    pub(super) refresh_token: Option<&'a str>,
    pub(super) expires_at: Option<Timestamp>,
    pub(super) scopes: Option<&'a [String]>,
    pub(super) learned_aud: Option<&'a Value>,
    pub(super) learned_iss: Option<&'a str>,
    pub(super) preserve_refresh: bool,
    pub(super) expected_access: Option<&'a str>,
}

#[derive(sqlx::FromRow)]
pub(super) struct StoredOAuthToken {
    pub(super) access_token: String,
    pub(super) refresh_token: Option<String>,
    pub(super) expires_at: Option<String>,
    pub(super) scopes: Option<String>,
    pub(super) token_type: Option<String>,
}

impl Database {
    pub(super) async fn put_oauth_state(
        &self,
        state: NewOAuthState<'_>,
    ) -> Result<bool, sqlx::Error> {
        macro_rules! insert {
            ($pool:ident,$expiry:literal,$lock:literal)=>{
                sqlx::query(concat!(
                    "INSERT INTO oauth_states(id,gateway_id,state,code_verifier,app_user_email,redirect_uri,
                        team_id,browser_binding_hash,expires_at,used,created_at)
                    SELECT $1,$2,$3,$4,$5,$6,$7,$8,",$expiry,",FALSE,CURRENT_TIMESTAMP
                    FROM gateways WHERE id=$2 AND version=$9 AND status='active'", $lock))
                    .bind(Uuid::new_v4().simple().to_string()).bind(state.gateway_id).bind(state.state)
                    .bind(state.verifier).bind(state.email).bind(state.redirect_uri).bind(state.team_id)
                    .bind(state.browser_binding_hash).bind(state.gateway_version)
                    .execute(observed($pool)).await?.rows_affected()!=0
            };
        }
        Ok(match self {
            Self::Sqlite(pool) => insert!(pool, "datetime(CURRENT_TIMESTAMP,'+300 seconds')", ""),
            Self::Postgres(pool) => insert!(
                pool,
                "CURRENT_TIMESTAMP+INTERVAL '300 seconds'",
                " FOR SHARE"
            ),
        })
    }

    pub(super) async fn consume_oauth_state(
        &self,
        state: &str,
    ) -> Result<Option<OAuthState>, sqlx::Error> {
        macro_rules! consume {
            ($pool:ident,$expiry:literal)=>{
                sqlx::query_as(concat!("UPDATE oauth_states SET used=TRUE WHERE state=$1 AND NOT used AND ",$expiry,
                    " RETURNING gateway_id,code_verifier,app_user_email,redirect_uri,browser_binding_hash,
                      (SELECT version FROM gateways WHERE id=oauth_states.gateway_id) AS gateway_version"))
                    .bind(state).fetch_optional(observed($pool)).await
            };
        }
        match self {
            Self::Sqlite(pool) => {
                consume!(pool, "julianday(expires_at)>julianday(CURRENT_TIMESTAMP)")
            }
            Self::Postgres(pool) => consume!(pool, "expires_at>clock_timestamp()"),
        }
    }

    pub(super) async fn write_oauth_tokens(
        &self,
        token: OAuthTokenWrite<'_>,
    ) -> Result<bool, sqlx::Error> {
        let expires = token.expires_at.map(|expires| expires.to_string());
        let scopes = token.scopes.map(|scopes| json!(scopes).to_string());
        let aud = token.learned_aud.map(Value::to_string);
        macro_rules! write {
            ($pool:ident,$date:literal,$scopes:literal,$audience:literal,$lock:literal)=>{
                sqlx::query(concat!("INSERT INTO oauth_tokens
                    (id,gateway_id,user_id,app_user_email,access_token,refresh_token,token_type,expires_at,scopes,
                     learned_aud,learned_iss,created_at,updated_at)
                    SELECT $1,$2,$3,$4,$5,$6,'Bearer',",$date,",",$scopes,",",$audience,",$10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
                    WHERE EXISTS(SELECT 1 FROM gateways WHERE id=$2 AND version=$13 AND status='active'", $lock, ")
                      AND EXISTS(SELECT 1 FROM email_users WHERE email=$4 AND is_active=TRUE)
                      AND (CAST($12 AS TEXT) IS NULL OR EXISTS(SELECT 1 FROM oauth_tokens prior
                          WHERE prior.gateway_id=$2 AND prior.app_user_email=$4 AND prior.access_token=$12))
                    ON CONFLICT(gateway_id,app_user_email) DO UPDATE SET user_id=excluded.user_id,access_token=excluded.access_token,
                    refresh_token=CASE WHEN $11 THEN COALESCE(excluded.refresh_token,oauth_tokens.refresh_token)
                      ELSE excluded.refresh_token END,token_type=excluded.token_type,
                    expires_at=excluded.expires_at,scopes=COALESCE(excluded.scopes,oauth_tokens.scopes),
                    learned_aud=COALESCE(excluded.learned_aud,oauth_tokens.learned_aud),learned_iss=COALESCE(excluded.learned_iss,oauth_tokens.learned_iss),
                    updated_at=CURRENT_TIMESTAMP
                    WHERE CAST($12 AS TEXT) IS NULL OR oauth_tokens.access_token=$12"))
                    .bind(Uuid::new_v4().simple().to_string()).bind(token.gateway_id).bind(token.subject).bind(token.email)
                    .bind(token.access_token).bind(token.refresh_token).bind(expires).bind(scopes).bind(aud).bind(token.learned_iss)
                    .bind(token.preserve_refresh).bind(token.expected_access).bind(token.gateway_version)
                    .execute(observed($pool)).await?.rows_affected()!=0
            };
        }
        Ok(match self {
            Self::Sqlite(pool) => write!(pool, "$7", "json($8)", "json($9)", ""),
            Self::Postgres(pool) => write!(
                pool,
                "CAST(CAST($7 AS TEXT) AS TIMESTAMPTZ)",
                "CAST(CAST($8 AS TEXT) AS JSON)", "CAST(CAST($9 AS TEXT) AS JSON)", " FOR SHARE"
            ),
        })
    }

    pub(super) async fn user_oauth_token(
        &self,
        id: &str,
        email: &str,
        version: i32,
    ) -> Result<Option<StoredOAuthToken>, sqlx::Error> {
        const SQL:&str="SELECT CAST(access_token AS TEXT) AS access_token,CAST(refresh_token AS TEXT) AS refresh_token,
            CAST(expires_at AS TEXT) AS expires_at,CAST(scopes AS TEXT) AS scopes,token_type
            FROM oauth_tokens WHERE gateway_id=$1 AND app_user_email=$2
              AND EXISTS (SELECT 1 FROM gateways WHERE id=$1 AND version=$3 AND status='active')";
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(SQL)
                    .bind(id)
                    .bind(email)
                    .bind(version)
                    .fetch_optional(observed(pool))
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(SQL)
                    .bind(id)
                    .bind(email)
                    .bind(version)
                    .fetch_optional(observed(pool))
                    .await
            }
        }
    }
}

impl Database {
    pub(super) async fn claim_oauth_refresh(
        &self,
        gateway: &str,
        email: &str,
        claim: &str,
    ) -> Result<bool, sqlx::Error> {
        macro_rules! acquire {
            ($pool:ident,$expiry:literal,$past:literal) => {
                sqlx::query(concat!("INSERT INTO cf_oauth_refresh_claims(gateway_id,app_user_email,claim,expires_at)
                    SELECT $1,$2,$3,",$expiry," WHERE EXISTS(SELECT 1 FROM oauth_tokens WHERE gateway_id=$1 AND app_user_email=$2)
                    ON CONFLICT(gateway_id,app_user_email) DO UPDATE SET claim=excluded.claim,expires_at=excluded.expires_at
                    WHERE ",$past))
                    .bind(gateway).bind(email).bind(claim).execute(observed($pool)).await?.rows_affected()!=0
            };
        }
        Ok(match self {
            Self::Sqlite(pool) => acquire!(
                pool,
                "datetime(CURRENT_TIMESTAMP,'+60 seconds')",
                "julianday(cf_oauth_refresh_claims.expires_at)<=julianday(CURRENT_TIMESTAMP)"
            ),
            Self::Postgres(pool) => acquire!(
                pool,
                "clock_timestamp()+INTERVAL '60 seconds'",
                "cf_oauth_refresh_claims.expires_at<=clock_timestamp()"
            ),
        })
    }

    pub(super) async fn release_oauth_refresh(
        &self,
        gateway: &str,
        email: &str,
        claim: &str,
    ) -> Result<(), sqlx::Error> {
        const SQL: &str = "DELETE FROM cf_oauth_refresh_claims WHERE gateway_id=$1 AND app_user_email=$2 AND claim=$3";
        macro_rules! release {
            ($pool:ident) => {{
                sqlx::query(SQL)
                    .bind(gateway)
                    .bind(email)
                    .bind(claim)
                    .execute(observed($pool))
                    .await?;
            }};
        }
        match self {
            Self::Sqlite(pool) => release!(pool),
            Self::Postgres(pool) => release!(pool),
        }
        Ok(())
    }
}
