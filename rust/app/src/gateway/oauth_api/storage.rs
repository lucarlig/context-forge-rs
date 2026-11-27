// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use super::*;

#[derive(sqlx::FromRow)]
pub(super) struct OAuthGateway {
    pub(super) id: String,
    visibility: String,
    team_id: Option<String>,
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
}

#[derive(sqlx::FromRow)]
pub(super) struct TokenStatus {
    gateway_id: String,
    expires_at: Option<String>,
    updated_at: Option<String>,
    scopes: Option<String>,
}

impl TokenStatus {
    pub(super) fn metadata(&self, now: Timestamp) -> Value {
        let status = match self.expires_at.as_deref().and_then(parse_time) {
            Some(expiry) if expiry <= now => "expired",
            Some(expiry) if expiry.as_second() - now.as_second() < 300 => "near_expiry",
            _ => "valid",
        };
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
                sqlx::query_as(concat!("SELECT id,visibility,team_id,owner_email,CAST(oauth_config AS TEXT) AS oauth_config
                    FROM gateways WHERE id IN (",$array,")")).bind(ids).fetch_all($pool).await
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
                    .bind(email).bind(ids).fetch_all($pool).await?
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
