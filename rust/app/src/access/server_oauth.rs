// SPDX-License-Identifier: Apache-2.0

use axum::http::Uri;
use jiff::Timestamp;

use super::*;
use crate::{
    database::observed,
    gateway::{oauth_issuers, resource_metadata_url},
    local_auth::{is_id_token, unverified_jwt_claims, verify_oidc_jwt},
    upstream::UpstreamClient,
};

const UNCONFIGURED: &str = "OAuth authorization server not configured for this resource";
const APPROVAL_REQUIRED: &str = "OAuth configuration requires administrator approval";

#[derive(Clone)]
pub(crate) struct ServerOAuthVerifier {
    upstream: UpstreamClient,
    allow_http_loopback: bool,
}

impl ServerOAuthVerifier {
    pub(crate) fn new(upstream: UpstreamClient, allow_http_loopback: bool) -> Self {
        Self {
            upstream,
            allow_http_loopback,
        }
    }

    pub(super) async fn authenticate(
        &self,
        access: &Authorizer,
        base: &str,
        server_id: &str,
        headers: &HeaderMap,
        uri: &Uri,
        token: &str,
    ) -> Result<Option<Principal>, AuthError> {
        let Some(unverified) = unverified_jwt_claims(token) else {
            return Ok(None);
        };
        let Some(issuer) = unverified
            .get("iss")
            .and_then(Value::as_str)
            .filter(|issuer| {
                !issuer.is_empty()
                    && issuer.len() <= 500
                    && issuer.trim_end_matches('/')
                        != access.internal_jwt_issuer.trim_end_matches('/')
            })
        else {
            return Ok(None);
        };
        let Some(server) = access
            .database
            .managed_server(server_id)
            .await?
            .filter(|server| server.oauth_enabled)
        else {
            return Ok(None);
        };
        let config = server
            .oauth_config
            .as_deref()
            .and_then(|config| serde_json::from_str::<Value>(config).ok())
            .filter(Value::is_object)
            .ok_or_else(|| unavailable(UNCONFIGURED))?;
        let allowed = oauth_issuers(&config, self.allow_http_loopback);
        if allowed.is_empty() {
            return Err(unavailable(UNCONFIGURED));
        }
        if !allowed
            .iter()
            .any(|allowed| allowed.trim_end_matches('/') == issuer.trim_end_matches('/'))
        {
            return Ok(None);
        }
        let generation = server
            .oauth_config_generation
            .as_deref()
            .filter(|generation| !generation.is_empty())
            .filter(|_| server.oauth_config_approved)
            .ok_or_else(|| unavailable(APPROVAL_REQUIRED))?;
        let invalid = || {
            let target = resource_metadata_url(base, headers, uri, server_id);
            let challenge =
                HeaderValue::from_str(&format!("Bearer resource_metadata=\"{target}\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("Bearer"));
            AuthError::ServerOAuth {
                status: StatusCode::UNAUTHORIZED,
                detail: "Invalid OAuth access token",
                challenge: Some(challenge),
            }
        };
        if is_id_token(&unverified) {
            return Err(invalid());
        }
        let canonical = format!("{}/servers/{server_id}/mcp", base.trim_end_matches('/'));
        let resource = configured_audiences(&config["resource"]);
        let mut audiences = resource.clone();
        if audiences.is_empty() {
            audiences.push(&canonical);
            audiences.extend(
                config["client_id"]
                    .as_str()
                    .map(str::trim)
                    .filter(|id| !id.is_empty()),
            );
        }
        let claims = verify_oidc_jwt(&self.upstream, issuer, &audiences, None, None, token)
            .await
            .ok_or_else(invalid)?;
        let expiry = claims
            .get("exp")
            .and_then(Value::as_i64)
            .filter(|expiry| *expiry > Timestamp::now().as_second())
            .ok_or_else(invalid)?;
        let email = ["email", "preferred_username", "sub"]
            .into_iter()
            .find_map(|claim| {
                claims
                    .get(claim)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
            })
            .map(|email| email.trim().to_ascii_lowercase())
            .filter(|email| email.contains('@') && email.len() <= 255)
            .ok_or_else(|| denied("OAuth token missing valid email claim"))?;
        let identity = match access
            .database
            .active_identity(Some(&email), None, None)
            .await?
        {
            Some(identity) => identity,
            None => {
                return Err(
                    match access.database.server_oauth_account_state(&email).await? {
                        None => denied(
                            "User not registered in ContextForge. Please log in via SSO first.",
                        ),
                        Some(false) => denied("Account disabled"),
                        Some(true) => AuthError::Invalid,
                    },
                );
            }
        };
        if resource.is_empty()
            && let Some(matched) = audiences
                .iter()
                .find(|audience| audience_matches(claims.get("aud"), audience))
        {
            access
                .database
                .learn_server_oauth_audience(server_id, generation, matched)
                .await?;
        }
        let current = access
            .database
            .managed_server(server_id)
            .await?
            .filter(|server| {
                server.enabled
                    && server.oauth_enabled
                    && server.oauth_config_approved
                    && server.oauth_config_generation.as_deref() == Some(generation)
            })
            .ok_or_else(|| unavailable(APPROVAL_REQUIRED))?;
        let current_config: Option<Value> = current
            .oauth_config
            .as_deref()
            .and_then(|config| serde_json::from_str(config).ok());
        if current_config.as_ref().is_some_and(|config| {
            let expected = configured_audiences(&config["resource"]);
            !expected.is_empty()
                && !expected
                    .iter()
                    .any(|audience| audience_matches(claims.get("aud"), audience))
        }) {
            return Err(invalid());
        }
        let visibility = identity.session_visibility(&access.database).await?;
        Ok(Some(Principal {
            email: identity.email,
            visibility,
            full_name: identity.full_name,
            expires_at: Some(expiry),
            token_use: TokenUse::Session,
            catalog_token: None,
            catalog_scopes: None,
            server_limit: None,
            is_admin: identity.is_admin,
            unrestricted_team_session: false,
            scopes: Vec::new(),
            credential_hash: Sha256::digest(token.as_bytes()).into(),
        }))
    }
}

fn configured_audiences(resource: &Value) -> Vec<&str> {
    match resource {
        Value::String(audience) if !audience.trim().is_empty() => vec![audience],
        Value::Array(audiences) => audiences
            .iter()
            .filter_map(Value::as_str)
            .filter(|audience| !audience.trim().is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn audience_matches(claim: Option<&Value>, expected: &str) -> bool {
    match claim {
        Some(Value::String(audience)) => audience == expected,
        Some(Value::Array(audiences)) => audiences
            .iter()
            .any(|audience| audience.as_str() == Some(expected)),
        _ => false,
    }
}

fn unavailable(detail: &'static str) -> AuthError {
    AuthError::ServerOAuth {
        status: StatusCode::SERVICE_UNAVAILABLE,
        detail,
        challenge: None,
    }
}

fn denied(detail: &'static str) -> AuthError {
    AuthError::ServerOAuth {
        status: StatusCode::UNAUTHORIZED,
        detail,
        challenge: None,
    }
}

impl Database {
    async fn server_oauth_account_state(&self, email: &str) -> Result<Option<bool>, sqlx::Error> {
        const SELECT: &str = "SELECT is_active FROM email_users WHERE email=$1";
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar(SELECT)
                    .bind(email)
                    .fetch_optional(observed(pool))
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar(SELECT)
                    .bind(email)
                    .fetch_optional(observed(pool))
                    .await
            }
        }
    }

    async fn learn_server_oauth_audience(
        &self,
        id: &str,
        generation: &str,
        audience: &str,
    ) -> Result<(), sqlx::Error> {
        macro_rules! learn {
            ($pool:expr,$config:literal,$absent:literal) => {{
                sqlx::query(concat!("UPDATE servers SET oauth_config=", $config, ",version=COALESCE(version,0)+1
                    WHERE id=$1 AND oauth_enabled AND oauth_config_approved AND oauth_config_generation=$2
                      AND ", $absent))
                    .bind(id).bind(generation).bind(audience).execute(observed($pool)).await?;
            }};
        }
        match self {
            Self::Sqlite(pool) => learn!(
                pool,
                "json_set(oauth_config,'$.resource',$3)",
                "NULLIF(json_extract(oauth_config,'$.resource'),'') IS NULL"
            ),
            Self::Postgres(pool) => learn!(
                pool,
                "CAST(jsonb_set(CAST(oauth_config AS JSONB),'{resource}',to_jsonb(CAST($3 AS TEXT)),TRUE) AS JSON)",
                "NULLIF(oauth_config->>'resource','') IS NULL"
            ),
        }
        Ok(())
    }
}
