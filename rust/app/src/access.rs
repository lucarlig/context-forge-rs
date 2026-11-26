// SPDX-License-Identifier: Apache-2.0

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use serde_json::{Value, json};

use crate::{
    auth::{self, TeamVisibility},
    database::Database,
    identity::{Grant, Identity},
    jwt::{JwtError, JwtVerifier, TokenUse, VerifiedJwt},
    mcp,
};

const GLOBAL_ONLY_PERMISSIONS: &[&str] = &[
    "admin.user_management",
    "admin.security_audit",
    "admin.sso_providers:create",
    "admin.sso_providers:read",
    "admin.sso_providers:update",
    "admin.sso_providers:delete",
];

pub struct Authorizer {
    database: Database,
    verifier: Option<JwtVerifier>,
    invalidate_sessions_on_password_change: bool,
}

#[derive(Clone, Debug)]
pub struct Principal {
    pub email: String,
    pub visibility: TeamVisibility,
    is_admin: bool,
    scopes: Vec<String>,
}

pub enum RoleContext<'a> {
    Global,
    Team(&'a str),
    AnyTeam,
}

#[derive(Clone)]
struct McpAccess {
    auth: Arc<Authorizer>,
    require_auth: bool,
}

impl Authorizer {
    pub fn new(
        database: Database,
        verifier: Option<JwtVerifier>,
        invalidate_sessions_on_password_change: bool,
    ) -> Self {
        Self {
            database,
            verifier,
            invalidate_sessions_on_password_change,
        }
    }

    pub fn mcp_router(self, require_auth: bool) -> Router {
        mcp::router().route_layer(middleware::from_fn_with_state(
            McpAccess {
                auth: Arc::new(self),
                require_auth,
            },
            authorize_mcp,
        ))
    }

    async fn authenticate(
        &self,
        token: &str,
        peer: Option<IpAddr>,
        server_id: Option<&str>,
    ) -> Result<Principal, AuthError> {
        let verifier = self.verifier.as_ref().ok_or(AuthError::Invalid)?;
        let jwt = verifier.verify(token).map_err(|error| match error {
            JwtError::TimeRestricted | JwtError::InvalidTimeRestrictions => AuthError::Forbidden,
            _ => AuthError::Invalid,
        })?;
        let scopes = verify_restrictions(jwt.payload(), peer, server_id)?;
        let identity = self.resolve_identity(&jwt).await?;
        let visibility = match jwt.token_use() {
            TokenUse::Api => auth::normalize_api_teams(jwt.payload()),
            TokenUse::Session => {
                let db_visibility = identity.session_visibility(&self.database).await?;
                auth::resolve_session_teams(jwt.payload(), Some(&identity.email), &db_visibility)
            }
        }
        .map_err(|_| AuthError::Invalid)?;

        if jwt.token_use() == TokenUse::Api
            && let TeamVisibility::Teams(claimed) = &visibility
        {
            let active = self.database.memberships(&identity.email).await?;
            if !claimed.iter().all(|team| active.contains(team)) {
                return Err(AuthError::TeamRevoked);
            }
        }

        // Cap API visibility by the persisted admin flag, including tokens issued before demotion.
        let visibility = if visibility == TeamVisibility::Admin && !identity.is_admin {
            TeamVisibility::Public
        } else {
            visibility
        };

        Ok(Principal {
            email: identity.email,
            visibility,
            is_admin: identity.is_admin,
            scopes,
        })
    }

    async fn resolve_identity(&self, jwt: &VerifiedJwt) -> Result<Identity, AuthError> {
        let payload = jwt.payload();
        let email = [
            payload.get("user").and_then(|user| user.get("email")),
            payload.get("email"),
            payload.get("sub"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .find(|identity| identity.contains('@'));
        let identity = self
            .database
            .active_identity(email, jwt.subject(), jwt.jti())
            .await?
            .ok_or(AuthError::Invalid)?;
        if self.invalidate_sessions_on_password_change
            && jwt.token_use() == TokenUse::Session
            && let Some(password_change_time) = identity.password_changed_at
            && jwt
                .payload()
                .get("iat")
                .and_then(Value::as_i64)
                .is_none_or(|iat| iat < password_change_time)
        {
            return Err(AuthError::Invalid);
        }
        Ok(identity)
    }

    pub async fn allows(
        &self,
        principal: &Principal,
        permission: &str,
        target: RoleContext<'_>,
        allow_admin_bypass: bool,
    ) -> Result<bool, sqlx::Error> {
        if !auth::token_scope_grants(Some(&principal.scopes), permission) {
            return Ok(false);
        }
        if allow_admin_bypass
            && principal.is_admin
            && principal.visibility != TeamVisibility::Public
        {
            return Ok(true);
        }

        let target = if GLOBAL_ONLY_PERMISSIONS.contains(&permission) {
            RoleContext::Global
        } else {
            target
        };
        let grants = self.database.grants(&principal.email).await?;
        Ok(grants.iter().any(|grant| {
            grant_applies(grant, &principal.visibility, &target)
                && grant
                    .permissions
                    .iter()
                    .any(|value| value == permission || value == "*")
        }))
    }
}

fn grant_applies(grant: &Grant, visibility: &TeamVisibility, target: &RoleContext<'_>) -> bool {
    match grant.scope.as_str() {
        "global" | "personal" => true,
        "team" => match visibility {
            TeamVisibility::Public => false,
            TeamVisibility::Admin => eligible_team(grant, target),
            TeamVisibility::Teams(allowed) => {
                let in_scope = |team: &str| allowed.iter().any(|value| value == team);
                if let RoleContext::Team(team) = target
                    && !in_scope(team)
                {
                    return false;
                }
                grant.team_id.as_deref().is_none_or(in_scope) && eligible_team(grant, target)
            }
        },
        _ => false,
    }
}

fn eligible_team(grant: &Grant, target: &RoleContext<'_>) -> bool {
    match target {
        RoleContext::Global => grant.team_id.is_none(),
        RoleContext::AnyTeam => !grant.is_personal_team,
        RoleContext::Team(team) => grant.team_id.as_deref().is_none_or(|id| id == *team),
    }
}

fn verify_restrictions(
    payload: &Value,
    peer: Option<IpAddr>,
    server_id: Option<&str>,
) -> Result<Vec<String>, AuthError> {
    let scopes = payload.get("scopes").filter(|scope| !scope.is_null());
    let Some(scopes) = scopes else {
        return Ok(Vec::new());
    };
    if let Some(required) = scopes.get("server_id").filter(|value| !value.is_null()) {
        let required = required
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or(AuthError::Invalid)?;
        if server_id != Some(required) {
            return Err(AuthError::Forbidden);
        }
    }
    if let Some(allowlist) = scopes
        .get("ip_restrictions")
        .filter(|value| !value.is_null())
    {
        let allowlist = allowlist.as_array().ok_or(AuthError::Invalid)?;
        let mut allowed = allowlist.is_empty();
        for value in allowlist {
            let ip_or_cidr = value.as_str().ok_or(AuthError::Invalid)?;
            if let Ok(ip) = ip_or_cidr.parse::<IpAddr>() {
                allowed |= peer == Some(ip);
            } else {
                let cidr = ip_or_cidr
                    .parse::<IpNet>()
                    .map_err(|_| AuthError::Invalid)?;
                allowed |= peer.is_some_and(|peer| cidr.contains(&peer));
            }
        }
        if !allowed {
            return Err(AuthError::Forbidden);
        }
    }
    if let Some(limits) = scopes.get("usage_limits").filter(|value| !value.is_null()) {
        let limits = limits.as_object().ok_or(AuthError::Invalid)?;
        if !limits.is_empty() {
            return Err(AuthError::Forbidden);
        }
    }

    match scopes.get("permissions").filter(|value| !value.is_null()) {
        None => Ok(Vec::new()),
        Some(permissions) => {
            serde_json::from_value(permissions.clone()).map_err(|_| AuthError::Invalid)
        }
    }
}

#[derive(Debug)]
enum AuthError {
    Required,
    Invalid,
    Forbidden,
    TeamRevoked,
    Storage(sqlx::Error),
}

impl From<sqlx::Error> for AuthError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Required => (
                StatusCode::UNAUTHORIZED,
                "Authentication required for MCP endpoints",
            ),
            Self::Invalid => (
                StatusCode::UNAUTHORIZED,
                "Invalid authentication credentials",
            ),
            Self::Forbidden => (StatusCode::FORBIDDEN, "Access denied"),
            Self::TeamRevoked => (
                StatusCode::FORBIDDEN,
                "Token invalid: User is no longer a member of the associated team",
            ),
            Self::Storage(error) => {
                tracing::error!(%error, "authorization database lookup failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authorization service unavailable",
                )
            }
        };
        let mut response = (status, Json(json!({"detail": message}))).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                "Bearer".parse().expect("valid header"),
            );
        }
        response
    }
}

fn bearer(headers: &HeaderMap) -> Result<Option<&str>, AuthError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AuthError::Invalid);
    }

    let mut words = value
        .to_str()
        .map_err(|_| AuthError::Invalid)?
        .split_ascii_whitespace();
    if !words
        .next()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("Bearer"))
    {
        return Err(AuthError::Invalid);
    }
    let token = words.next().ok_or(AuthError::Invalid)?;
    if words.next().is_some() {
        return Err(AuthError::Invalid);
    }
    Ok(Some(token))
}

async fn authorize_mcp(
    State(access): State<McpAccess>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    match bearer(request.headers())? {
        None if access.require_auth => Err(AuthError::Required),
        None => Ok(next.run(request).await),
        Some(token) => {
            let peer = request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|peer| peer.0.ip());
            let principal = access.auth.authenticate(token, peer, None).await?;
            if !access
                .auth
                .allows(&principal, "servers.use", RoleContext::AnyTeam, true)
                .await?
            {
                return Err(AuthError::Forbidden);
            }
            request.extensions_mut().insert(principal);
            Ok(next.run(request).await)
        }
    }
}

#[cfg(test)]
mod tests;
