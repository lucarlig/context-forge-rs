// SPDX-License-Identifier: Apache-2.0

mod server_oauth;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    auth::{self, TeamVisibility},
    catalog::{CatalogScope, CatalogServer},
    database::Database,
    identity::{Grant, Identity},
    jwt::{JwtError, JwtVerifier, TokenUse, VerifiedJwt, validate_time_restrictions},
    local_auth::ExternalIdentitySettings,
    tokens::{ApiTokenRecord, TokenIdentity, TokenRequest, TokenReservation, TokenUsageRecord},
};
pub(crate) use server_oauth::ServerOAuthVerifier;

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
    log_token_usage: bool,
    external: Option<ExternalIdentitySettings>,
    internal_jwt_issuer: String,
}

#[derive(Clone, Debug)]
pub struct Principal {
    pub email: String,
    pub visibility: TeamVisibility,
    pub(crate) full_name: Option<String>,
    pub(crate) expires_at: Option<i64>,
    pub(crate) token_use: TokenUse,
    catalog_token: Option<TokenIdentity>,
    catalog_scopes: Option<Vec<String>>,
    pub(crate) server_limit: Option<String>,
    is_admin: bool,
    scopes: Vec<String>,
    credential_hash: [u8; 32],
}

pub enum RoleContext<'a> {
    Global,
    Team(&'a str),
    AnyTeam,
}

#[derive(Clone, Copy)]
enum ApiTarget {
    Management,
    PublicRpc,
}

#[derive(Clone, Copy)]
pub(crate) struct OAuthBrowserSession;

enum ServerTarget<'a> {
    Endpoint(Option<&'a str>),
    RpcParameters,
}

#[derive(Clone)]
struct McpAccess {
    auth: Arc<Authorizer>,
    require_auth: bool,
    legacy_transport: bool,
    oauth_base: Option<Arc<str>>,
    server_oauth: Option<ServerOAuthVerifier>,
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
            log_token_usage: true,
            external: None,
            internal_jwt_issuer: "mcpgateway".to_owned(),
        }
    }

    pub fn with_token_usage_logging(mut self, enabled: bool) -> Self {
        self.log_token_usage = enabled;
        self
    }

    pub fn with_external_identity(mut self, settings: Option<ExternalIdentitySettings>) -> Self {
        self.external = settings;
        self
    }

    pub fn with_internal_jwt_issuer(mut self, issuer: String) -> Self {
        self.internal_jwt_issuer = issuer;
        self
    }

    pub(crate) async fn reserve_usage(
        &self,
        principal: Option<&Principal>,
        request: TokenRequest<'_>,
    ) -> Result<Option<TokenUsageRecord>, AuthError> {
        let Some(token) = principal.and_then(|principal| principal.catalog_token.as_ref()) else {
            return Ok(None);
        };
        match self
            .database
            .reserve_token_request(token, request, self.log_token_usage)
            .await?
        {
            TokenReservation::Allowed(record) => Ok(record),
            TokenReservation::Limited(reason) => Err(AuthError::UsageLimit(reason)),
            TokenReservation::Inactive => Err(AuthError::Inactive),
        }
    }

    pub(crate) async fn finish_usage(
        &self,
        record: Option<TokenUsageRecord>,
        status: StatusCode,
        started: std::time::Instant,
    ) {
        if let Some(record) = record
            && let Err(error) = self
                .database
                .finish_token_request(
                    record,
                    status.as_u16(),
                    started.elapsed().as_millis().min(i32::MAX as u128) as i32,
                )
                .await
        {
            tracing::warn!(%error,"could not finish API token usage record");
        }
    }

    pub fn protect_mcp(self: &Arc<Self>, router: Router, require_auth: bool) -> Router {
        self.protect_mcp_with_oauth(router, require_auth, "http://localhost:4444", None)
    }

    pub(crate) fn protect_mcp_with_oauth(
        self: &Arc<Self>,
        router: Router,
        require_auth: bool,
        oauth_base: &str,
        server_oauth: Option<ServerOAuthVerifier>,
    ) -> Router {
        router.route_layer(middleware::from_fn_with_state(
            McpAccess {
                auth: self.clone(),
                require_auth,
                legacy_transport: false,
                oauth_base: Some(oauth_base.into()),
                server_oauth,
            },
            authorize_mcp,
        ))
    }

    pub(crate) fn protect_legacy_transport(
        self: &Arc<Self>,
        router: Router,
        require_auth: bool,
    ) -> Router {
        router.route_layer(middleware::from_fn_with_state(
            McpAccess {
                auth: self.clone(),
                require_auth,
                legacy_transport: true,
                oauth_base: None,
                server_oauth: None,
            },
            authorize_mcp,
        ))
    }

    pub fn protect_api(self: &Arc<Self>, router: Router) -> Router {
        self.protect_api_with_message(router, "Authorization token required")
    }

    pub(crate) fn protect_api_with_message(
        self: &Arc<Self>,
        router: Router,
        missing: &'static str,
    ) -> Router {
        router.route_layer(middleware::from_fn_with_state(
            (self.clone(), missing, ApiTarget::Management),
            authorize_api,
        ))
    }

    pub(crate) fn protect_rpc(self: &Arc<Self>, router: Router) -> Router {
        router.route_layer(middleware::from_fn_with_state(
            (
                self.clone(),
                "Authorization token required",
                ApiTarget::PublicRpc,
            ),
            authorize_api,
        ))
    }

    pub(crate) fn protect_oauth_browser(self: &Arc<Self>, router: Router, login: String) -> Router {
        router.route_layer(middleware::from_fn_with_state(
            (self.clone(), login),
            authorize_oauth_browser,
        ))
    }

    pub(crate) async fn websocket_principal(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
        require_auth: bool,
    ) -> Result<Option<Principal>, AuthError> {
        let credential = bearer(headers)?;
        let Some(credential) = credential else {
            return if require_auth {
                Err(AuthError::ApiRequired("Authorization token required"))
            } else {
                Ok(None)
            };
        };
        let principal = self.authenticate(credential, peer, None).await?;
        for permission in [
            "tools.read",
            "tools.execute",
            "resources.read",
            "prompts.read",
            "servers.use",
            "a2a.read",
        ] {
            if self
                .allows(&principal, permission, RoleContext::AnyTeam, true)
                .await?
            {
                return Ok(Some(principal));
            }
        }
        Err(AuthError::Forbidden)
    }

    pub(crate) async fn authenticate(
        &self,
        token: &str,
        peer: Option<IpAddr>,
        server_id: Option<&str>,
    ) -> Result<Principal, AuthError> {
        self.authenticate_for(token, peer, ServerTarget::Endpoint(server_id))
            .await
    }

    pub(crate) async fn rate_limit_identity(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
    ) -> Option<(String, Option<String>)> {
        let token = bearer(headers)
            .ok()
            .flatten()
            .or_else(|| auth_cookie(headers))?;
        let principal = self
            .authenticate_for(token, peer, ServerTarget::RpcParameters)
            .await
            .ok()?;
        let team = match (principal.token_use, principal.visibility) {
            (TokenUse::Api, TeamVisibility::Teams(mut teams)) if teams.len() == 1 => {
                let team = teams.pop().expect("one team");
                self.database
                    .is_personal_team(&team)
                    .await
                    .ok()
                    .filter(|personal| !personal)
                    .map(|_| team)
            }
            _ => None,
        };
        Some((principal.email, team))
    }

    pub(crate) async fn csrf_identity(&self, token: &str) -> Option<(String, String)> {
        let jwt = self.verify_gateway_token(token).ok()?;
        let session = jwt.jti().filter(|jti| !jti.is_empty())?.to_owned();
        let email = match self.resolve_identity(&jwt).await {
            Ok(identity) => identity.email,
            Err(_) => claimed_email(&jwt)?.to_owned(),
        };
        Some((email, session))
    }

    pub(crate) fn verify_gateway_token(&self, token: &str) -> Result<VerifiedJwt, JwtError> {
        self.verifier
            .as_ref()
            .ok_or(JwtError::Invalid)?
            .verify(token)
    }

    pub(crate) async fn allows_admin_ui(
        &self,
        principal: &Principal,
        target: RoleContext<'_>,
    ) -> Result<bool, sqlx::Error> {
        if principal.visibility == TeamVisibility::Public {
            return Ok(false);
        }
        if principal.is_admin {
            return Ok(true);
        }
        let grants = self.database.grants(&principal.email).await?;
        Ok(grants.iter().any(|grant| {
            grant_applies(grant, &principal.visibility, &target)
                && grant
                    .permissions
                    .iter()
                    .any(|permission| permission == "*" || permission.starts_with("admin."))
        }))
    }

    async fn authenticate_for(
        &self,
        token: &str,
        peer: Option<IpAddr>,
        target: ServerTarget<'_>,
    ) -> Result<Principal, AuthError> {
        let jwt = match self
            .verifier
            .as_ref()
            .map(|verifier| verifier.verify(token))
        {
            Some(Ok(jwt)) => jwt,
            Some(Err(JwtError::TimeRestricted | JwtError::InvalidTimeRestrictions)) => {
                return Err(AuthError::Forbidden);
            }
            _ => return self.authenticate_external(token).await,
        };
        let tracked = if jwt.token_use() == TokenUse::Api
            && let Some(jti) = jwt.jti()
        {
            self.database.token_from_jti(jti).await?
        } else {
            None
        };
        if let Some(token_row) = tracked.as_ref() {
            if token_row.token_hash != crate::tokens::hash_token(token) {
                return Err(AuthError::Invalid);
            }
            if token_row.is_revoked {
                return Err(AuthError::Revoked);
            }
            if !token_row.is_active {
                return Err(AuthError::Inactive);
            }
        }
        let claim_server = jwt.payload()["scopes"]
            .get("server_id")
            .filter(|id| !id.is_null())
            .map(|id| {
                id.as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or(AuthError::Invalid)
            })
            .transpose()?;
        let recorded_server = tracked.as_ref().and_then(|row| row.server_id.as_deref());
        if recorded_server == Some("") {
            return Err(AuthError::Invalid);
        }
        if claim_server.is_some() && recorded_server.is_some() && claim_server != recorded_server {
            return Err(AuthError::Forbidden);
        }
        let server_limit = claim_server.or(recorded_server);
        if let ServerTarget::Endpoint(server_id) = target
            && server_limit.is_some()
            && server_limit != server_id
        {
            return Err(AuthError::Forbidden);
        }
        let server_limit = server_limit.map(str::to_owned);
        let scopes = verify_restrictions(jwt.payload(), peer, tracked.is_some())?;
        let identity = self.resolve_identity(&jwt).await?;
        let (catalog_scopes, catalog_token) = if let Some(row) = tracked {
            if row.user_email != identity.email {
                return Err(AuthError::Invalid);
            }
            let scopes = managed_token_scopes(&row, peer)?;
            (
                Some(scopes),
                Some(TokenIdentity {
                    id: row.id,
                    jti: row.jti,
                    user_email: row.user_email,
                }),
            )
        } else {
            (None, None)
        };
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
            full_name: identity.full_name,
            expires_at: jwt.payload().get("exp").and_then(Value::as_i64),
            token_use: jwt.token_use(),
            catalog_token,
            catalog_scopes,
            server_limit,
            is_admin: identity.is_admin,
            scopes,
            credential_hash: Sha256::digest(token.as_bytes()).into(),
        })
    }

    async fn authenticate_external(&self, token: &str) -> Result<Principal, AuthError> {
        let settings = self.external.as_ref().ok_or(AuthError::Invalid)?;
        let (email, expires) = settings
            .authenticate(&self.database, token)
            .await?
            .ok_or(AuthError::Invalid)?;
        let identity = self
            .database
            .active_identity(Some(&email), None, None)
            .await?
            .ok_or(AuthError::Invalid)?;
        let visibility = identity.session_visibility(&self.database).await?;
        Ok(Principal {
            email: identity.email,
            visibility,
            full_name: identity.full_name,
            expires_at: Some(expires),
            token_use: TokenUse::Session,
            catalog_token: None,
            catalog_scopes: None,
            server_limit: None,
            is_admin: identity.is_admin,
            scopes: Vec::new(),
            credential_hash: Sha256::digest(token.as_bytes()).into(),
        })
    }

    async fn resolve_identity(&self, jwt: &VerifiedJwt) -> Result<Identity, AuthError> {
        let identity = self
            .database
            .active_identity(claimed_email(jwt), jwt.subject(), jwt.jti())
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
        if !principal.token_allows(permission) {
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

    pub(crate) async fn allows_global_only(
        &self,
        principal: &Principal,
        permission: &str,
    ) -> Result<bool, sqlx::Error> {
        if !principal.token_allows(permission) {
            return Ok(false);
        }
        if principal.is_admin && principal.visibility != TeamVisibility::Public {
            return Ok(true);
        }
        Ok(self
            .database
            .grants(&principal.email)
            .await?
            .iter()
            .any(|grant| {
                grant.scope == "global"
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
    allow_limits: bool,
) -> Result<Vec<String>, AuthError> {
    let scopes = payload.get("scopes").filter(|scope| !scope.is_null());
    let Some(scopes) = scopes else {
        return Ok(Vec::new());
    };
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
        if !limits.is_empty() && !allow_limits {
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

fn managed_token_scopes(
    row: &ApiTokenRecord,
    peer: Option<IpAddr>,
) -> Result<Vec<String>, AuthError> {
    let decode = |value: Option<&str>| -> Result<Value, AuthError> {
        value
            .map(|value| serde_json::from_str(value).map_err(|_| AuthError::Invalid))
            .transpose()
            .map(|value| value.unwrap_or_default())
    };
    let time = decode(row.time_restrictions.as_deref())?;
    if !time.is_null() {
        validate_time_restrictions(&time, jiff::Timestamp::now())
            .map_err(|_| AuthError::Forbidden)?;
    }
    let stored = decode(row.resource_scopes.as_deref())?;
    let mut stored: Vec<String> = if stored.is_null() {
        Vec::new()
    } else {
        serde_json::from_value(stored).map_err(|_| AuthError::Invalid)?
    };
    if !stored
        .iter()
        .any(|name| matches!(name.as_str(), "*" | "servers.use"))
        && stored.iter().any(|name| {
            ["tools.", "resources.", "prompts.", "logging."]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
    {
        stored.push("servers.use".to_owned());
    }
    let persisted = json!({"scopes":{"permissions":stored,
        "ip_restrictions":decode(row.ip_restrictions.as_deref())?}});
    verify_restrictions(&persisted, peer, false)
}

#[derive(Debug)]
pub(crate) enum AuthError {
    Required,
    ApiRequired(&'static str),
    Invalid,
    Revoked,
    Inactive,
    UsageLimit(&'static str),
    Forbidden,
    ServerMissing(Option<String>),
    TeamRevoked,
    ServerOAuth {
        status: StatusCode,
        detail: &'static str,
        challenge: Option<HeaderValue>,
    },
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
            Self::ApiRequired(message) => (StatusCode::UNAUTHORIZED, message),
            Self::Invalid => (
                StatusCode::UNAUTHORIZED,
                "Invalid authentication credentials",
            ),
            Self::Revoked => (StatusCode::UNAUTHORIZED, "Token has been revoked"),
            Self::Inactive => (StatusCode::UNAUTHORIZED, "Token is inactive or expired"),
            Self::UsageLimit(reason) => (StatusCode::TOO_MANY_REQUESTS, reason),
            Self::Forbidden => (StatusCode::FORBIDDEN, "Access denied"),
            Self::ServerMissing(None) => (StatusCode::NOT_FOUND, "Server not found"),
            Self::ServerMissing(Some(id)) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"detail": format!("Server not found: {id}")})),
                )
                    .into_response();
            }
            Self::TeamRevoked => (
                StatusCode::FORBIDDEN,
                "Token invalid: User is no longer a member of the associated team",
            ),
            Self::ServerOAuth {
                status,
                detail,
                challenge,
            } => {
                let mut response = (status, Json(json!({"detail":detail}))).into_response();
                if let Some(challenge) = challenge {
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, challenge);
                }
                return response;
            }
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

impl Principal {
    pub(crate) fn verified_bearer<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        let token = bearer(headers).ok()??;
        let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        (actual == self.credential_hash).then_some(token)
    }

    pub(crate) fn credential_hash(&self) -> [u8; 32] {
        self.credential_hash
    }

    pub(crate) fn is_admin(&self) -> bool {
        self.is_admin
    }

    pub(crate) fn is_global_admin(&self) -> bool {
        self.is_admin && self.visibility == TeamVisibility::Admin
    }

    pub(crate) fn token_allows(&self, permission: &str) -> bool {
        auth::token_scope_grants(Some(&self.scopes), permission)
            && auth::token_scope_grants(self.catalog_scopes.as_deref(), permission)
    }

    pub(crate) fn authorization_fingerprint(&self) -> [u8; 32] {
        let scope = match &self.visibility {
            TeamVisibility::Public => json!("public"),
            TeamVisibility::Admin => json!("admin"),
            TeamVisibility::Teams(teams) => {
                let mut sorted: Vec<_> = teams.iter().collect();
                sorted.sort_unstable();
                sorted.dedup();
                json!(sorted)
            }
        };
        let mut scopes: Vec<_> = self.scopes.iter().collect();
        scopes.sort_unstable();
        scopes.dedup();
        let mut data = json!([self.email, self.is_admin, scope, scopes]);
        if let Some(catalog_scopes) = self.catalog_scopes.as_ref() {
            let mut catalog_scopes = catalog_scopes.iter().collect::<Vec<_>>();
            catalog_scopes.sort_unstable();
            catalog_scopes.dedup();
            data.as_array_mut()
                .expect("authorization fingerprint")
                .push(json!(catalog_scopes));
        }
        let data = data.to_string();
        Sha256::digest(data.as_bytes()).into()
    }
}

fn claimed_email(jwt: &VerifiedJwt) -> Option<&str> {
    let payload = jwt.payload();
    [
        payload.get("user").and_then(|user| user.get("email")),
        payload.get("email"),
        payload.get("sub"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .map(str::trim)
    .find(|identity| identity.contains('@'))
}

pub(crate) fn auth_cookie(headers: &HeaderMap) -> Option<&str> {
    cookie(headers, "jwt_token").or_else(|| cookie(headers, "access_token"))
}

pub(crate) fn browser_request(headers: &HeaderMap) -> bool {
    let text = |name| headers.get(name).and_then(|value| value.to_str().ok());
    text(header::ACCEPT).is_some_and(|value| value.contains("text/html"))
        || headers
            .get("hx-request")
            .is_some_and(|value| value == "true")
        || text(header::REFERER)
            .and_then(|value| url::Url::parse(value).ok())
            .is_some_and(|referer| {
                let host = &referer[url::Position::BeforeHost..url::Position::AfterPort];
                text(header::HOST).is_some_and(|value| value == host)
                    && (referer.path().contains("/admin")
                        || referer.path().contains("/oauth/callback"))
            })
}

pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|cookie| cookie.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|value| value.trim().split_once('='))
        .find_map(|(key, value)| {
            let value = value.trim();
            (key == name && !value.is_empty()).then_some(value)
        })
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
    path: Option<Path<ServerPath>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let server_id = path.as_ref().and_then(|path| path.server_id.as_deref());
    let credential = bearer(request.headers())?;
    let anonymous_server = if credential.is_none()
        && let Some(base) = access.oauth_base.as_deref()
        && let Some(id) = server_id
    {
        let server = access.auth.database.catalog_server(id).await?;
        if server.as_ref().is_some_and(|server| server.oauth_enabled) {
            let url =
                crate::gateway::resource_metadata_url(base, request.headers(), request.uri(), id);
            let challenge =
                axum::http::HeaderValue::from_str(&format!("Bearer resource_metadata=\"{url}\""))
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("Bearer"));
            return Ok((
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, challenge)],
                Json(json!({"detail":"This server requires OAuth authentication"})),
            )
                .into_response());
        }
        Some(server)
    } else {
        None
    };
    let principal = match credential {
        None if access.require_auth => {
            return Err(if access.legacy_transport {
                AuthError::ApiRequired("Authorization token required")
            } else {
                AuthError::Required
            });
        }
        None if access.legacy_transport => return Err(AuthError::Forbidden),
        None => None,
        Some(token) => {
            let server_principal = if let Some(verifier) = &access.server_oauth
                && let Some(server) = server_id
                && let Some(base) = access.oauth_base.as_deref()
            {
                verifier
                    .authenticate(
                        &access.auth,
                        base,
                        server,
                        request.headers(),
                        request.uri(),
                        token,
                    )
                    .await?
            } else {
                None
            };
            Some(match server_principal {
                Some(principal) => principal,
                None => {
                    access
                        .auth
                        .authenticate(token, peer(&request), server_id)
                        .await?
                }
            })
        }
    };
    let scope = catalog_scope(principal.as_ref());
    let server = match server_id {
        Some(id) => {
            let server = match anonymous_server {
                Some(server) => server,
                None => access.auth.database.catalog_server(id).await?,
            }
            .ok_or_else(|| {
                AuthError::ServerMissing(access.legacy_transport.then(|| id.to_owned()))
            })?;
            if server.oauth_enabled && principal.is_none() {
                return Err(AuthError::Required);
            }
            if !server.enabled || !server.is_visible(scope) {
                return Err(AuthError::Forbidden);
            }
            Some(server)
        }
        None => None,
    };
    if let Some(principal) = principal {
        if !access
            .auth
            .allows(
                &principal,
                "servers.use",
                role_context(server.as_ref()),
                true,
            )
            .await?
        {
            return Err(AuthError::Forbidden);
        }
        request.extensions_mut().insert(principal);
    }
    if let Some(server) = server {
        request.extensions_mut().insert(server);
    }
    dispatch_with_usage(&access.auth, request, next).await
}

#[derive(Deserialize)]
struct ServerPath {
    server_id: Option<String>,
}

async fn authorize_api(
    State((access, missing, target)): State<(Arc<Authorizer>, &'static str, ApiTarget)>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    if matches!(target, ApiTarget::PublicRpc)
        && request
            .headers()
            .get_all(header::AUTHORIZATION)
            .iter()
            .count()
            == 1
        && request
            .headers()
            .get(header::AUTHORIZATION)
            .is_some_and(|value| value.is_empty())
    {
        return Err(AuthError::ApiRequired(missing));
    }
    let token = bearer(request.headers())?.ok_or(AuthError::ApiRequired(missing))?;
    let target = match target {
        ApiTarget::Management => ServerTarget::Endpoint(None),
        ApiTarget::PublicRpc => ServerTarget::RpcParameters,
    };
    let principal = access
        .authenticate_for(token, peer(&request), target)
        .await?;
    request.extensions_mut().insert(principal);
    dispatch_with_usage(&access, request, next).await
}

async fn authorize_oauth_browser(
    State((access, login)): State<(Arc<Authorizer>, String)>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let browser = browser_request(request.headers());
    let token = bearer(request.headers())?;
    let session = token.is_none() && browser;
    let credential = token.or_else(|| session.then(|| auth_cookie(request.headers())).flatten());
    let Some(credential) = credential else {
        if session && request.uri().path().starts_with("/oauth/authorize/") {
            return Ok((StatusCode::FOUND, [(header::LOCATION, login)]).into_response());
        }
        return Err(AuthError::ApiRequired("Authorization token required"));
    };
    let principal = access
        .authenticate(credential, peer(&request), None)
        .await?;
    if session {
        if principal.token_use != TokenUse::Session {
            return Err(AuthError::ApiRequired("Browser session required"));
        }
        request.extensions_mut().insert(OAuthBrowserSession);
    }
    request.extensions_mut().insert(principal);
    dispatch_with_usage(&access, request, next).await
}

async fn dispatch_with_usage(
    auth: &Authorizer,
    request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let started = std::time::Instant::now();
    let address = peer(&request).map(|address| address.to_string());
    let reservation = auth
        .reserve_usage(
            request.extensions().get::<Principal>(),
            TokenRequest {
                endpoint: request.uri().path(),
                method: request.method().as_str(),
                peer: address.as_deref(),
                agent: request
                    .headers()
                    .get(header::USER_AGENT)
                    .and_then(|value| value.to_str().ok()),
            },
        )
        .await?;
    let response = next.run(request).await;
    auth.finish_usage(reservation, response.status(), started)
        .await;
    Ok(response)
}

fn peer(request: &Request) -> Option<IpAddr> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.0.ip())
}

pub(crate) fn catalog_scope(principal: Option<&Principal>) -> CatalogScope<'_> {
    match principal {
        Some(user) => CatalogScope {
            email: Some(&user.email),
            visibility: &user.visibility,
        },
        None => CatalogScope {
            email: None,
            visibility: &TeamVisibility::Public,
        },
    }
}

pub(crate) fn role_context(server: Option<&CatalogServer>) -> RoleContext<'_> {
    match server.and_then(|server| server.team_id.as_deref()) {
        Some(team) => RoleContext::Team(team),
        None => RoleContext::AnyTeam,
    }
}

#[cfg(test)]
mod tests;
