// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use hmac::{Hmac, KeyInit, Mac};
use jiff::Timestamp;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock, ErrorCode, MetaObject};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    access::{self, Authorizer, Principal, RoleContext},
    auth::TeamVisibility,
    catalog::{
        CatalogList, CatalogServer, CatalogTool, GatewayRegistration, RegisteredTool,
        RegistrationError, ToolDefinition, slugify,
    },
    database::Database,
    mcp::{HttpOptions, ProtocolMode, SessionSettings},
    sessions::Session,
    upstream::{ToolContext, UpstreamClient, UpstreamError},
};

pub struct GatewayService {
    pub(crate) access: Arc<Authorizer>,
    database: Database,
    upstream: UpstreamClient,
    pagination: Pagination,
    refresh: CatalogRefresh,
}

pub struct CatalogRefresh {
    pub default_seconds: i32,
    pub minimum_seconds: i32,
}

impl Default for CatalogRefresh {
    fn default() -> Self {
        Self {
            default_seconds: 300,
            minimum_seconds: 60,
        }
    }
}

pub struct Pagination {
    page_size: u32,
    ttl: i64,
    key: [u8; 32],
}

impl Pagination {
    pub fn new(page_size: u32, ttl: i64, secret: Option<&str>) -> Self {
        let key = match secret {
            Some(secret) => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                    .expect("HMAC accepts secrets of any size");
                mac.update(b"context-forge-rs:mcp-list-cursor");
                mac.finalize().into_bytes().into()
            }
            None => {
                let mut nonce = [0; 32];
                nonce[..16].copy_from_slice(Uuid::new_v4().as_bytes());
                nonce[16..].copy_from_slice(Uuid::new_v4().as_bytes());
                nonce
            }
        };
        Self {
            page_size,
            ttl,
            key,
        }
    }
}

impl GatewayService {
    pub fn new(
        database: Database,
        access: Arc<Authorizer>,
        upstream: UpstreamClient,
        pagination: Pagination,
        refresh: CatalogRefresh,
    ) -> Self {
        Self {
            access,
            database,
            upstream,
            pagination,
            refresh,
        }
    }

    pub fn registration_router(self: &Arc<Self>) -> Router {
        let router = Router::new()
            .route("/gateways", post(register))
            .route("/gateways/", post(register))
            .route("/v1/gateways", post(register))
            .route("/v1/gateways/", post(register))
            .route("/v1/mcp-servers", post(register))
            .route("/v1/mcp-servers/", post(register))
            .with_state(self.clone());
        self.access.protect_api(router)
    }

    pub fn mcp_router(self: &Arc<Self>, require_auth: bool, mode: ProtocolMode) -> Router {
        self.mcp_router_with_options(require_auth, mode, HttpOptions::default())
    }

    pub fn mcp_router_with_sessions(
        self: &Arc<Self>,
        require_auth: bool,
        mode: ProtocolMode,
        sessions: Option<SessionSettings>,
    ) -> Router {
        self.mcp_router_with_options(
            require_auth,
            mode,
            HttpOptions {
                sessions,
                ..HttpOptions::default()
            },
        )
    }

    pub fn mcp_router_with_options(
        self: &Arc<Self>,
        require_auth: bool,
        mode: ProtocolMode,
        options: HttpOptions,
    ) -> Router {
        crate::mcp::router(self.clone(), mode, options, require_auth)
    }

    pub(crate) async fn catalog_ttl_ms(&self, server: Option<&CatalogServer>) -> u64 {
        let default = self.refresh.default_seconds;
        let seconds = if let Some(server) = server {
            match self
                .database
                .tool_refresh_interval(&server.id, default)
                .await
            {
                Ok(interval) => interval.unwrap_or(default),
                Err(error) => {
                    tracing::warn!(%error, "could not determine MCP catalog refresh interval");
                    return 0;
                }
            }
        } else {
            default
        };
        u64::try_from(seconds.max(self.refresh.minimum_seconds)).unwrap_or_default() * 1000
    }

    pub(crate) async fn list_tools(
        &self,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        cursor: Option<&str>,
    ) -> Result<ToolPage, ToolError> {
        if principal.is_some_and(|principal| !principal.token_allows("tools.read")) {
            return Err(ToolError::Denied);
        }

        let server_id = server.map(|server| server.id.as_str());
        let fingerprint = list_fingerprint("tools/list", principal, server_id);
        let continuation = cursor
            .map(|cursor| self.pagination.decode(cursor, &fingerprint))
            .transpose()?;
        let size = self.pagination.page_size;
        let mut rows = self
            .database
            .list_mcp_tools(
                access::catalog_scope(principal),
                server_id,
                continuation.as_ref().map(|cursor| cursor.after_id.as_str()),
                size + 1,
            )
            .await?;

        let has_more = rows.len() > size as usize;
        rows.truncate(size as usize);
        let next_cursor = if has_more {
            let last = rows.last().ok_or(ToolError::Unavailable)?;
            let expires = continuation.map(|c| c.exp).unwrap_or_else(|| {
                Timestamp::now()
                    .as_second()
                    .saturating_add(self.pagination.ttl)
            });
            Some(
                self.pagination
                    .encode(last.id.clone(), fingerprint, expires)?,
            )
        } else {
            None
        };
        Ok(ToolPage {
            tools: rows.into_iter().map(|row| row.definition).collect(),
            next_cursor,
        })
    }

    pub(crate) async fn list_catalog_metadata(
        &self,
        list: CatalogList,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        cursor: Option<&str>,
    ) -> Result<Value, ToolError> {
        if principal.is_some_and(|principal| !principal.token_allows(list.permission())) {
            return Err(ToolError::Denied);
        }
        let server = server.map(|server| server.id.as_str());
        let fingerprint = list_fingerprint(list.method(), principal, server);
        let continuation = cursor
            .map(|cursor| self.pagination.decode(cursor, &fingerprint))
            .transpose()?;
        let size = self.pagination.page_size;
        let mut rows = self
            .database
            .list_catalog_metadata(
                list,
                access::catalog_scope(principal),
                server,
                continuation.as_ref().map(|cursor| cursor.after_id.as_str()),
                size + 1,
            )
            .await?;
        let has_more = rows.len() > size as usize;
        rows.truncate(size as usize);
        let next_cursor = if has_more {
            let (id, _) = rows.last().ok_or(ToolError::Unavailable)?;
            let expires = continuation.map(|cursor| cursor.exp).unwrap_or_else(|| {
                Timestamp::now()
                    .as_second()
                    .saturating_add(self.pagination.ttl)
            });
            Some(self.pagination.encode(id.clone(), fingerprint, expires)?)
        } else {
            None
        };
        let items: Vec<_> = rows.into_iter().map(|(_, item)| item).collect();
        let mut result = json!({ (list.result_key()): items });
        if let Some(cursor) = next_cursor {
            result["nextCursor"] = cursor.into();
        }
        Ok(result)
    }

    pub(crate) async fn call_tool(
        &self,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        mut request: CallToolRequestParams,
        mut context: ToolContext<'_>,
        downstream: Option<&Session>,
    ) -> Result<Value, ToolError> {
        let tool = tokio::select! {
            biased;
            () = context.cancellation.cancelled() => return Err(ToolError::Cancelled),
            result = self.lookup_invokable_tool(principal, server, &request.name) => result?,
        }
        .ok_or(ToolError::NotFound)?;
        if tool.gateway_transport != "STREAMABLEHTTP"
            || tool.gateway_mode != "cache"
            || tool.request_type != "STREAMABLEHTTP"
            || tool.requires_gateway_policy
        {
            return Err(ToolError::Unavailable);
        }
        let association = downstream.and_then(|session| {
            let authorization = principal.map(Principal::authorization_fingerprint);
            context.notifications = session.passive_journal(authorization);
            session.upstream(&tool.gateway_id, &tool.gateway_url, authorization)
        });
        request.name = tool.original_name.into();
        let legacy_caller = context.client_capabilities.is_none();
        let result = self
            .upstream
            .call_tool_with_context(&tool.gateway_url, request, context, association.as_deref())
            .await;
        match result {
            Ok(result) if legacy_caller && result["resultType"] == "input_required" => {
                input_error_result("Elicitation not supported", None)
            }
            Ok(result) => Ok(result),
            Err(UpstreamError::Cancelled) => Err(ToolError::Cancelled),
            Err(UpstreamError::Rpc { code, message, .. })
                if code == i64::from(ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY.0) =>
            {
                input_error_result(&message, Some(code))
            }
            Err(error) => {
                tracing::warn!(%error, gateway = %tool.gateway_id, "upstream tool call failed");
                Err(ToolError::Unavailable)
            }
        }
    }

    pub(crate) async fn tool_definition(
        &self,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        name: &str,
    ) -> Result<Option<ToolDefinition>, ToolError> {
        Ok(self
            .lookup_invokable_tool(principal, server, name)
            .await?
            .map(|tool| tool.definition))
    }

    async fn lookup_invokable_tool(
        &self,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        name: &str,
    ) -> Result<Option<CatalogTool>, ToolError> {
        if let Some(principal) = principal
            && !self
                .access
                .allows(
                    principal,
                    "tools.execute",
                    access::role_context(server),
                    true,
                )
                .await?
        {
            return Err(ToolError::Denied);
        }

        Ok(self
            .database
            .find_mcp_tool(
                access::catalog_scope(principal),
                server.map(|server| server.id.as_str()),
                name,
            )
            .await?)
    }
}

fn input_error_result(message: &str, code: Option<i64>) -> Result<Value, ToolError> {
    let mut result = CallToolResult::error(vec![ContentBlock::text(format!(
        "MCP server error: {message}"
    ))]);
    result.result_type = None;
    if let Some(code) = code {
        let mut meta = MetaObject::new();
        meta.0
            .insert("io.contextforge/errorCode".to_owned(), json!({"code":code}));
        result.meta = Some(meta);
    }
    serde_json::to_value(result).map_err(|_| ToolError::Unavailable)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ToolError {
    #[error("Access denied")]
    Denied,
    #[error("Unknown tool")]
    NotFound,
    #[error("Tool service unavailable")]
    Unavailable,
    #[error("Request cancelled")]
    Cancelled,
    #[error("Invalid cursor")]
    Cursor,
    #[error("Catalog database failure")]
    Database(#[from] sqlx::Error),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToolPage {
    pub(crate) tools: Vec<ToolDefinition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PageCursor {
    after_id: String,
    fingerprint: [u8; 32],
    exp: i64,
}

impl Pagination {
    fn decode(&self, cursor: &str, fingerprint: &[u8; 32]) -> Result<PageCursor, ToolError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 0;
        let page = decode::<PageCursor>(
            cursor,
            &DecodingKey::from_secret(&self.key).map_err(|_| ToolError::Unavailable)?,
            &validation,
        )
        .map_err(|_| ToolError::Cursor)?
        .claims;
        if &page.fingerprint != fingerprint || page.after_id.is_empty() {
            return Err(ToolError::Cursor);
        }
        Ok(page)
    }

    fn encode(
        &self,
        after_id: String,
        fingerprint: [u8; 32],
        exp: i64,
    ) -> Result<String, ToolError> {
        let key = EncodingKey::from_secret(&self.key).map_err(|_| ToolError::Unavailable)?;
        encode(
            &Header::new(Algorithm::HS256),
            &PageCursor {
                after_id,
                fingerprint,
                exp,
            },
            &key,
        )
        .map_err(|_| ToolError::Unavailable)
    }
}

fn list_fingerprint(method: &str, principal: Option<&Principal>, server: Option<&str>) -> [u8; 32] {
    let (identity, scope) = match principal {
        None => (None, json!("public")),
        Some(principal) => (
            Some(principal.email.as_str()),
            match &principal.visibility {
                TeamVisibility::Admin => json!("admin"),
                TeamVisibility::Public => json!("public"),
                TeamVisibility::Teams(teams) => {
                    let mut teams: Vec<_> = teams.iter().collect();
                    teams.sort_unstable();
                    json!(teams)
                }
            },
        ),
    };
    let value = json!([method, identity, scope, server]).to_string();
    Sha256::digest(value.as_bytes()).into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterGateway {
    name: String,
    url: String,
    description: Option<String>,
    transport: Option<String>,
    visibility: Option<String>,
    #[serde(alias = "teamId")]
    team_id: Option<String>,
    tags: Option<Vec<String>>,
    #[serde(alias = "gatewayMode")]
    gateway_mode: Option<String>,
    #[serde(alias = "authType")]
    auth_type: Option<String>,
}

async fn register(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<RegisterGateway>,
) -> Result<Json<Value>, RegistrationResponse> {
    let name = input.name.trim();
    let slug = slugify(name);
    if name.len() > 255 || slug.is_empty() {
        return Err(RegistrationResponse::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid gateway name",
        ));
    }
    if input
        .transport
        .as_deref()
        .is_none_or(|transport| !transport.eq_ignore_ascii_case("STREAMABLEHTTP"))
        || input
            .gateway_mode
            .as_deref()
            .is_some_and(|mode| mode != "cache")
        || input
            .auth_type
            .as_deref()
            .is_some_and(|auth| auth != "none")
    {
        return Err(RegistrationResponse::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unsupported gateway transport, mode, or authentication",
        ));
    }

    let visibility = input.visibility.as_deref().unwrap_or("public");
    if !matches!(visibility, "public" | "team" | "private") {
        return Err(RegistrationResponse::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid gateway visibility",
        ));
    }
    let team =
        registration_team(&service, &principal, visibility, input.team_id.as_deref()).await?;
    let context = team
        .as_deref()
        .map_or(RoleContext::AnyTeam, RoleContext::Team);
    let allowed = service
        .access
        .allows(&principal, "gateways.create", context, true)
        .await?;
    if !allowed {
        return Err(RegistrationResponse::new(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }

    let url = input.url.trim();
    let (discovery, metadata) = service
        .upstream
        .discover_catalog(url)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "upstream gateway discovery failed");
            match error {
                UpstreamError::InvalidUrl | UpstreamError::BlockedDestination => {
                    RegistrationResponse::new(
                        StatusCode::BAD_REQUEST,
                        "Gateway URL is invalid or disallowed",
                    )
                }
                _ => {
                    RegistrationResponse::new(StatusCode::BAD_GATEWAY, "Failed to discover gateway")
                }
            }
        })?;
    let tools: Vec<ToolDefinition> = discovery
        .tools
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .map_err(|_| {
            RegistrationResponse::new(StatusCode::BAD_GATEWAY, "Upstream returned an invalid tool")
        })?;
    let id = Uuid::new_v4().simple().to_string();
    let tags = input.tags.unwrap_or_default();
    let description = input.description.as_deref().map(str::trim);
    let registration = GatewayRegistration {
        id: &id,
        name,
        slug: &slug,
        url,
        description,
        capabilities: &discovery.capabilities,
        visibility,
        team_id: team.as_deref(),
        owner_email: &principal.email,
        tags: &tags,
    };
    let tool_slugs: Vec<_> = tools.iter().map(|tool| slugify(&tool.name)).collect();
    let tool_names: Vec<_> = tool_slugs
        .iter()
        .map(|tool| format!("{slug}-{tool}"))
        .collect();
    let tool_ids: Vec<_> = tools
        .iter()
        .map(|_| Uuid::new_v4().simple().to_string())
        .collect();
    let registered_tools: Vec<_> = (0..tools.len())
        .map(|index| RegisteredTool {
            id: &tool_ids[index],
            slug: &tool_slugs[index],
            name: &tool_names[index],
            definition: &tools[index],
        })
        .collect();
    service
        .database
        .register_discovered_gateway(&registration, &registered_tools, &metadata)
        .await?;
    let address = peer.map(|Extension(ConnectInfo(address))| address.ip().to_string());
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    Ok(Json(registration_response(&registration, address, agent)))
}

async fn registration_team(
    service: &GatewayService,
    principal: &Principal,
    visibility: &str,
    requested: Option<&str>,
) -> Result<Option<String>, RegistrationResponse> {
    match &principal.visibility {
        TeamVisibility::Public if visibility == "public" => Ok(None),
        TeamVisibility::Public => Err(RegistrationResponse::new(
            StatusCode::FORBIDDEN,
            "Public-only tokens cannot create team or private resources. Use visibility='public' or obtain a team-scoped token.",
        )),
        scope => {
            let team = match scope {
                TeamVisibility::Teams(teams) => {
                    if requested.is_some_and(|id| !teams.iter().any(|team| team == id)) {
                        return Err(RegistrationResponse::new(
                            StatusCode::FORBIDDEN,
                            "Access issue: This API token does not have the required permissions for this team.",
                        ));
                    }
                    requested.or_else(|| (teams.len() == 1).then(|| teams[0].as_str()))
                }
                _ => requested,
            };
            if let Some(team) = team
                && !service.database.active_team(team).await?
            {
                return Err(RegistrationResponse::new(
                    StatusCode::FORBIDDEN,
                    "Access denied",
                ));
            }
            if visibility == "team" && team.is_none() {
                return Err(RegistrationResponse::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Team visibility requires a team",
                ));
            }
            Ok(team.map(str::to_owned))
        }
    }
}

fn registration_response(
    gateway: &GatewayRegistration<'_>,
    address: Option<String>,
    agent: Option<&str>,
) -> Value {
    let now = Timestamp::now().to_string();
    let mut response = json!({
        "id": gateway.id, "name": gateway.name, "slug": gateway.slug, "url": gateway.url,
        "description": gateway.description, "transport": "STREAMABLEHTTP",
        "capabilities": gateway.capabilities, "createdAt": now, "updatedAt": now, "lastSeen": now,
        "status": "active", "registrationAttempts": 0, "enabled": true, "reachable": true,
        "ownerEmail": gateway.owner_email, "teamId": gateway.team_id, "visibility": gateway.visibility,
        "createdBy": gateway.owner_email, "createdFromIp": address, "createdVia": "api", "createdUserAgent": agent,
        "version": 1, "gatewayMode": "cache", "signingAlgorithm": "ed25519", "tags": gateway.tags,
        "toolCount": 0, "promptCount": 0, "resourceCount": 0, "skippedTools": [],
    });
    for name in [
        "statusMessage",
        "nextRetryAt",
        "lastError",
        "lifecycleClaimedBy",
        "lifecycleClaimedAt",
        "lifecycleClaimExpiresAt",
        "toolValidationPolicy",
        "passthroughHeaders",
        "caCertificate",
        "caCertificateSig",
        "clientCert",
        "clientKey",
        "authType",
        "authValue",
        "authHeaders",
        "authHeadersUnmasked",
        "oauthConfig",
        "registrationMethod",
        "sigv4Config",
        "authQueryParamKey",
        "authQueryParamValueMasked",
        "authUsername",
        "authPassword",
        "authToken",
        "authHeaderKey",
        "authHeaderValue",
        "authPasswordUnmasked",
        "authTokenUnmasked",
        "authHeaderValueUnmasked",
        "team",
        "modifiedBy",
        "modifiedFromIp",
        "modifiedVia",
        "modifiedUserAgent",
        "importBatchId",
        "federationSource",
        "refreshIntervalSeconds",
        "lastRefreshAt",
        "identityPropagation",
    ] {
        response[name] = Value::Null;
    }
    response
}

struct RegistrationResponse {
    status: StatusCode,
    message: &'static str,
}

impl RegistrationResponse {
    fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl IntoResponse for RegistrationResponse {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"message": self.message}))).into_response()
    }
}

impl From<RegistrationError> for RegistrationResponse {
    fn from(error: RegistrationError) -> Self {
        match error {
            RegistrationError::NameConflict => {
                Self::new(StatusCode::CONFLICT, "Gateway name already exists")
            }
            RegistrationError::UrlConflict => {
                Self::new(StatusCode::CONFLICT, "Gateway already exists")
            }
            RegistrationError::ToolNameConflict => Self::new(
                StatusCode::CONFLICT,
                "Gateway tool name conflicts with an existing tool",
            ),
            RegistrationError::Invalid(message) => {
                Self::new(StatusCode::UNPROCESSABLE_ENTITY, message)
            }
            RegistrationError::Database(error) => error.into(),
        }
    }
}

impl From<sqlx::Error> for RegistrationResponse {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "gateway registry database operation failed");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Gateway registry unavailable",
        )
    }
}

#[cfg(test)]
pub(crate) fn test_service(database: Database, authorizer: Authorizer) -> Arc<GatewayService> {
    Arc::new(GatewayService::new(
        database,
        Arc::new(authorizer),
        UpstreamClient::new(Default::default(), std::time::Duration::from_secs(1)),
        Pagination::new(100, 900, None),
        CatalogRefresh::default(),
    ))
}
