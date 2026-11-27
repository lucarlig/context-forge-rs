// SPDX-License-Identifier: Apache-2.0

mod content;
mod management;
mod proxy;

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderName, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use hmac::{Hmac, KeyInit, Mac};
use jiff::Timestamp;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ErrorCode, ErrorData, MetaObject,
    SubscriptionFilter,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing_subscriber::{Registry, filter::LevelFilter, reload};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    access::{self, Authorizer, Principal, RoleContext},
    auth::TeamVisibility,
    catalog::{
        CatalogList, CatalogServer, CatalogTool, ContentGateway, GatewayMode, GatewayRegistration,
        RegisteredTls, RegisteredTool, RegistrationError, RegistrationOptions, ToolDefinition,
        slugify,
    },
    config::{HeaderForwarding, IdentityForwarding, ProxyCatalogSettings, SecretKdf},
    credentials::{
        AuthError, AuthInput, CredentialCipher, CredentialError, UpstreamCredentials,
        decode_headers, decode_query, validate_query_host,
    },
    database::Database,
    forward_identity::IdentityError,
    mcp::{HttpOptions, ProtocolMode, SessionSettings, SseSettings, WebSocketSettings},
    oauth_client::OAuthConfig,
    proxy_catalog_cache::ProxyCatalogCache,
    secret_envelope::SecretEnvelope,
    sessions::Session,
    sigv4::SigV4Config,
    subscriptions::{AcceptedSubscription, CatalogSubscriptions, ListenSettings},
    upstream::{ToolContext, UpstreamClient, UpstreamEndpoint, UpstreamError, UpstreamTransport},
    upstream_tls::TlsMaterial,
};
use proxy::DirectTarget;

pub(crate) use proxy::GATEWAY_ID_HEADER;

pub struct GatewayService {
    pub(crate) access: Arc<Authorizer>,
    database: Database,
    upstream: UpstreamClient,
    pagination: Pagination,
    management_page_size: u32,
    management_max_page_size: u32,
    refresh: CatalogRefresh,
    active_refreshes: Mutex<HashSet<String>>,
    logging_filter: Option<reload::Handle<LevelFilter, Registry>>,
    subscriptions: CatalogSubscriptions,
    credential_cipher: Option<CredentialCipher>,
    vault: Option<SecretEnvelope>,
    query_auth_hosts: Option<HashSet<String>>,
    header_forwarding: HeaderForwarding,
    identity_forwarding: IdentityForwarding,
    direct_proxy_timeout: Option<Duration>,
    proxy_catalog: ProxyCatalogCache,
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
            management_page_size: 50,
            management_max_page_size: 500,
            refresh,
            active_refreshes: Mutex::default(),
            logging_filter: None,
            subscriptions: CatalogSubscriptions::new(ListenSettings::default()),
            credential_cipher: None,
            vault: None,
            query_auth_hosts: None,
            header_forwarding: HeaderForwarding::default(),
            identity_forwarding: IdentityForwarding::default(),
            direct_proxy_timeout: None,
            proxy_catalog: ProxyCatalogCache::new(ProxyCatalogSettings::default()),
        }
    }

    pub fn with_logging_filter(mut self, filter: reload::Handle<LevelFilter, Registry>) -> Self {
        self.logging_filter = Some(filter);
        self
    }

    pub fn with_management_page_sizes(mut self, default: u32, maximum: u32) -> Self {
        self.management_page_size = default;
        self.management_max_page_size = maximum;
        self
    }

    pub fn with_listen_settings(mut self, settings: ListenSettings) -> Self {
        self.subscriptions = CatalogSubscriptions::new(settings);
        self
    }

    pub fn with_credential_secret(mut self, secret: Option<&str>) -> Self {
        self.credential_cipher = secret.map(CredentialCipher::new);
        self.vault = secret.map(SecretEnvelope::new);
        self
    }

    pub fn with_secret_kdf(mut self, kdf: SecretKdf) -> Self {
        if let Some(vault) = &mut self.vault {
            vault.kdf = kdf;
        }
        self
    }

    pub fn with_query_auth_hosts(mut self, hosts: Option<HashSet<String>>) -> Self {
        self.query_auth_hosts = hosts;
        self
    }

    pub fn with_header_forwarding(mut self, forwarding: HeaderForwarding) -> Self {
        self.header_forwarding = forwarding;
        self
    }

    pub(crate) fn header_forwarding_enabled(&self) -> bool {
        self.header_forwarding.enabled
    }

    pub fn with_identity_forwarding(mut self, forwarding: IdentityForwarding) -> Self {
        self.identity_forwarding = forwarding;
        self
    }

    pub fn with_direct_proxy(mut self, timeout: Option<Duration>) -> Self {
        self.direct_proxy_timeout = timeout;
        self
    }

    pub fn with_proxy_catalog(mut self, settings: ProxyCatalogSettings) -> Self {
        self.proxy_catalog = ProxyCatalogCache::new(settings);
        self
    }

    pub(crate) async fn prepare_subscription(
        &self,
        requested: SubscriptionFilter,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
    ) -> Result<AcceptedSubscription, ErrorData> {
        self.subscriptions
            .prepare(
                &self.database,
                &self.upstream,
                self.credential_cipher.as_ref(),
                requested,
                principal,
                server,
            )
            .await
    }

    pub(crate) async fn visible_server(
        &self,
        id: &str,
        principal: Option<&Principal>,
    ) -> Result<Option<CatalogServer>, sqlx::Error> {
        let scope = access::catalog_scope(principal);
        Ok(self.database.catalog_server(id).await?.filter(|server| {
            server.enabled
                && server.is_visible(scope)
                && (!server.oauth_enabled || principal.is_some())
        }))
    }

    #[allow(deprecated)]
    pub(crate) async fn set_log_level(
        &self,
        level: rmcp::model::LoggingLevel,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
    ) -> Result<(), ErrorData> {
        self.check_mcp_permission(principal, server, "admin.system_config")
            .await?;
        use rmcp::model::LoggingLevel::*;
        let filter = match level {
            Debug => LevelFilter::DEBUG,
            Info | Notice => LevelFilter::INFO,
            Warning => LevelFilter::WARN,
            Error | Critical | Alert | Emergency => LevelFilter::ERROR,
        };
        if let Some(handle) = &self.logging_filter
            && let Err(error) = handle.reload(filter)
        {
            tracing::warn!(%error, "MCP log level update failed");
        }
        Ok(())
    }

    pub fn registration_router(self: &Arc<Self>) -> Router {
        let mut router = Router::new();
        for route in ["/gateways", "/v1/gateways", "/v1/mcp-servers"] {
            router = router
                .route(route, get(management::list).post(register))
                .route(&format!("{route}/"), get(management::list).post(register))
                .route(
                    &format!("{route}/{{key}}"),
                    get(management::detail).delete(management::delete),
                )
                .route(
                    &format!("{route}/{{key}}/impact-preview"),
                    get(management::impact_preview),
                )
                .route(
                    &format!("{route}/{{key}}/tools/refresh"),
                    post(management::refresh),
                );
        }
        self.access.protect_api(router.with_state(self.clone()))
    }

    pub fn mcp_router(self: &Arc<Self>, require_auth: bool, mode: ProtocolMode) -> Router {
        self.mcp_router_with_options(require_auth, mode, HttpOptions::default())
    }

    pub fn legacy_sse_router(
        self: &Arc<Self>,
        require_auth: bool,
        settings: SseSettings,
    ) -> Router {
        crate::legacy_sse::router(self.clone(), self.database.clone(), require_auth, settings)
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

    pub fn websocket_router(self: &Arc<Self>, settings: WebSocketSettings) -> Router {
        crate::websocket::router(self.clone(), settings)
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
        let target = tokio::select! {
            biased;
            () = context.cancellation.cancelled() => return Err(ToolError::Cancelled),
            result = async {
                self.check_tool_execution(principal, server).await?;
                self.direct_target(context.request_headers, principal).await.map_err(ToolError::from)
            } => result?,
        };
        let (gateway, direct_timeout) = match target {
            DirectTarget::Found {
                gateway, timeout, ..
            } => (gateway, Some(timeout)),
            DirectTarget::Denied => {
                return tool_result_error(format!("Tool not found: {}", request.name));
            }
            DirectTarget::Fallback | DirectTarget::Disabled => {
                let tool = tokio::select! {
                    biased;
                    () = context.cancellation.cancelled() => return Err(ToolError::Cancelled),
                    result = self.lookup_tool(principal, server, &request.name) => result?,
                }
                .ok_or(ToolError::NotFound)?;
                let transport = UpstreamTransport::from_name(&tool.gateway_transport);
                let available = matches!(tool.gateway_mode.as_str(), "cache" | "direct_proxy")
                    && UpstreamTransport::from_name(&tool.request_type) == transport
                    && !tool.requires_gateway_policy;
                request.name = tool.original_name.into();
                (
                    ContentGateway {
                        id: tool.gateway_id,
                        url: tool.gateway_url,
                        transport,
                        available,
                        needs_upstream_config: tool.needs_upstream_config,
                    },
                    None,
                )
            }
        };
        let transport = gateway
            .transport
            .filter(|_| gateway.available)
            .ok_or(ToolError::Unavailable)?;
        let credentials = self
            .configured_upstream(
                &gateway.id,
                &gateway.url,
                gateway.needs_upstream_config,
                context.request_headers,
                principal,
            )
            .await?;
        let endpoint = UpstreamEndpoint {
            url: &gateway.url,
            transport,
            credentials: credentials.as_ref(),
        };
        let association = downstream.and_then(|session| {
            let authorization = principal.map(Principal::authorization_fingerprint);
            context.notifications = session.passive_journal(authorization);
            session.upstream(&gateway.id, endpoint, authorization)
        });
        let legacy_caller = context.client_capabilities.is_none();
        let client = direct_timeout.map(|timeout| self.upstream.with_timeout_cap(timeout));
        let result = client
            .as_ref()
            .unwrap_or(&self.upstream)
            .call_tool_with_context(endpoint, request, context, association.as_deref())
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
                tracing::warn!(%error, gateway = %gateway.id, "upstream tool call failed");
                if direct_timeout.is_some() {
                    tool_result_error("Direct proxy tool invocation failed")
                } else {
                    Err(ToolError::Unavailable)
                }
            }
        }
    }

    async fn configured_upstream(
        &self,
        id: &str,
        url: &str,
        needs_upstream_config: bool,
        request_headers: Option<&HeaderMap>,
        principal: Option<&Principal>,
    ) -> Result<Option<UpstreamCredentials>, ToolError> {
        let incoming =
            request_headers.filter(|headers| self.header_forwarding.needs_config(headers));
        if !needs_upstream_config && incoming.is_none() && !self.identity_forwarding.enabled {
            return Ok(None);
        }
        let connection = self
            .database
            .gateway_connection(id, url)
            .await?
            .ok_or(ToolError::Unavailable)?;
        let kind = connection.kind.as_str();
        let cipher = self.credential_cipher.as_ref();
        let mut credentials = if matches!(kind, "" | "none" | "one_time_auth" | "oauth") {
            Ok(UpstreamCredentials::default())
        } else if kind == "sigv4" {
            SigV4Config::load(
                cipher.ok_or(ToolError::Unavailable)?,
                connection.sigv4.as_deref().ok_or(ToolError::Unavailable)?,
            )
            .map(|sigv4| UpstreamCredentials {
                sigv4: Some(sigv4),
                ..UpstreamCredentials::default()
            })
        } else if kind == "query_param" {
            validate_query_host(self.query_auth_hosts.as_ref(), url)
                .map_err(|_| ToolError::Unavailable)?;
            decode_query(
                cipher,
                connection.query.as_deref().ok_or(ToolError::Unavailable)?,
            )
            .map(|query| UpstreamCredentials {
                query,
                ..UpstreamCredentials::default()
            })
        } else {
            decode_headers(
                cipher,
                connection
                    .headers
                    .as_deref()
                    .ok_or(ToolError::Unavailable)?,
            )
            .map(|headers| UpstreamCredentials {
                headers,
                ..UpstreamCredentials::default()
            })
        }
        .map_err(|CredentialError| {
            tracing::warn!(gateway = %id, "could not load upstream authentication");
            ToolError::Unavailable
        })?;
        let client_key = match connection.client_key.filter(|key| !key.trim().is_empty()) {
            Some(key) if key.trim_start().starts_with("-----BEGIN ") => Some(Zeroizing::new(key)),
            Some(key) => Some(
                self.vault
                    .as_ref()
                    .ok_or(ToolError::Unavailable)?
                    .open(key)
                    .await
                    .map_err(|_| ToolError::Unavailable)?,
            ),
            None => None,
        };
        credentials.tls = TlsMaterial::from_pem(
            connection.ca_certificate.as_deref(),
            connection
                .client_cert
                .as_deref()
                .filter(|cert| !cert.trim().is_empty()),
            client_key.as_ref().map(|key| key.as_str()),
        )
        .map_err(|_| {
            tracing::warn!(gateway = %id, "could not load upstream TLS material");
            ToolError::Unavailable
        })?;
        if kind == "oauth" {
            let config = OAuthConfig::load(
                self.vault.as_ref().ok_or(ToolError::Unavailable)?,
                connection.oauth.as_deref().ok_or(ToolError::Unavailable)?,
            )
            .await
            .map_err(|_| ToolError::Unavailable)?;
            let authorization = config
                .authorization(&self.upstream, credentials.tls.as_ref())
                .await
                .map_err(|error| {
                    tracing::warn!(gateway = %id, %error, "could not obtain upstream OAuth token");
                    ToolError::Unavailable
                })?;
            credentials
                .headers
                .insert(header::AUTHORIZATION, authorization);
        }
        if let Some(incoming) = incoming {
            let managed = matches!(kind, "basic" | "bearer" | "authheaders" | "sigv4" | "oauth");
            self.header_forwarding
                .apply(
                    &self.database,
                    &mut credentials.headers,
                    incoming,
                    connection.passthrough.as_deref(),
                    managed,
                )
                .await?;
        }
        self.identity_forwarding
            .apply(
                &mut credentials,
                principal,
                id,
                connection.identity.as_deref(),
            )
            .map_err(|error| {
                tracing::warn!(gateway = %id, %error, "could not propagate upstream identity");
                ToolError::Unavailable
            })?;
        Ok((!credentials.headers.is_empty()
            || !credentials.query.is_empty()
            || credentials.sigv4.is_some()
            || credentials.tls.is_some()
            || credentials.identity_meta.is_some())
        .then_some(credentials))
    }

    pub(crate) async fn tool_definition(
        &self,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        name: &str,
    ) -> Result<Option<ToolDefinition>, ToolError> {
        self.check_tool_execution(principal, server).await?;
        Ok(self
            .lookup_tool(principal, server, name)
            .await?
            .map(|tool| tool.definition))
    }

    async fn check_tool_execution(
        &self,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
    ) -> Result<(), ToolError> {
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
        Ok(())
    }

    async fn lookup_tool(
        &self,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        name: &str,
    ) -> Result<Option<CatalogTool>, ToolError> {
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

fn tool_result_error(message: impl Into<String>) -> Result<Value, ToolError> {
    let mut result = CallToolResult::error(vec![ContentBlock::text(message.into())]);
    result.result_type = None;
    serde_json::to_value(result).map_err(|_| ToolError::Unavailable)
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
    #[serde(alias = "passthroughHeaders")]
    passthrough_headers: Option<Vec<String>>,
    #[serde(alias = "identityPropagation")]
    identity_propagation: Option<Value>,
    #[serde(alias = "caCertificate")]
    ca_certificate: Option<String>,
    #[serde(alias = "caCertificateSig")]
    ca_certificate_sig: Option<String>,
    #[serde(alias = "signingAlgorithm")]
    signing_algorithm: Option<String>,
    #[serde(alias = "clientCert")]
    client_cert: Option<String>,
    #[serde(alias = "clientKey")]
    client_key: Option<String>,
    #[serde(default, alias = "oneTimeAuth")]
    one_time_auth: bool,
    #[serde(flatten)]
    auth: AuthInput,
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
    let transport = UpstreamTransport::from_name(input.transport.as_deref().unwrap_or("SSE"))
        .ok_or_else(|| {
            RegistrationResponse::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unsupported gateway transport, mode, or authentication",
            )
        })?;
    let mode = match input.gateway_mode.as_deref().unwrap_or("cache") {
        "cache" => GatewayMode::Cache,
        "direct_proxy" if service.direct_proxy_timeout.is_some() => GatewayMode::DirectProxy,
        "direct_proxy" => {
            return Err(RegistrationResponse::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unexpected error",
            ));
        }
        _ => {
            return Err(RegistrationResponse::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unsupported gateway transport, mode, or authentication",
            ));
        }
    };

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
    let one_time_auth = input.one_time_auth || input.auth.is_one_time_marker();
    if let Some(identity) = &input.identity_propagation {
        service
            .identity_forwarding
            .validate(identity)
            .map_err(|error| match error {
                IdentityError::Config => RegistrationResponse::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid upstream identity propagation configuration",
                ),
                IdentityError::Signing => RegistrationResponse::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Identity claim signing requires a dedicated IDENTITY_CLAIMS_SECRET",
                ),
            })?;
    }
    if input.passthrough_headers.as_ref().is_some_and(|headers| {
        headers
            .iter()
            .any(|name| HeaderName::from_bytes(name.as_bytes()).is_err())
    }) {
        return Err(RegistrationResponse::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid passthrough header name",
        ));
    }
    let mut auth = input
        .auth
        .prepare(service.credential_cipher.as_ref(), service.query_auth_hosts.as_ref(), url)
        .map_err(|error| match error {
            AuthError::Invalid => RegistrationResponse::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid upstream authentication credentials",
            ),
            AuthError::Unsupported => RegistrationResponse::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unsupported gateway transport, mode, or authentication",
            ),
            AuthError::Encryption(_) => RegistrationResponse::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Gateway credential encryption unavailable",
            ),
            AuthError::QueryDisabled => RegistrationResponse::new(StatusCode::UNPROCESSABLE_ENTITY,
                "Query parameter authentication is disabled. Set INSECURE_ALLOW_QUERYPARAM_AUTH=true to enable."),
            AuthError::QueryHost => RegistrationResponse::new(StatusCode::UNPROCESSABLE_ENTITY,
                "Query parameter authentication is not allowed for the upstream host."),
        })?;
    let client_key = input.client_key.map(Zeroizing::new);
    let tls = TlsMaterial::from_pem(
        input.ca_certificate.as_deref(),
        input.client_cert.as_deref(),
        client_key.as_ref().map(|key| key.as_str()),
    )
    .map_err(|_| {
        RegistrationResponse::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid upstream TLS certificate or private key",
        )
    })?;
    let encrypted_client_key = if let Some(key) = client_key {
        let encryption_error = || {
            RegistrationResponse::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Gateway credential encryption unavailable",
            )
        };
        Some(
            service
                .vault
                .as_ref()
                .ok_or_else(encryption_error)?
                .seal(key)
                .await
                .map_err(|_| encryption_error())?,
        )
    } else {
        None
    };
    if let Some(config) = input.auth.oauth_config()
        && let Some(auth) = &mut auth
    {
        let encryption_error = || {
            RegistrationResponse::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Gateway credential encryption unavailable",
            )
        };
        let (encoded, masked) = config
            .store(service.vault.as_ref().ok_or_else(encryption_error)?)
            .await
            .map_err(|_| encryption_error())?;
        let authorization = config
            .authorization(&service.upstream, tls.as_ref())
            .await
            .map_err(|error| {
                tracing::warn!(%error, "upstream gateway OAuth token request failed");
                match error {
                    UpstreamError::InvalidUrl | UpstreamError::BlockedDestination => {
                        RegistrationResponse::new(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "OAuth token endpoint is invalid or disallowed",
                        )
                    }
                    UpstreamError::InvalidCredentials => RegistrationResponse::new(
                        StatusCode::BAD_REQUEST,
                        "Invalid OAuth client credentials",
                    ),
                    _ => RegistrationResponse::new(
                        StatusCode::BAD_GATEWAY,
                        "OAuth authentication failed",
                    ),
                }
            })?;
        auth.encoded_oauth = Some(encoded);
        auth.masked["oauthConfig"] = masked;
        auth.credentials
            .headers
            .insert(header::AUTHORIZATION, authorization);
    }
    let mut anonymous_credentials = UpstreamCredentials::default();
    let discovery_credentials = auth
        .as_mut()
        .map_or(&mut anonymous_credentials, |auth| &mut auth.credentials);
    discovery_credentials.tls = tls;
    let (discovery, metadata) = service
        .upstream
        .discover_catalog(UpstreamEndpoint {
            url,
            transport,
            credentials: Some(discovery_credentials),
        })
        .await
        .map_err(|error| {
            tracing::warn!(%error, "upstream gateway discovery failed");
            match error {
                UpstreamError::Status(401 | 403) if discovery_credentials.sigv4.is_some() => {
                    RegistrationResponse::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Upstream rejected the SigV4 credentials",
                    )
                }
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
        transport,
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
    let address = peer.map(|Extension(ConnectInfo(address))| address.ip().to_string());
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    service
        .database
        .register_discovered_gateway(
            &registration,
            &registered_tools,
            &metadata,
            RegistrationOptions {
                auth: if one_time_auth { None } else { auth.as_ref() },
                passthrough_headers: input.passthrough_headers.as_deref(),
                identity: input.identity_propagation.as_ref(),
                mode,
                one_time_auth,
                tls: RegisteredTls {
                    ca_certificate: input.ca_certificate.as_deref(),
                    ca_certificate_sig: input.ca_certificate_sig.as_deref(),
                    signing_algorithm: input.signing_algorithm.as_deref(),
                    client_cert: input.client_cert.as_deref(),
                    client_key: encrypted_client_key.as_deref(),
                },
                created_from_ip: address.as_deref(),
                created_user_agent: agent,
            },
        )
        .await?;
    service.subscriptions.registered(&registration);
    let mut response = registration_response(&registration, address, agent);
    response["gatewayMode"] = mode.name().into();
    response["caCertificate"] = json!(input.ca_certificate);
    response["caCertificateSig"] = json!(input.ca_certificate_sig);
    response["clientCert"] = json!(input.client_cert);
    if let Some(algorithm) = input.signing_algorithm {
        response["signingAlgorithm"] = algorithm.into();
    }
    if encrypted_client_key.is_some() {
        response["clientKey"] = "*****".into();
    }
    if let Some(headers) = input.passthrough_headers {
        response["passthroughHeaders"] = json!(headers);
    }
    if let Some(identity) = input.identity_propagation {
        response["identityPropagation"] = identity;
    }
    if one_time_auth {
        response["authType"] = "one_time_auth".into();
    } else if let Some(auth) = auth
        && let Value::Object(masked) = auth.masked
    {
        response
            .as_object_mut()
            .expect("registration response object")
            .extend(masked);
    }
    Ok(Json(response))
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
        "description": gateway.description, "transport": gateway.transport.name(),
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
