// SPDX-License-Identifier: Apache-2.0
//! MCP Streamable HTTP ingress.

use std::{collections::HashSet, convert::Infallible, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::{
        Extensions, HeaderMap, HeaderValue, Method, StatusCode,
        header::{ACCEPT, ALLOW, CACHE_CONTROL, CONTENT_TYPE, HOST, ORIGIN, RETRY_AFTER, VARY},
        uri::Authority,
    },
    middleware::{self, Next},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::any,
};
use futures_util::{Stream, StreamExt, stream};
use rmcp::model::{
    CallToolRequestParams, CancelledNotificationParam, CompleteRequestParams, ErrorData,
    GetPromptRequestParams, GetPromptResponse, Implementation, InitializeRequestParams,
    InitializeResult, PaginatedRequestParams, ProgressNotification, ProgressNotificationParam,
    ProgressToken, PromptsCapability, ProtocolVersion, ReadResourceRequestParams,
    ReadResourceResponse, RequestId, ResourcesCapability, ServerCapabilities, ServerJsonRpcMessage,
    ToolsCapability,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

pub use crate::legacy_sse::SseSettings;
pub use crate::redis_sessions::RedisSessionDirectory;
pub use crate::subscriptions::ListenSettings;
pub use crate::websocket::WebSocketSettings;

use crate::{
    access::{self, Principal},
    affinity::{self, Forwarded},
    catalog::{CatalogList, CatalogServer},
    events::{Journal, parse_cursor},
    gateway::{GatewayService, ToolError},
    modern::Modern,
    sessions::{
        PendingError, PendingRequest, Session, SessionAccess, SessionError, Sessions,
        new_session_id,
    },
    upstream::{ToolContext, ToolProgress},
};

const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const SESSION_HEADER: &str = "mcp-session-id";
const LAST_EVENT_ID: &str = "last-event-id";
const RUNTIME_HEADER: &str = "x-contextforge-mcp-runtime";
const LEGACY_VERSIONS: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
const MODERN_VERSION: &str = "2026-07-28";
pub(crate) const ROOT_INSTRUCTIONS: &str = "ContextForge providing federated tools, resources and prompts. Use /admin interface for configuration.";
const SUPPORTED_VERSIONS: [&str; 5] = [
    LEGACY_VERSIONS[0],
    LEGACY_VERSIONS[1],
    LEGACY_VERSIONS[2],
    LEGACY_VERSIONS[3],
    MODERN_VERSION,
];
pub(crate) const JSON_MEDIA_TYPE: &str = "application/json";
pub(crate) const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;
const REQUEST_CANCELLED: i32 = -32800;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProtocolMode {
    #[default]
    Auto,
    Legacy,
}

pub struct SessionSettings {
    pub ttl: Duration,
    pub get_stream_enabled: bool,
    pub shutdown: CancellationToken,
    pub event_capacity: usize,
    pub event_ttl: Duration,
    pub redis: Option<Arc<RedisSessionDirectory>>,
    pub affinity_forward_timeout: Duration,
    pub affinity_forward_concurrency: usize,
    pub affinity_session_lock_timeout: Duration,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(3600),
            get_stream_enabled: true,
            shutdown: CancellationToken::new(),
            event_capacity: 100,
            event_ttl: Duration::from_secs(3600),
            redis: None,
            affinity_forward_timeout: Duration::from_secs(30),
            affinity_forward_concurrency: 32,
            affinity_session_lock_timeout: Duration::from_secs(30),
        }
    }
}

pub struct HttpOptions {
    pub json_response: bool,
    pub sessions: Option<SessionSettings>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            json_response: true,
            sessions: None,
        }
    }
}

struct McpState {
    service: Arc<GatewayService>,
    modern: Option<Modern>,
    sessions: Option<Sessions>,
    json_response: bool,
}

/// Build the Streamable HTTP routes for mounting behind gateway access checks.
pub(crate) fn router(
    service: Arc<GatewayService>,
    mode: ProtocolMode,
    options: HttpOptions,
    require_auth: bool,
) -> Router {
    let relay = options.sessions.as_ref().and_then(|sessions| {
        Some((
            sessions.redis.as_ref()?.clone(),
            sessions.affinity_forward_timeout,
            sessions.affinity_forward_concurrency,
            sessions.affinity_session_lock_timeout,
            sessions.shutdown.clone(),
        ))
    });
    let gateway = service.clone();
    let router = Router::new()
        .route("/mcp", any(handle_request))
        .route("/mcp/", any(handle_request))
        .route("/servers/{server_id}/mcp", any(handle_request))
        .route("/servers/{server_id}/mcp/", any(handle_request))
        .route("/v1/virtual-servers/{server_id}/mcp", any(handle_request))
        .route("/v1/virtual-servers/{server_id}/mcp/", any(handle_request))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(Arc::new(McpState {
            modern: (mode == ProtocolMode::Auto)
                .then(|| Modern::new(service.clone(), options.json_response)),
            sessions: options.sessions.map(Sessions::new),
            json_response: options.json_response,
            service,
        }));
    let router = gateway.access.protect_mcp(router, require_auth);
    if let Some((redis, timeout, concurrency, lock_timeout, shutdown)) = relay {
        affinity::spawn(
            redis,
            router.clone(),
            timeout,
            concurrency,
            lock_timeout,
            shutdown,
        );
    }
    router
}

#[derive(Default)]
pub struct IngressPolicy {
    pub origins: HashSet<String>,
    pub hosts: HashSet<String>,
}

impl IngressPolicy {
    pub fn apply(self, router: Router) -> Router {
        router.route_layer(middleware::from_fn_with_state(
            Arc::new(self),
            check_ingress,
        ))
    }
}

async fn check_ingress(
    State(policy): State<Arc<IngressPolicy>>,
    request: Request,
    next: Next,
) -> Response {
    let mut origins = request.headers().get_all(ORIGIN).iter();
    if !policy.origins.is_empty()
        && let Some(origin) = origins.next()
        && (origins.next().is_some()
            || !origin
                .to_str()
                .is_ok_and(|value| policy.origins.contains(value)))
    {
        return (
            StatusCode::FORBIDDEN,
            Json(Detail {
                detail: "Forbidden: Origin not allowed",
            }),
        )
            .into_response();
    }

    if !policy.hosts.is_empty() {
        let mut hosts = request.headers().get_all(HOST).iter();
        let host = hosts.next();
        let raw = host
            .and_then(|value| value.to_str().ok())
            .or_else(|| request.uri().authority().map(Authority::as_str));
        let disallowed =
            raw.is_some_and(|host| !is_loopback_host(host) && !policy.hosts.contains(host));
        if hosts.next().is_some() || host.is_some_and(|value| value.to_str().is_err()) || disallowed
        {
            return (
                StatusCode::FORBIDDEN,
                Json(Detail {
                    detail: "Forbidden: Host not allowed",
                }),
            )
                .into_response();
        }
    }
    next.run(request).await
}

fn is_loopback_host(value: &str) -> bool {
    let host = value.parse::<Authority>();
    value == "::1"
        || host.as_ref().is_ok_and(|authority| {
            matches!(authority.host(), "127.0.0.1" | "localhost" | "[::1]")
                && !authority.as_str().contains('@')
        })
}

async fn handle_request(State(state): State<Arc<McpState>>, request: Request) -> Response {
    let supported: &'static [&str] = if state.modern.is_some() {
        &SUPPORTED_VERSIONS
    } else {
        &LEGACY_VERSIONS
    };
    let version = request.headers().get(PROTOCOL_VERSION_HEADER);
    if let Some(version) = version
        && !version
            .to_str()
            .is_ok_and(|version| supported.contains(&version))
    {
        let requested: String = version.as_bytes().iter().copied().map(char::from).collect();
        return rpc_error(
            StatusCode::BAD_REQUEST,
            &Value::Null,
            UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            Some(VersionError {
                supported,
                requested: &requested,
            }),
        );
    }

    if request.method() != Method::GET
        && version.is_some_and(|version| version == MODERN_VERSION)
        && let Some(modern) = &state.modern
    {
        let mut response = modern.handle(request).await;
        response
            .headers_mut()
            .insert(RUNTIME_HEADER, HeaderValue::from_static("rust"));
        response
            .headers_mut()
            .entry(VARY)
            .or_insert(HeaderValue::from_static("Origin"));
        return response;
    }

    let request = match forward_remote(&state, request).await {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let is_head = request.method() == Method::HEAD;
    let mut response = match *request.method() {
        Method::GET => handle_get(&state, request).await,
        Method::POST => handle_post(&state, request).await,
        Method::DELETE => delete_session(state.sessions.as_ref(), request).await,
        _ => {
            let mut response =
                transport_error(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, POST, DELETE"));
            response
        }
    };
    response
        .headers_mut()
        .insert(VARY, HeaderValue::from_static("Origin"));
    response
        .headers_mut()
        .insert(RUNTIME_HEADER, HeaderValue::from_static("rust"));
    if is_head {
        *response.body_mut() = Body::empty();
    }
    response
}

async fn forward_remote(state: &McpState, request: Request) -> Result<Request, Box<Response>> {
    if !matches!(
        *request.method(),
        Method::GET | Method::POST | Method::DELETE
    ) || request.extensions().get::<Forwarded>().is_some()
    {
        return Ok(request);
    }
    let Some(sessions) = &state.sessions else {
        return Ok(request);
    };
    let Some(redis) = sessions.redis() else {
        return Ok(request);
    };
    if request.method() == Method::GET {
        if !has_post_cursor(request.headers()) {
            return Ok(request);
        }
    } else if !redis.affinity_enabled() {
        return Ok(request);
    }
    let Ok(Some(id)) = session_header(request.headers()) else {
        return Ok(request);
    };
    if sessions.local_exists(id) {
        return Ok(request);
    }
    let owner = request
        .extensions()
        .get::<Principal>()
        .map(|principal| principal.email.as_str());
    let server = request
        .extensions()
        .get::<CatalogServer>()
        .map(|server| server.id.as_str());
    let worker = match redis
        .locate(id, owner, server, *request.method() == Method::POST)
        .await
    {
        Err(SessionError::Remote(worker)) => worker,
        // The local route applies endpoint-specific validation and error formatting.
        _ => return Ok(request),
    };
    let request = if *request.method() == Method::POST {
        let (parts, body) = request.into_parts();
        let body = Bytes::from_request(Request::from_parts(parts.clone(), body), &())
            .await
            .map_err(|rejection| Box::new(rejection.into_response()))?;
        let is_utf8 = std::str::from_utf8(&body).is_ok();
        let is_initializer = serde_json::from_slice::<Value>(&body)
            .is_ok_and(|message| message.get("id").is_some() && message["method"] == "initialize");
        let request = Request::from_parts(parts, Body::from(body));
        if is_initializer || !is_utf8 {
            return Ok(request);
        }
        request
    } else {
        request
    };
    Err(Box::new(
        affinity::forward(
            redis.clone(),
            worker,
            request,
            sessions.affinity_forward_timeout(),
        )
        .await,
    ))
}

async fn handle_get(state: &McpState, request: Request) -> Response {
    let Some(sessions) = &state.sessions else {
        return get_not_allowed(
            "Stateful sessions disabled on this gateway; passive SSE stream is not available.",
        );
    };
    if !sessions.get_stream_enabled() {
        return get_not_allowed(
            "GET /mcp stream disabled by operator (MCP_GET_STREAM_ENABLED=False).",
        );
    }
    if let Some(redis) = sessions.redis()
        && !has_post_cursor(request.headers())
    {
        return handle_shared_events(
            state,
            sessions,
            redis,
            request.headers(),
            request.extensions(),
        )
        .await;
    }
    let (session_id, session) = match session_from_request(
        sessions,
        request.headers(),
        request.extensions(),
        SessionAccess::Get,
    )
    .await
    {
        Ok(owned) => owned,
        Err(SessionError::Missing) => {
            return get_not_allowed(
                "Passive SSE stream requires an Mcp-Session-Id from a prior initialize.",
            );
        }
        Err(error) => return session_error(error),
    };
    if !accepts_event_stream(request.headers()) {
        return (
            StatusCode::NOT_ACCEPTABLE,
            Json(Detail {
                detail: "GET /mcp requires Accept: text/event-stream",
            }),
        )
            .into_response();
    }
    let principal = request.extensions().get::<Principal>();
    let authorization = principal.map(Principal::authorization_fingerprint);
    let server = request.extensions().get::<CatalogServer>();
    let cursor = request.headers().get(LAST_EVENT_ID);
    let resumed = cursor
        .and_then(|value| value.to_str().ok())
        .and_then(|cursor| session.replay(cursor));
    if let Some(redis) = sessions.redis()
        && resumed.is_none()
    {
        return handle_shared_events(
            state,
            sessions,
            redis,
            request.headers(),
            request.extensions(),
        )
        .await;
    }
    let replay = if let Some((journal, replay)) = resumed {
        if journal.authorization != authorization {
            return session_error(SessionError::Forbidden);
        }
        if let Some(permission) = journal.permission() {
            match allows_events(state, principal, server, permission).await {
                Ok(true) => {}
                Ok(false) => return session_error(SessionError::Forbidden),
                Err(error) => return event_permission_error(error),
            }
        }
        if journal.is_post_open() {
            return stream_conflict("The original MCP POST stream is still open.");
        }
        Some(replay)
    } else {
        match allows_events(state, principal, server, "tools.execute").await {
            Ok(true) => session.passive_journal(authorization).and_then(|journal| {
                journal
                    .local()
                    .map(|journal| journal.listen(cursor.is_none()))
            }),
            Ok(false) => None,
            Err(error) => return event_permission_error(error),
        }
    };
    let listener = match sessions.listen(&session_id, session).await {
        Ok(Some(listener)) => listener,
        Ok(None) => {
            return stream_conflict("Another GET /mcp stream is already open for this session.");
        }
        Err(SessionError::Unavailable) => return listener_unavailable(),
        Err(error) => return session_error(error),
    };
    let events = stream::unfold((listener, replay), |(listener, mut replay)| async move {
        let Some(reader) = &mut replay else {
            listener.wait_until_closed().await;
            return None;
        };
        let frame = tokio::select! {
            biased;
            () = listener.wait_until_closed() => None,
            frame = reader.next() => frame,
        }?;
        Some((Ok::<_, Infallible>(frame.into_event()), (listener, replay)))
    });
    event_stream(events)
}

fn has_post_cursor(headers: &HeaderMap) -> bool {
    headers
        .get(LAST_EVENT_ID)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_cursor)
        .is_some()
}

async fn handle_shared_events(
    state: &McpState,
    sessions: &Sessions,
    redis: &Arc<RedisSessionDirectory>,
    headers: &HeaderMap,
    extensions: &Extensions,
) -> Response {
    let id = match session_header(headers) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return get_not_allowed(
                "Passive SSE stream requires an Mcp-Session-Id from a prior initialize.",
            );
        }
        Err(error) => return session_error(error),
    };
    let principal = extensions.get::<Principal>();
    let server = extensions.get::<CatalogServer>();
    match redis
        .locate(
            id,
            principal.map(|p| p.email.as_str()),
            server.map(|s| s.id.as_str()),
            false,
        )
        .await
    {
        Ok(()) | Err(SessionError::Remote(_)) => {}
        Err(error) => return session_error(error),
    }
    if !accepts_event_stream(headers) {
        return (
            StatusCode::NOT_ACCEPTABLE,
            Json(Detail {
                detail: "GET /mcp requires Accept: text/event-stream",
            }),
        )
            .into_response();
    }
    let allowed = match allows_events(state, principal, server, "tools.execute").await {
        Ok(allowed) => allowed,
        Err(error) => return event_permission_error(error),
    };
    let journal = match sessions.shared_events(
        redis,
        id,
        principal.map(Principal::authorization_fingerprint),
    ) {
        Ok(journal) => journal,
        Err(error) => return session_error(error),
    };
    let cursor = headers
        .get(LAST_EVENT_ID)
        .map(|value| value.to_str().unwrap_or(""));
    let after = match journal.after(cursor, allowed) {
        Ok(after) => after,
        Err(error) => return session_error(error),
    };
    let listener = match sessions.listen_shared(redis, id).await {
        Ok(Some(listener)) => listener,
        Ok(None) => {
            return stream_conflict("Another GET /mcp stream is already open for this session.");
        }
        Err(SessionError::Unavailable) => return listener_unavailable(),
        Err(error) => return session_error(error),
    };
    let reader = match journal.listen(after, allowed).await {
        Ok(reader) => reader,
        Err(error) => return session_error(error),
    };
    event_stream(stream::unfold(
        (listener, reader),
        |(listener, mut reader)| async move {
            let event = tokio::select! {
                biased;
                () = listener.wait_until_lost() => None,
                event = reader.next() => event,
            }?;
            Some((Ok(event), (listener, reader)))
        },
    ))
}

fn listener_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(RETRY_AFTER, "1")],
        Json(Detail {
            detail: "Listener-claim storage unavailable; retry shortly.",
        }),
    )
        .into_response()
}

fn event_stream(
    events: impl Stream<Item = Result<Event, Infallible>> + Send + 'static,
) -> Response {
    (
        [
            (CONTENT_TYPE, "text/event-stream; charset=utf-8"),
            (CACHE_CONTROL, "no-cache"),
            (
                axum::http::HeaderName::from_static("x-accel-buffering"),
                "no",
            ),
        ],
        Sse::new(events).keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("ping"),
        ),
    )
        .into_response()
}

async fn allows_events(
    state: &McpState,
    principal: Option<&Principal>,
    server: Option<&CatalogServer>,
    permission: &str,
) -> Result<bool, sqlx::Error> {
    let Some(principal) = principal else {
        return Ok(true);
    };
    state
        .service
        .access
        .allows(principal, permission, access::role_context(server), true)
        .await
}

fn event_permission_error(error: sqlx::Error) -> Response {
    tracing::error!(%error, "MCP stream permission lookup failed");
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

fn stream_conflict(detail: &'static str) -> Response {
    (
        StatusCode::CONFLICT,
        [(RETRY_AFTER, "1")],
        Json(Detail { detail }),
    )
        .into_response()
}

fn get_not_allowed(detail: &'static str) -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(ALLOW, "POST, DELETE")],
        Json(Detail { detail }),
    )
        .into_response()
}

pub(crate) fn accepts_event_stream(headers: &HeaderMap) -> bool {
    if !headers.contains_key(ACCEPT) {
        return true;
    }
    headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|entry| {
            let mut fields = entry.split(';');
            let media = fields.next().unwrap_or_default().trim();
            let quality = fields
                .filter_map(|param| param.split_once('='))
                .find(|(name, _)| name.trim().eq_ignore_ascii_case("q"))
                .map_or(1.0, |(_, value)| {
                    value.trim().parse::<f64>().unwrap_or_default()
                });
            quality > 0.0
                && (media == "*/*"
                    || media.eq_ignore_ascii_case("text/*")
                    || media.eq_ignore_ascii_case("text/event-stream"))
        })
}

async fn delete_session(sessions: Option<&Sessions>, request: Request) -> Response {
    let Some(sessions) = sessions else {
        return transport_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed: Session termination not supported",
        );
    };
    match session_from_request(
        sessions,
        request.headers(),
        request.extensions(),
        SessionAccess::Delete,
    )
    .await
    {
        Ok(_) => Json(json!({"jsonrpc": "2.0", "result": {}})).into_response(),
        Err(error) => session_error(error),
    }
}

async fn session_from_request(
    sessions: &Sessions,
    headers: &HeaderMap,
    extensions: &Extensions,
    access: SessionAccess,
) -> Result<(HeaderValue, Arc<Session>), SessionError> {
    let owner = extensions.get::<Principal>().map(|p| p.email.as_str());
    let server = extensions.get::<CatalogServer>().map(|s| s.id.as_str());
    let id = session_header(headers)?.ok_or(SessionError::Missing)?;
    let session = sessions.access(Some(id), owner, server, access).await?;
    Ok((id.clone(), session))
}

async fn handle_post(state: &Arc<McpState>, request: Request) -> Response {
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|header| header.to_str().ok())
        .unwrap_or_default();
    if !content_type
        .get(..JSON_MEDIA_TYPE.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(JSON_MEDIA_TYPE))
    {
        return (
            StatusCode::BAD_REQUEST,
            Body::from("Invalid Content-Type header"),
        )
            .into_response();
    }
    let accept_error = |message| {
        let response = transport_error(StatusCode::NOT_ACCEPTABLE, message);
        if state.sessions.is_some() && matches!(session_header(request.headers()), Ok(None)) {
            return with_session(response, Some(&new_session_id()));
        }
        response
    };
    if !state.json_response
        && !(accepts_json(request.headers()) && accepts_post_stream(request.headers()))
    {
        return accept_error(
            "Not Acceptable: Client must accept both application/json and text/event-stream",
        );
    }
    if state.json_response && !accepts_json(request.headers()) {
        return accept_error("Not Acceptable: Client must accept application/json");
    }
    if !content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .split(',')
        .any(|part| part.trim() == JSON_MEDIA_TYPE)
    {
        return transport_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Unsupported Media Type: Content-Type must be application/json",
        );
    }

    let session_id = if state.sessions.is_some() {
        match session_header(request.headers()) {
            Ok(id) => id.cloned(),
            Err(error) => return session_error(error),
        }
    } else {
        None
    };
    let (mut parts, body) = request.into_parts();
    let prime = parts
        .headers
        .get(PROTOCOL_VERSION_HEADER)
        .is_some_and(|version| version == ProtocolVersion::V_2025_11_25.as_str());
    let principal = parts.extensions.remove::<Principal>();
    let server = parts.extensions.remove::<CatalogServer>();
    let bytes = match Bytes::from_request(Request::from_parts(parts, body), &()).await {
        Ok(bytes) => bytes,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Body::from("Request body too large"),
            )
                .into_response();
        }
        Err(_) => return transport_error(StatusCode::BAD_REQUEST, "Invalid request body"),
    };

    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => dispatch(state, principal, server, session_id, value, prime).await,
        Err(error) => rpc_error(
            StatusCode::BAD_REQUEST,
            &Value::Null,
            PARSE_ERROR,
            &format!("Parse error: {error}"),
            None::<()>,
        ),
    }
}

pub(crate) fn accepts_json(headers: &HeaderMap) -> bool {
    accepted_media_types(headers).any(|media_type| {
        media_type == "*/*"
            || media_type.eq_ignore_ascii_case("application/*")
            || media_type.eq_ignore_ascii_case(JSON_MEDIA_TYPE)
    })
}

pub(crate) fn accepts_post_stream(headers: &HeaderMap) -> bool {
    accepted_media_types(headers).any(|media_type| {
        media_type == "*/*"
            || media_type.eq_ignore_ascii_case("text/*")
            || media_type.eq_ignore_ascii_case("text/event-stream")
    })
}

fn accepted_media_types(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(','))
        .filter_map(|entry| entry.split(';').next())
        .map(str::trim)
}

async fn dispatch(
    state: &McpState,
    principal: Option<Principal>,
    server: Option<CatalogServer>,
    session_id: Option<HeaderValue>,
    value: Value,
    prime: bool,
) -> Response {
    let Value::Object(mut message) = value else {
        return invalid_envelope();
    };
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return invalid_envelope();
    }
    let id = message.remove("id");
    if id
        .as_ref()
        .is_some_and(|id| !(id.is_string() || id.is_i64() || id.is_u64()))
    {
        return invalid_envelope();
    }
    let owner = principal.as_ref().map(|p| p.email.as_str());
    let server_id = server.as_ref().map(|s| s.id.as_str());

    if let Some(method) = message.remove("method") {
        let Value::String(method) = method else {
            return invalid_envelope();
        };
        let params = match message.remove("params") {
            None | Some(Value::Null) => None,
            Some(params @ Value::Object(_)) => Some(params),
            Some(_) => return invalid_envelope(),
        };
        if let (Some(id), "initialize") = (id.as_ref(), method.as_str()) {
            let Some(result) = initialize(params.as_ref(), server.as_ref()) else {
                return invalid_params(id);
            };
            let can_prime = result.protocol_version == ProtocolVersion::V_2025_11_25;
            let (session_id, journal) = match &state.sessions {
                Some(sessions) => match sessions.create(owner, server_id).await {
                    Ok((session_id, session)) => {
                        let journal = post_journal(
                            &session,
                            state.json_response,
                            principal.as_ref(),
                            None,
                            can_prime,
                        );
                        (Some(session_id), journal)
                    }
                    Err(error) => return session_error(error),
                },
                None => (None, None),
            };
            let reply = std::future::ready(rpc_success(id, result));
            return post_reply(state.json_response, session_id, reply, None, journal).await;
        }
        let session = match &state.sessions {
            Some(sessions) => match sessions
                .access(session_id.as_ref(), owner, server_id, SessionAccess::Post)
                .await
            {
                Ok(session) => Some(session),
                Err(error) => return post_session_error(error),
            },
            None => None,
        };
        let Some(id) = id else {
            let response = match (method.as_str(), session) {
                ("notifications/cancelled", Some(session)) => {
                    cancel_request(&session, params.as_ref())
                }
                _ => accepted(),
            };
            return with_session(response, session_id.as_ref());
        };
        let stateful = session.is_some();
        let permission = match method.as_str() {
            "tools/call" => Some("tools.execute"),
            "resources/read" => Some("resources.read"),
            "prompts/get" => Some("prompts.read"),
            "completion/complete" => Some("tools.read"),
            "logging/setLevel" => Some("admin.system_config"),
            _ => None,
        };
        let journal = session.as_ref().and_then(|session| {
            post_journal(
                session,
                state.json_response,
                principal.as_ref(),
                permission,
                prime,
            )
        });
        let (progress, updates) = match (!state.json_response && permission.is_some())
            .then(|| progress_token(params.as_ref()))
            .flatten()
        {
            Some(token) => {
                let (progress, updates) = ToolProgress::channel(token);
                (Some(progress), Some(updates))
            }
            None => (None, None),
        };
        let service = state.service.clone();
        let reply = async move {
            let principal = principal.as_ref();
            let server = server.as_ref();
            let params = params.as_ref();
            match method.as_str() {
                "ping" => rpc_success(&id, Empty {}),
                "logging/setLevel" => set_log_level(&service, principal, server, &id, params).await,
                "tools/list" => list_tools(&service, principal, server, &id, params).await,
                "resources/list" => {
                    list_catalog_metadata(
                        &service,
                        CatalogList::Resources,
                        principal,
                        server,
                        &id,
                        params,
                    )
                    .await
                }
                "resources/templates/list" => {
                    list_catalog_metadata(
                        &service,
                        CatalogList::Templates,
                        principal,
                        server,
                        &id,
                        params,
                    )
                    .await
                }
                "prompts/list" => {
                    list_catalog_metadata(
                        &service,
                        CatalogList::Prompts,
                        principal,
                        server,
                        &id,
                        params,
                    )
                    .await
                }
                "tools/call" => {
                    call_tool(
                        &service,
                        principal,
                        server,
                        session,
                        &id,
                        params,
                        progress.as_ref(),
                    )
                    .await
                }
                "resources/read" => {
                    let Some(Ok(params)) = params.map(ReadResourceRequestParams::deserialize)
                    else {
                        return invalid_params(&id);
                    };
                    if params.input_responses.is_some() || params.request_state.is_some() {
                        return invalid_params(&id);
                    }
                    let pending = match track_request(session.as_ref(), &id) {
                        Ok(pending) => pending,
                        Err(reply) => return *reply,
                    };
                    let cancellation = pending
                        .as_ref()
                        .map(|pending| pending.token.clone())
                        .unwrap_or_default();
                    let context = ToolContext {
                        cancellation: &cancellation,
                        progress: progress.as_ref(),
                        notifications: None,
                        client_capabilities: None,
                    };
                    let result = service
                        .read_resource(params, principal, server, context, session.as_deref())
                        .await;
                    if cancellation.is_cancelled() {
                        return tool_error(&id, ToolError::Cancelled);
                    }
                    match result {
                        Ok(ReadResourceResponse::Complete(mut result)) => {
                            result.result_type = None;
                            result.ttl_ms = None;
                            result.cache_scope = None;
                            rpc_success(&id, result)
                        }
                        Ok(_) => content_error(
                            &id,
                            ErrorData::internal_error("Elicitation not supported", None),
                        ),
                        Err(error) => content_error(&id, error),
                    }
                }
                "prompts/get" => {
                    let Some(Ok(params)) = params.map(GetPromptRequestParams::deserialize) else {
                        return invalid_params(&id);
                    };
                    if params.input_responses.is_some() || params.request_state.is_some() {
                        return invalid_params(&id);
                    }
                    let pending = match track_request(session.as_ref(), &id) {
                        Ok(pending) => pending,
                        Err(reply) => return *reply,
                    };
                    let cancellation = pending
                        .as_ref()
                        .map(|pending| pending.token.clone())
                        .unwrap_or_default();
                    let context = ToolContext {
                        cancellation: &cancellation,
                        progress: progress.as_ref(),
                        notifications: None,
                        client_capabilities: None,
                    };
                    let result = service
                        .get_prompt(params, principal, server, context, session.as_deref())
                        .await;
                    if cancellation.is_cancelled() {
                        return tool_error(&id, ToolError::Cancelled);
                    }
                    match result {
                        Ok(GetPromptResponse::Complete(mut result)) => {
                            result.result_type = None;
                            rpc_success(&id, result)
                        }
                        Ok(_) => content_error(
                            &id,
                            ErrorData::internal_error("Elicitation not supported", None),
                        ),
                        Err(error) => content_error(&id, error),
                    }
                }
                "completion/complete" => {
                    let Some(Ok(params)) = params.map(CompleteRequestParams::deserialize) else {
                        return invalid_params(&id);
                    };
                    let pending = match track_request(session.as_ref(), &id) {
                        Ok(pending) => pending,
                        Err(reply) => return *reply,
                    };
                    let cancellation = pending
                        .as_ref()
                        .map(|pending| pending.token.clone())
                        .unwrap_or_default();
                    let context = ToolContext {
                        cancellation: &cancellation,
                        progress: progress.as_ref(),
                        notifications: None,
                        client_capabilities: None,
                    };
                    let result = service
                        .complete(params, principal, server, context, session.as_deref())
                        .await;
                    if cancellation.is_cancelled() {
                        return tool_error(&id, ToolError::Cancelled);
                    }
                    match result {
                        Ok(mut result) => {
                            result.result_type = None;
                            rpc_success(&id, result)
                        }
                        Err(error) => content_error(&id, error),
                    }
                }
                _ => rpc_error(
                    StatusCode::OK,
                    &id,
                    METHOD_NOT_FOUND,
                    "Method not found",
                    Some(method),
                ),
            }
        };
        if stateful {
            // Keep processing if the client loses the HTTP connection.
            let task = tokio::spawn(reply);
            return post_reply(
                state.json_response,
                session_id,
                async move {
                    match task.await {
                        Ok(response) => response,
                        Err(error) => {
                            tracing::error!(%error, "MCP request task failed");
                            tool_error(&Value::Null, ToolError::Unavailable)
                        }
                    }
                },
                updates,
                journal,
            )
            .await;
        }
        return post_reply(state.json_response, session_id, reply, updates, None).await;
    }

    let result = message.get("result");
    let error = message.get("error");
    let valid_response = match (result, error) {
        (Some(Value::Object(_)), None) => true,
        (None, Some(Value::Object(error))) => {
            error.get("code").is_some_and(Value::is_i64)
                && error.get("message").is_some_and(Value::is_string)
        }
        _ => false,
    };
    if id.is_some() && valid_response {
        if let Some(sessions) = &state.sessions
            && let Err(error) = sessions
                .access(session_id.as_ref(), owner, server_id, SessionAccess::Post)
                .await
        {
            return post_session_error(error);
        }
        return with_session(accepted(), session_id.as_ref());
    }

    invalid_envelope()
}

fn progress_token(params: Option<&Value>) -> Option<ProgressToken> {
    ProgressToken::deserialize(params?.get("_meta")?.get("progressToken")?).ok()
}

fn post_journal(
    session: &Session,
    json_response: bool,
    principal: Option<&Principal>,
    permission: Option<&'static str>,
    prime: bool,
) -> Option<(Arc<Journal>, bool)> {
    if json_response {
        return None;
    }
    Some((session.start_journal(principal, permission)?, prime))
}

async fn post_reply(
    json_response: bool,
    session_id: Option<HeaderValue>,
    reply: impl Future<Output = Response> + Send + 'static,
    updates: Option<tokio::sync::mpsc::Receiver<ProgressNotificationParam>>,
    journal: Option<(Arc<Journal>, bool)>,
) -> Response {
    let response = if json_response {
        reply.await
    } else {
        let frames = reply_frames(reply, updates);
        match journal {
            Some((journal, prime)) => {
                let prefix = prime.then(|| journal.prime());
                post_sse(recorded_events(journal, frames), prefix)
            }
            None => post_sse(
                frames
                    .map(|frame| frame.map(|data| Event::default().event("message").data(&*data))),
                None,
            ),
        }
    };
    with_session(response, session_id.as_ref())
}

type ReplyFrame = Result<Arc<str>, std::io::Error>;

fn reply_frames(
    reply: impl Future<Output = Response> + Send + 'static,
    updates: Option<tokio::sync::mpsc::Receiver<ProgressNotificationParam>>,
) -> impl futures_util::Stream<Item = ReplyFrame> + Send + 'static {
    stream::unfold(Some((Box::pin(reply), updates)), |state| async move {
        let (mut reply, mut updates) = state?;
        let terminal = if let Some(receiver) = &mut updates {
            tokio::select! {
                biased;
                next = receiver.recv() => match next {
                    Some(progress) => {
                        return Some((vec![progress_frame(progress)], Some((reply, updates))));
                    }
                    None => reply.await,
                },
                terminal = &mut reply => terminal,
            }
        } else {
            reply.await
        };
        let mut events = Vec::new();
        if let Some(mut receiver) = updates {
            while let Ok(progress) = receiver.try_recv() {
                events.push(progress_frame(progress));
            }
        }
        let bytes = to_bytes(terminal.into_body(), usize::MAX)
            .await
            .map_err(std::io::Error::other);
        events.push(bytes.and_then(|body| {
            std::str::from_utf8(&body)
                .map(Arc::from)
                .map_err(std::io::Error::other)
        }));
        Some((events, None))
    })
    .flat_map(stream::iter)
}

fn recorded_events(
    journal: Arc<Journal>,
    frames: impl futures_util::Stream<Item = ReplyFrame> + Send + 'static,
) -> impl futures_util::Stream<Item = Result<Event, std::io::Error>> + Send + 'static {
    let guard = journal.live_post();
    let (sender, receiver) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut sender = Some(sender);
        let mut frames = std::pin::pin!(frames);
        while let Some(frame) = frames.next().await {
            let event = frame.map(|data| journal.publish(Some(data)).into_event());
            if let Some(output) = &sender
                && !matches!(
                    tokio::time::timeout(Duration::from_secs(5), output.send(event)).await,
                    Ok(Ok(()))
                )
            {
                sender = None;
            }
        }
        journal.finish();
    });
    stream::unfold((receiver, guard), |(mut receiver, guard)| async move {
        receiver
            .recv()
            .await
            .map(|event| (event, (receiver, guard)))
    })
}

fn post_sse(
    events: impl futures_util::Stream<Item = Result<Event, std::io::Error>> + Send + 'static,
    prefix: Option<Bytes>,
) -> Response {
    let response = (
        [
            (CACHE_CONTROL, "no-cache, no-transform"),
            (
                axum::http::HeaderName::from_static("x-accel-buffering"),
                "no",
            ),
        ],
        Sse::new(events).keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("ping"),
        ),
    )
        .into_response();
    let Some(prefix) = prefix else {
        return response;
    };
    let (parts, body) = response.into_parts();
    let frames = stream::iter([Ok(prefix)]).chain(body.into_data_stream());
    Response::from_parts(parts, Body::from_stream(frames))
}

fn progress_frame(progress: ProgressNotificationParam) -> ReplyFrame {
    let notification =
        ServerJsonRpcMessage::notification(ProgressNotification::new(progress).into());
    serde_json::to_string(&notification)
        .map(Arc::from)
        .map_err(std::io::Error::other)
}

async fn list_tools(
    service: &GatewayService,
    principal: Option<&Principal>,
    server: Option<&CatalogServer>,
    id: &Value,
    params: Option<&Value>,
) -> Response {
    let cursor = match params.map(PaginatedRequestParams::deserialize) {
        None => None,
        Some(Ok(params)) => params.cursor,
        Some(Err(_)) => return invalid_params(id),
    };
    match service
        .list_tools(principal, server, cursor.as_deref())
        .await
    {
        Ok(page) => rpc_success(id, page),
        Err(error) => tool_error(id, error),
    }
}

async fn list_catalog_metadata(
    service: &GatewayService,
    list: CatalogList,
    principal: Option<&Principal>,
    server: Option<&CatalogServer>,
    id: &Value,
    params: Option<&Value>,
) -> Response {
    let cursor = match params.map(PaginatedRequestParams::deserialize) {
        None => None,
        Some(Ok(params)) => params.cursor,
        Some(Err(_)) => return invalid_params(id),
    };
    match service
        .list_catalog_metadata(list, principal, server, cursor.as_deref())
        .await
    {
        Ok(result) => rpc_success(id, result),
        Err(error) => tool_error(id, error),
    }
}

async fn call_tool(
    service: &GatewayService,
    principal: Option<&Principal>,
    server: Option<&CatalogServer>,
    session: Option<Arc<Session>>,
    id: &Value,
    params: Option<&Value>,
    progress: Option<&ToolProgress>,
) -> Response {
    let Some(Ok(params)) = params.map(CallToolRequestParams::deserialize) else {
        return invalid_params(id);
    };
    if params.input_responses.is_some() || params.request_state.is_some() {
        return invalid_params(id);
    }
    let pending = match track_request(session.as_ref(), id) {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    let cancellation = pending
        .as_ref()
        .map(|pending| pending.token.clone())
        .unwrap_or_default();
    let result = service
        .call_tool(
            principal,
            server,
            params,
            ToolContext {
                cancellation: &cancellation,
                progress,
                notifications: None,
                client_capabilities: None,
            },
            session.as_deref(),
        )
        .await;
    if cancellation.is_cancelled() {
        return tool_error(id, ToolError::Cancelled);
    }
    match result {
        Ok(result) => rpc_success(id, result),
        Err(error) => tool_error(id, error),
    }
}

fn track_request(
    session: Option<&Arc<Session>>,
    id: &Value,
) -> Result<Option<PendingRequest>, Box<Response>> {
    let Some(session) = session else {
        return Ok(None);
    };
    let request_id = RequestId::deserialize(id).map_err(|_| Box::new(invalid_envelope()))?;
    match session.clone().track(request_id) {
        Ok(pending) => Ok(Some(pending)),
        Err(PendingError::DuplicateId) => Err(Box::new(rpc_error(
            StatusCode::OK,
            id,
            INVALID_REQUEST,
            "Request ID already in use",
            None::<()>,
        ))),
        Err(PendingError::Capacity) => Err(Box::new(rpc_error(
            StatusCode::SERVICE_UNAVAILABLE,
            id,
            INVALID_REQUEST,
            "Too many in-flight requests",
            None::<()>,
        ))),
    }
}

fn content_error(id: &Value, error: ErrorData) -> Response {
    rpc_error(StatusCode::OK, id, error.code.0, &error.message, error.data)
}

#[allow(deprecated)]
async fn set_log_level(
    service: &GatewayService,
    principal: Option<&Principal>,
    server: Option<&CatalogServer>,
    id: &Value,
    params: Option<&Value>,
) -> Response {
    let Some(Ok(params)) = params.map(rmcp::model::SetLevelRequestParams::deserialize) else {
        return invalid_params(id);
    };
    match service.set_log_level(params.level, principal, server).await {
        Ok(()) => rpc_success(id, Empty {}),
        Err(error) => content_error(id, error),
    }
}

fn cancel_request(session: &Session, params: Option<&Value>) -> Response {
    let Some(Ok(params)) = params.map(CancelledNotificationParam::deserialize) else {
        return invalid_envelope();
    };
    if let Some(id) = params.request_id {
        session.cancel_request(&id);
    }
    accepted()
}

fn invalid_params(id: &Value) -> Response {
    rpc_error(
        StatusCode::OK,
        id,
        INVALID_PARAMS,
        "Invalid request parameters",
        Some(""),
    )
}

fn tool_error(id: &Value, error: ToolError) -> Response {
    let (code, message) = match error {
        ToolError::Denied => (0, "Access denied"),
        ToolError::NotFound => (0, "Unknown tool"),
        ToolError::Cursor => (INVALID_PARAMS, "Invalid cursor"),
        ToolError::Unavailable => (0, "Tool service unavailable"),
        ToolError::Cancelled => (REQUEST_CANCELLED, "Request cancelled"),
        ToolError::Database(error) => {
            tracing::error!(%error, "MCP tool database operation failed");
            (0, "Tool service unavailable")
        }
    };
    rpc_error(StatusCode::OK, id, code, message, None::<()>)
}

#[allow(deprecated)]
fn initialize(params: Option<&Value>, server: Option<&CatalogServer>) -> Option<InitializeResult> {
    let params = InitializeRequestParams::deserialize(params?).ok()?;
    let protocol_version = if LEGACY_VERSIONS.contains(&params.protocol_version.as_str()) {
        params.protocol_version
    } else {
        ProtocolVersion::LATEST_WITH_INITIALIZE
    };
    let mut capabilities = catalog_capabilities();
    capabilities.logging = Some(Default::default());
    let mut result = InitializeResult::new(capabilities)
        .with_protocol_version(protocol_version)
        .with_server_info(Implementation::new(
            "ContextForge",
            env!("CARGO_PKG_VERSION"),
        ));
    result.instructions = match server {
        Some(server) => server.instructions.clone(),
        None => Some(ROOT_INSTRUCTIONS.to_owned()),
    };
    Some(result)
}

pub(crate) fn catalog_capabilities() -> ServerCapabilities {
    let mut capabilities = ServerCapabilities::default();
    capabilities.completions = Some(Default::default());
    let mut tools = ToolsCapability::default();
    tools.list_changed = Some(false);
    capabilities.tools = Some(tools);
    let mut prompts = PromptsCapability::default();
    prompts.list_changed = Some(false);
    capabilities.prompts = Some(prompts);
    let mut resources = ResourcesCapability::default();
    resources.list_changed = Some(false);
    resources.subscribe = Some(false);
    capabilities.resources = Some(resources);
    capabilities
}

pub(crate) fn catalog_event_capabilities() -> ServerCapabilities {
    let mut capabilities = catalog_capabilities();
    if let Some(tools) = &mut capabilities.tools {
        tools.list_changed = Some(true);
    }
    if let Some(prompts) = &mut capabilities.prompts {
        prompts.list_changed = Some(true);
    }
    if let Some(resources) = &mut capabilities.resources {
        resources.list_changed = Some(true);
        resources.subscribe = Some(true);
    }
    capabilities
}

pub(crate) async fn legacy_transport_reply(
    service: &Arc<GatewayService>,
    principal: Option<&Principal>,
    server: Option<&CatalogServer>,
    mut request: Value,
) -> Option<Value> {
    let method = request["method"].as_str()?;
    let id = request.get("id")?.clone();
    if !(id.is_i64() || id.is_u64() || id.is_string()) {
        return None;
    }
    if method == "initialize" {
        let params = &request["params"];
        let protocol_version = params["protocol_version"]
            .as_str()
            .or_else(|| params["protocolVersion"].as_str());
        let result = protocol_version.filter(|version| !version.is_empty()).map(|version| {
            let capabilities = legacy_transport_capabilities(version);
            json!({
                "protocolVersion":version,
                "capabilities":capabilities,
                "serverInfo":Implementation::new("ContextForge",env!("CARGO_PKG_VERSION")),
                "instructions":server.and_then(|server| server.instructions.as_deref()).unwrap_or(ROOT_INSTRUCTIONS),
            })
        });
        return Some(match result {
            Some(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
            None => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32002,"message":"Missing protocol version","data":{}}})
            }
        });
    }
    request["jsonrpc"] = json!("2.0");
    let state = McpState {
        service: service.clone(),
        sessions: None,
        modern: None,
        json_response: true,
    };
    let reply = dispatch(
        &state,
        principal.cloned(),
        server.cloned(),
        None,
        request,
        false,
    )
    .await;
    let payload = match to_bytes(reply.into_body(), MAX_REQUEST_BODY_BYTES * 2).await {
        Ok(body) => serde_json::from_slice::<Value>(&body).ok(),
        Err(_) => None,
    };
    Some(payload.filter(|payload| payload["jsonrpc"] == "2.0").unwrap_or_else(|| {
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32600,"message":"Invalid Request"}})
    }))
}

#[allow(deprecated)]
fn legacy_transport_capabilities(version: &str) -> ServerCapabilities {
    let mut capabilities = catalog_event_capabilities();
    if version != MODERN_VERSION {
        capabilities.logging = Some(Default::default());
    }
    capabilities
}

fn with_session(mut response: Response, id: Option<&HeaderValue>) -> Response {
    if let Some(id) = id {
        response.headers_mut().insert(SESSION_HEADER, id.clone());
    }
    response
}

fn session_header(headers: &HeaderMap) -> Result<Option<&HeaderValue>, SessionError> {
    let mut values = headers.get_all(SESSION_HEADER).iter();
    let id = values.next();
    if values.next().is_some() {
        return Err(SessionError::InvalidHeader);
    }
    Ok(id.filter(|value| !value.is_empty()))
}

fn post_session_error(error: SessionError) -> Response {
    if matches!(error, SessionError::NotFound | SessionError::Remote(_)) {
        return transport_error(StatusCode::NOT_FOUND, "Session not found");
    }
    session_error(error)
}

fn session_error(error: SessionError) -> Response {
    let (status, detail) = match error {
        SessionError::Missing => {
            let response =
                transport_error(StatusCode::BAD_REQUEST, "Bad Request: Missing session ID");
            return with_session(response, Some(&new_session_id()));
        }
        SessionError::InvalidHeader => {
            return transport_error(StatusCode::BAD_REQUEST, "Bad Request: Invalid session ID");
        }
        SessionError::NotFound => (StatusCode::NOT_FOUND, "Session not found"),
        SessionError::Forbidden => (StatusCode::FORBIDDEN, "Session access denied"),
        SessionError::Capacity => (StatusCode::SERVICE_UNAVAILABLE, "Session capacity reached"),
        SessionError::Remote(_) => (StatusCode::NOT_FOUND, "Session not found"),
        SessionError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Session ownership unavailable",
        ),
    };
    (status, Json(Detail { detail })).into_response()
}

#[derive(Serialize)]
struct Empty {}

#[derive(Serialize)]
struct Detail {
    detail: &'static str,
}

#[derive(Serialize)]
struct VersionError<'a> {
    supported: &'static [&'static str],
    requested: &'a str,
}

fn accepted() -> Response {
    (StatusCode::ACCEPTED, [(CONTENT_TYPE, JSON_MEDIA_TYPE)]).into_response()
}

fn invalid_envelope() -> Response {
    rpc_error(
        StatusCode::BAD_REQUEST,
        &Value::Null,
        INVALID_PARAMS,
        "Validation error: expected a valid JSON-RPC message",
        None::<()>,
    )
}

fn transport_error(status: StatusCode, message: &'static str) -> Response {
    rpc_error(status, &Value::Null, INVALID_REQUEST, message, None::<()>)
}

#[derive(Serialize)]
struct RpcSuccess<'a, T> {
    jsonrpc: &'static str,
    id: &'a Value,
    result: T,
}

fn rpc_success(id: &Value, result: impl Serialize) -> Response {
    Json(RpcSuccess {
        jsonrpc: "2.0",
        id,
        result,
    })
    .into_response()
}

#[derive(Serialize)]
struct RpcError<'a, T> {
    jsonrpc: &'static str,
    id: &'a Value,
    error: RpcErrorDetails<'a, T>,
}

#[derive(Serialize)]
struct RpcErrorDetails<'a, T> {
    code: i32,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
}

pub(crate) fn rpc_error(
    status: StatusCode,
    id: &Value,
    code: i32,
    message: &str,
    data: Option<impl Serialize>,
) -> Response {
    (
        status,
        Json(RpcError {
            jsonrpc: "2.0",
            id,
            error: RpcErrorDetails {
                code,
                message,
                data,
            },
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use serde_json::json;
    use std::time::Duration;
    use tower::ServiceExt;

    use super::*;
    use crate::{access::Authorizer, config::Settings, database::Database, gateway::test_service};

    fn test_router() -> Router {
        let database = Database::from_settings(&Settings {
            host: "127.0.0.1".into(),
            port: 4444,
            database_url: "sqlite:///:memory:".into(),
            db_pool_size: 1,
            db_pool_timeout: Duration::from_secs(1),
            sqlite_busy_timeout: Duration::from_secs(5),
            redis: None,
        })
        .unwrap();
        let auth = Authorizer::new(database.clone(), None, true);
        router(
            test_service(database, auth),
            ProtocolMode::Legacy,
            HttpOptions::default(),
            false,
        )
    }

    async fn request(
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        payload: &str,
    ) -> (StatusCode, HeaderMap, Bytes) {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = test_router()
            .oneshot(request.body(Body::from(payload.to_owned())).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let data = to_bytes(body, 8192).await.unwrap();
        (parts.status, parts.headers, data)
    }

    const JSON_HEADERS: [(&str, &str); 2] = [
        ("accept", "application/json, text/event-stream"),
        ("content-type", "application/json"),
    ];

    #[tokio::test]
    async fn configured_ingress_allowlists_cover_both_mcp_paths() {
        let app = IngressPolicy {
            origins: ["https://console.example.test".into()].into(),
            hosts: ["gateway.example.test:8443".into()].into(),
        }
        .apply(test_router());

        for path in ["/mcp", "/mcp/"] {
            for (origin, host, status, detail) in [
                (
                    Some("https://console.example.test"),
                    "gateway.example.test:8443",
                    StatusCode::OK,
                    None,
                ),
                (None, "127.0.0.1:4444", StatusCode::OK, None),
                (None, "[::1]:4444", StatusCode::OK, None),
                (
                    Some("https://other.example.test"),
                    "gateway.example.test:8443",
                    StatusCode::FORBIDDEN,
                    Some("Forbidden: Origin not allowed"),
                ),
                (
                    None,
                    "gateway.example.test",
                    StatusCode::FORBIDDEN,
                    Some("Forbidden: Host not allowed"),
                ),
            ] {
                let mut request = Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(HOST, host);
                if let Some(origin) = origin {
                    request = request.header(ORIGIN, origin);
                }
                for (name, value) in JSON_HEADERS {
                    request = request.header(name, value);
                }
                let request = request
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                    .unwrap();
                let response = app.clone().oneshot(request).await.unwrap();
                assert_eq!(response.status(), status);
                if let Some(detail) = detail {
                    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
                    assert_eq!(
                        serde_json::from_slice::<Value>(&bytes).unwrap(),
                        json!({"detail":detail})
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn initialize_negotiates_supported_versions_and_counters_unknown_offers() {
        for (path, requested, expected) in [
            ("/mcp", "2024-11-05", "2024-11-05"),
            ("/mcp/", "2025-11-25", "2025-11-25"),
            ("/mcp/", "2026-07-28", "2025-11-25"),
            ("/mcp/", "2099-01-01", "2025-11-25"),
        ] {
            let payload = json!({
                "jsonrpc": "2.0",
                "id": "initialize-1",
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": { "name": "wire-test", "version": "0.1" },
                    "protocolVersion": requested
                }
            });
            let (status, headers, data) =
                request(Method::POST, path, &JSON_HEADERS, &payload.to_string()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(headers[CONTENT_TYPE], JSON_MEDIA_TYPE);
            assert_eq!(headers[VARY], "Origin");
            assert_eq!(headers[RUNTIME_HEADER], "rust");
            assert!(!headers.contains_key("mcp-session-id"));
            let data: Value = serde_json::from_slice(&data).unwrap();
            assert_eq!(
                data,
                json!({
                    "jsonrpc": "2.0",
                    "id": "initialize-1",
                    "result": {
                        "protocolVersion": expected,
                        "capabilities": {"completions": {}, "logging": {}, "tools": {"listChanged": false}, "prompts": {"listChanged": false},
                            "resources": {"listChanged": false, "subscribe": false}},
                        "serverInfo": { "name": "ContextForge", "version": env!("CARGO_PKG_VERSION") },
                        "instructions": ROOT_INSTRUCTIONS,
                    }
                })
            );
        }
    }

    #[tokio::test]
    async fn ping_and_initialized_notification_are_stateless() {
        let mut headers = JSON_HEADERS.to_vec();
        headers.push((PROTOCOL_VERSION_HEADER, "2025-11-25"));
        let (status, response_headers, data) = request(
            Method::POST,
            "/mcp/",
            &headers,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(response_headers[CONTENT_TYPE], JSON_MEDIA_TYPE);
        assert!(data.is_empty());

        let (status, _, data) = request(
            Method::POST,
            "/mcp/",
            &headers,
            r#"{"jsonrpc":"2.0","method":"ping","id":4}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(data, r#"{"jsonrpc":"2.0","id":4,"result":{}}"#);
    }

    #[tokio::test]
    async fn reports_invalid_initialize_params_and_unknown_methods() {
        let (status, _, data) = request(
            Method::POST,
            "/mcp/",
            &JSON_HEADERS,
            r#"{"jsonrpc":"2.0","id":5,"method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"c","version":"1"}}}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            data,
            r#"{"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"Invalid request parameters","data":""}}"#
        );

        let (status, _, data) = request(
            Method::POST,
            "/mcp/",
            &JSON_HEADERS,
            r#"{"jsonrpc":"2.0","id":6,"method":"fixture/missing"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            data,
            r#"{"jsonrpc":"2.0","id":6,"error":{"code":-32601,"message":"Method not found","data":"fixture/missing"}}"#
        );
    }

    #[tokio::test]
    async fn rejects_unsupported_version_before_dispatch() {
        let (status, headers, data) = request(
            Method::POST,
            "/mcp/",
            &[(PROTOCOL_VERSION_HEADER, "2026-07-28")],
            r#"{"jsonrpc":"2.0","method":"ping","id":8}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(headers[CONTENT_TYPE], JSON_MEDIA_TYPE);
        assert_eq!(
            data,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2024-11-05","2025-03-26","2025-06-18","2025-11-25"],"requested":"2026-07-28"}}}"#
        );
    }

    #[tokio::test]
    async fn rejects_unsupported_http_methods_and_return_formats() {
        let (status, headers, data) = request(Method::GET, "/mcp/", &[], "").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers[ALLOW], "POST, DELETE");
        assert_eq!(
            data,
            r#"{"detail":"Stateful sessions disabled on this gateway; passive SSE stream is not available."}"#
        );

        let (status, headers, data) = request(Method::DELETE, "/mcp/", &[], "").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(!headers.contains_key(ALLOW));
        assert_eq!(
            data,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Method Not Allowed: Session termination not supported"}}"#
        );

        let (status, headers, _) = request(Method::PUT, "/mcp/", &[], "").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers[ALLOW], "GET, POST, DELETE");

        let (status, headers, data) = request(Method::HEAD, "/mcp/", &[], "").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers[ALLOW], "GET, POST, DELETE");
        assert!(data.is_empty());

        let (status, _, data) = request(
            Method::POST,
            "/mcp/",
            &[
                ("accept", "text/event-stream"),
                ("content-type", JSON_MEDIA_TYPE),
            ],
            r#"{"jsonrpc":"2.0","method":"ping","id":4}"#,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            data,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Not Acceptable: Client must accept application/json"}}"#
        );

        let (status, _, _) = request(
            Method::POST,
            "/mcp/",
            &[("accept", "*/*"), ("content-type", "Application/JSON")],
            r#"{"jsonrpc":"2.0","method":"ping","id":4}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn rejects_invalid_content_type_oversized_requests_and_malformed_json() {
        let (status, headers, data) = request(
            Method::POST,
            "/mcp/",
            &[
                ("accept", "application/json"),
                ("content-type", "text/plain"),
            ],
            "{}",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!headers.contains_key(CONTENT_TYPE));
        assert_eq!(data, "Invalid Content-Type header");

        let (status, _, data) =
            request(Method::POST, "/mcp/", &JSON_HEADERS, r#"{"jsonrpc":"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let data: Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(data["error"]["code"], PARSE_ERROR);

        let (status, _, data) = request(
            Method::POST,
            "/mcp/",
            &JSON_HEADERS,
            r#"{"jsonrpc":"2.0","method":"ping","id":true}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let data: Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(data["error"]["code"], INVALID_PARAMS);

        for path in ["/mcp", "/mcp/"] {
            let oversized = " ".repeat(MAX_REQUEST_BODY_BYTES + 1);
            let (status, _, data) = request(Method::POST, path, &JSON_HEADERS, &oversized).await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(data, "Request body too large");
        }
    }
}
