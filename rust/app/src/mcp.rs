// SPDX-License-Identifier: Apache-2.0
//! Legacy stateless MCP Streamable HTTP.

use std::{collections::HashSet, sync::Arc};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{ACCEPT, ALLOW, CONTENT_TYPE, HOST, ORIGIN, VARY},
        uri::Authority,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
};
use rmcp::model::{
    CallToolRequestParams, Implementation, InitializeRequestParams, InitializeResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ToolsCapability,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    access::Principal,
    catalog::CatalogServer,
    gateway::{GatewayService, ToolError},
};

const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const RUNTIME_HEADER: &str = "x-contextforge-mcp-runtime";
const LEGACY_VERSIONS: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
const JSON_MEDIA_TYPE: &str = "application/json";
const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;

/// Build the root Streamable HTTP routes for mounting behind gateway access checks.
pub fn router(service: Arc<GatewayService>) -> Router {
    Router::new()
        .route("/mcp", any(handle_request))
        .route("/mcp/", any(handle_request))
        .route("/servers/{server_id}/mcp", any(handle_request))
        .route("/servers/{server_id}/mcp/", any(handle_request))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(service)
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

async fn handle_request(State(service): State<Arc<GatewayService>>, request: Request) -> Response {
    if let Some(version) = request.headers().get(PROTOCOL_VERSION_HEADER)
        && !version
            .to_str()
            .is_ok_and(|version| LEGACY_VERSIONS.contains(&version))
    {
        let requested: String = version.as_bytes().iter().copied().map(char::from).collect();
        return rpc_error(
            StatusCode::BAD_REQUEST,
            &Value::Null,
            UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            Some(VersionError {
                supported: LEGACY_VERSIONS,
                requested: &requested,
            }),
        );
    }

    let is_head = request.method() == Method::HEAD;
    let mut response = match *request.method() {
        Method::GET => (
            StatusCode::METHOD_NOT_ALLOWED,
            [(ALLOW, "POST, DELETE")],
            Json(Detail {
                detail: "Stateful sessions disabled on this gateway; passive SSE stream is not available.",
            }),
        )
            .into_response(),
        Method::POST => handle_post(&service, request).await,
        Method::DELETE => transport_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed: Session termination not supported",
        ),
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

async fn handle_post(service: &GatewayService, mut request: Request) -> Response {
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
    if !accepts_json(request.headers()) {
        return transport_error(
            StatusCode::NOT_ACCEPTABLE,
            "Not Acceptable: Client must accept application/json",
        );
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

    let principal = request.extensions_mut().remove::<Principal>();
    let server = request.extensions_mut().remove::<CatalogServer>();
    let bytes = match Bytes::from_request(request, &()).await {
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
        Ok(value) => dispatch(service, principal.as_ref(), server.as_ref(), &value).await,
        Err(error) => rpc_error(
            StatusCode::BAD_REQUEST,
            &Value::Null,
            PARSE_ERROR,
            &format!("Parse error: {error}"),
            None::<()>,
        ),
    }
}

fn accepts_json(headers: &HeaderMap) -> bool {
    headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(','))
        .filter_map(|entry| entry.split(';').next())
        .map(str::trim)
        .any(|media_type| {
            media_type == "*/*"
                || media_type.eq_ignore_ascii_case("application/*")
                || media_type.eq_ignore_ascii_case(JSON_MEDIA_TYPE)
        })
}

async fn dispatch(
    service: &GatewayService,
    principal: Option<&Principal>,
    server: Option<&CatalogServer>,
    value: &Value,
) -> Response {
    let Some(message) = value.as_object() else {
        return invalid_envelope();
    };
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return invalid_envelope();
    }
    let id = message.get("id");
    if id.is_some_and(|id| !(id.is_string() || id.is_i64() || id.is_u64())) {
        return invalid_envelope();
    }

    if let Some(method) = message.get("method") {
        let Some(method) = method.as_str() else {
            return invalid_envelope();
        };
        let params = match message.get("params") {
            None | Some(Value::Null) => None,
            Some(params @ Value::Object(_)) => Some(params),
            Some(_) => return invalid_envelope(),
        };
        return match (id, method) {
            (None, _) => accepted(),
            (Some(id), "initialize") => initialize(id, params),
            (Some(id), "ping") => rpc_success(id, Empty {}),
            (Some(id), "tools/list") => list_tools(service, principal, server, id, params).await,
            (Some(id), "tools/call") => call_tool(service, principal, server, id, params).await,
            (Some(id), method) => rpc_error(
                StatusCode::OK,
                id,
                METHOD_NOT_FOUND,
                "Method not found",
                Some(method),
            ),
        };
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
        return accepted();
    }

    invalid_envelope()
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

async fn call_tool(
    service: &GatewayService,
    principal: Option<&Principal>,
    server: Option<&CatalogServer>,
    id: &Value,
    params: Option<&Value>,
) -> Response {
    let Some(Ok(params)) = params.map(CallToolRequestParams::deserialize) else {
        return invalid_params(id);
    };
    if params.input_responses.is_some() || params.request_state.is_some() {
        return invalid_params(id);
    }
    let arguments = Value::Object(params.arguments.unwrap_or_default());
    match service
        .call_tool(principal, server, &params.name, arguments)
        .await
    {
        Ok(result) => rpc_success(id, result),
        Err(error) => tool_error(id, error),
    }
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
        ToolError::Database(error) => {
            tracing::error!(%error, "MCP tool database operation failed");
            (0, "Tool service unavailable")
        }
    };
    rpc_error(StatusCode::OK, id, code, message, None::<()>)
}

fn initialize(id: &Value, params: Option<&Value>) -> Response {
    let Some(Ok(params)) = params.map(InitializeRequestParams::deserialize) else {
        return invalid_params(id);
    };
    let protocol_version = if LEGACY_VERSIONS.contains(&params.protocol_version.as_str()) {
        params.protocol_version
    } else {
        ProtocolVersion::LATEST_WITH_INITIALIZE
    };
    let mut capabilities = ServerCapabilities::default();
    let mut tools = ToolsCapability::default();
    tools.list_changed = Some(false);
    capabilities.tools = Some(tools);
    rpc_success(
        id,
        InitializeResult::new(capabilities)
            .with_protocol_version(protocol_version)
            .with_server_info(Implementation::new(
                "ContextForge",
                env!("CARGO_PKG_VERSION"),
            )),
    )
}

#[derive(Serialize)]
struct Empty {}

#[derive(Serialize)]
struct Detail {
    detail: &'static str,
}

#[derive(Serialize)]
struct VersionError<'a> {
    supported: [&'static str; 4],
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

fn rpc_error(
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
        router(test_service(database, auth))
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
                        "capabilities": {"tools": {"listChanged": false}},
                        "serverInfo": { "name": "ContextForge", "version": env!("CARGO_PKG_VERSION") }
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
