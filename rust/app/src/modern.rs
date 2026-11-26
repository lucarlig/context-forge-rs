// SPDX-License-Identifier: Apache-2.0
//! Modern stateless MCP Streamable HTTP.

use std::{borrow::Cow, sync::Arc};

use axum::{
    body::{Body, Bytes, to_bytes},
    extract::{FromRequest, Request},
    http::{
        HeaderValue, Method, StatusCode,
        header::{ACCEPT, ALLOW, CONTENT_TYPE},
        request::Parts,
    },
    response::{IntoResponse, Response},
};
use rmcp::{
    RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ClientJsonRpcMessage,
        ClientRequest, ContentBlock, CustomRequest, CustomResult, DiscoverResult, ErrorCode,
        ErrorData, Implementation, InitializeRequestParams, InitializeResult, JsonRpcError,
        ListToolsResult, MetaObject, PaginatedRequestParams, ProgressNotification,
        ProgressNotificationParam, ProtocolVersion, ResultType, ServerCapabilities, ServerConfig,
        Tool, ToolsCapability,
    },
    service::RequestContext,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    access::Principal,
    catalog::{CatalogServer, ToolDefinition},
    gateway::{GatewayService, ToolError},
    mcp::{
        JSON_MEDIA_TYPE, MAX_REQUEST_BODY_BYTES, accepts_event_stream, accepts_json,
        accepts_post_stream, rpc_error,
    },
    modern_validation::reject_invalid_request,
    upstream::{ToolContext, ToolProgress},
};

const ROOT_INSTRUCTIONS: &str =
    "ContextForge provides federated tools. Register MCP servers through /v1/mcp-servers.";
const SERVER_INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";
const MODERN_VERSIONS: &[ProtocolVersion] = &[ProtocolVersion::V_2026_07_28];

type Transport = StreamableHttpService<GatewayHandler, NeverSessionManager>;

#[derive(Clone)]
struct AcceptsProgress;

#[derive(Clone)]
pub struct Modern {
    gateway: Arc<GatewayService>,
    transport: Transport,
    json_response: bool,
}

impl Modern {
    /// Build the modern Streamable HTTP service for use behind the gateway ingress.
    pub fn new(gateway: Arc<GatewayService>, json_response: bool) -> Self {
        let config = StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_stateless_protocol_metadata_required(true)
            .with_max_request_body_bytes(MAX_REQUEST_BODY_BYTES)
            .disable_allowed_hosts();
        Self {
            transport: transport(gateway.clone(), None, config),
            gateway,
            json_response,
        }
    }

    /// Handle a request with authorization and virtual-server context attached by Axum.
    pub async fn handle(&self, mut request: Request) -> Response {
        if request.method() != Method::POST {
            return (StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, "POST")]).into_response();
        }

        let content_type = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
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
        if !accepts_json(request.headers())
            || (!self.json_response && !accepts_post_stream(request.headers()))
        {
            return StatusCode::NOT_ACCEPTABLE.into_response();
        }
        if accepts_event_stream(request.headers()) {
            request.extensions_mut().insert(AcceptsProgress);
        }

        // The SDK requires both Accept types even when JSON mode is enabled.
        // ContextForge's JSON mode also accepts a JSON-only preference.
        request.headers_mut().insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );

        let (parts, body) = request.into_parts();
        let bytes = match Bytes::from_request(Request::from_parts(parts.clone(), body), &()).await {
            Ok(bytes) => bytes,
            Err(error) => return error.into_response(),
        };
        let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
            return rpc_error(
                StatusCode::BAD_REQUEST,
                &Value::Null,
                -32700,
                "Parse error",
                None::<()>,
            );
        };
        if let Some(response) = reject_invalid_request(&parts.headers, &body) {
            return response;
        }
        let scoped_tool =
            if parts.headers.get("mcp-method") == Some(&HeaderValue::from_static("tools/call")) {
                match self.tool_for_headers(&parts, &body).await {
                    Ok(tool) => tool,
                    Err(error) => return error.into_response(),
                }
            } else {
                None
            };
        let request = Request::from_parts(parts, Body::from(bytes));
        let Some(tool) = scoped_tool else {
            return handle(&self.transport, request).await;
        };

        // The SDK looks up the tool schema before dispatch, without a request context.
        // Supply only a definition resolved for this authorized request.
        let transport = transport(
            self.gateway.clone(),
            Some(tool),
            self.transport.config.clone(),
        );
        handle(&transport, request).await
    }

    async fn tool_for_headers(
        &self,
        parts: &Parts,
        body: &Value,
    ) -> Result<Option<Tool>, StatusCode> {
        let Ok(ClientJsonRpcMessage::Request(message)) = ClientJsonRpcMessage::deserialize(body)
        else {
            return Ok(None);
        };
        let ClientRequest::CallToolRequest(call) = message.request else {
            return Ok(None);
        };
        match self
            .gateway
            .tool_definition(
                parts.extensions.get::<Principal>(),
                parts.extensions.get::<CatalogServer>(),
                &call.params.name,
            )
            .await
        {
            Ok(Some(definition)) => protocol_tool(definition)
                .map(Some)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR),
            Ok(None) | Err(ToolError::Denied | ToolError::NotFound) => Ok(None),
            Err(error) => {
                tracing::error!(%error, "MCP tool schema lookup failed");
                Err(StatusCode::SERVICE_UNAVAILABLE)
            }
        }
    }
}

async fn handle(transport: &Transport, request: Request) -> Response {
    let response = transport.handle(request).await.into_response();
    if !matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST
    ) || response.headers().get(CONTENT_TYPE) != Some(&HeaderValue::from_static(JSON_MEDIA_TYPE))
    {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let Ok(body) = to_bytes(body, MAX_REQUEST_BODY_BYTES).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(mut reply) = serde_json::from_slice::<JsonRpcError>(&body) else {
        return Response::from_parts(parts, Body::from(body));
    };
    match reply.error.code {
        ErrorCode::METHOD_NOT_FOUND if reply.error.data.is_none() => {
            reply.error = method_not_found(reply.error.message.into_owned());
        }
        ErrorCode::PARSE_ERROR => reply.error.message = Cow::Borrowed("Parse error"),
        _ => return Response::from_parts(parts, Body::from(body)),
    }
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    Response::from_parts(
        parts,
        Body::from(serde_json::to_vec(&reply).expect("serialize JSON-RPC error")),
    )
}

fn transport(
    gateway: Arc<GatewayService>,
    scoped_tool: Option<Tool>,
    config: StreamableHttpServerConfig,
) -> Transport {
    StreamableHttpService::new(
        move || {
            Ok(GatewayHandler {
                gateway: gateway.clone(),
                scoped_tool: scoped_tool.clone(),
            })
        },
        Arc::new(NeverSessionManager::default()),
        config,
    )
}

struct GatewayHandler {
    gateway: Arc<GatewayService>,
    scoped_tool: Option<Tool>,
}

impl ServerHandler for GatewayHandler {
    fn get_info(&self) -> ServerConfig {
        let mut capabilities = ServerCapabilities::default();
        let mut tools = ToolsCapability::default();
        tools.list_changed = Some(false);
        capabilities.tools = Some(tools);
        ServerConfig::new(capabilities)
            .with_server_info(implementation())
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(MODERN_VERSIONS)
    }

    fn negotiate_initialize(
        &self,
        _request: &InitializeRequestParams,
    ) -> Result<InitializeResult, ErrorData> {
        Err(method_not_found("initialize"))
    }

    async fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        let parts = request_parts(&context)?;
        let server = parts.extensions.get::<CatalogServer>();
        let mut result =
            DiscoverResult::from_server_info(MODERN_VERSIONS.to_vec(), self.get_info());
        result.ttl_ms = self.gateway.catalog_ttl_ms(server).await;
        result.instructions = match server {
            Some(server) => server.instructions.clone(),
            None => Some(ROOT_INSTRUCTIONS.to_owned()),
        };
        Ok(result)
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let parts = request_parts(&context)?;
        let server = parts.extensions.get::<CatalogServer>();
        let page = self
            .gateway
            .list_tools(
                parts.extensions.get::<Principal>(),
                server,
                request.as_ref().and_then(|params| params.cursor.as_deref()),
            )
            .await
            .map_err(tool_error)?;
        let tools = page
            .tools
            .into_iter()
            .map(protocol_tool)
            .collect::<Result<Vec<_>, _>>()?;
        let mut result = ListToolsResult::with_all_items(tools)
            .with_ttl_ms(self.gateway.catalog_ttl_ms(server).await);
        result.next_cursor = page.next_cursor;
        stamp_server_info(&mut result.meta);
        Ok(result)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let parts = request_parts(&context)?;
        if request.input_responses.is_some() || request.request_state.is_some() {
            return Err(ErrorData::invalid_params(
                "Tool input responses are unsupported",
                None,
            ));
        }
        let progress = parts
            .extensions
            .get::<AcceptsProgress>()
            .and_then(|_| context.meta.get_progress_token())
            .map(ToolProgress::channel);
        let (relay, updates) = match progress {
            Some((relay, updates)) => (Some(relay), Some(updates)),
            None => (None, None),
        };
        let invocation = self.gateway.call_tool(
            parts.extensions.get::<Principal>(),
            parts.extensions.get::<CatalogServer>(),
            &request.name,
            Value::Object(request.arguments.unwrap_or_default()),
            ToolContext {
                cancellation: &context.ct,
                progress: relay.as_ref(),
                notifications: None,
            },
            None,
        );
        let mut result = match with_progress(invocation, updates, &context).await {
            Ok(value) => serde_json::from_value::<CallToolResult>(value)
                .map_err(|_| ErrorData::internal_error("Invalid upstream tool result", None))?,
            Err(ToolError::NotFound) => CallToolResult::error(vec![ContentBlock::text(format!(
                "Unknown tool: {}",
                request.name
            ))]),
            Err(error) => return Err(tool_error(error)),
        };
        result.result_type = Some(ResultType::COMPLETE);
        stamp_server_info(&mut result.meta);
        Ok(CallToolResponse::Complete(result))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.scoped_tool
            .as_ref()
            .filter(|tool| tool.name == name)
            .cloned()
    }

    async fn on_custom_request(
        &self,
        request: CustomRequest,
        _context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, ErrorData> {
        Err(method_not_found(request.method))
    }
}

async fn with_progress(
    invocation: impl Future<Output = Result<Value, ToolError>>,
    updates: Option<tokio::sync::mpsc::Receiver<ProgressNotificationParam>>,
    context: &RequestContext<RoleServer>,
) -> Result<Value, ToolError> {
    let Some(mut updates) = updates else {
        return invocation.await;
    };
    let mut invocation = std::pin::pin!(invocation);
    let result = loop {
        tokio::select! {
            biased;
            update = updates.recv() => {
                let Some(update) = update else {
                    return invocation.await;
                };
                if !send_progress(context, update).await {
                    drop(updates);
                    return invocation.await;
                }
            }
            result = &mut invocation => break result,
        }
    };
    while let Ok(update) = updates.try_recv() {
        if !send_progress(context, update).await {
            break;
        }
    }
    result
}

async fn send_progress(
    context: &RequestContext<RoleServer>,
    update: ProgressNotificationParam,
) -> bool {
    let notification = ProgressNotification::new(update);
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            context.peer.send_notification(notification.into())
        )
        .await,
        Ok(Ok(()))
    )
}

fn request_parts(context: &RequestContext<RoleServer>) -> Result<&Parts, ErrorData> {
    context
        .extensions
        .get::<Parts>()
        .ok_or_else(|| ErrorData::internal_error("Missing gateway request context", None))
}

fn protocol_tool(definition: ToolDefinition) -> Result<Tool, ErrorData> {
    serde_json::to_value(definition)
        .and_then(serde_json::from_value)
        .map_err(|error| {
            tracing::warn!(%error, "invalid MCP tool definition");
            ErrorData::internal_error("Invalid tool definition", None)
        })
}

fn implementation() -> Implementation {
    Implementation::new("ContextForge", env!("CARGO_PKG_VERSION"))
}

fn stamp_server_info(meta: &mut Option<MetaObject>) {
    meta.get_or_insert_with(MetaObject::new).0.insert(
        SERVER_INFO_KEY.to_owned(),
        json!({"name": "ContextForge", "version": env!("CARGO_PKG_VERSION")}),
    );
}

fn method_not_found(method: impl Into<Value>) -> ErrorData {
    ErrorData::new(
        ErrorCode::METHOD_NOT_FOUND,
        "Method not found",
        Some(method.into()),
    )
}

fn tool_error(error: ToolError) -> ErrorData {
    match error {
        ToolError::Denied => ErrorData::new(ErrorCode(0), "Access denied", None),
        ToolError::NotFound => ErrorData::new(ErrorCode(0), "Unknown tool", None),
        ToolError::Cursor => ErrorData::invalid_params("Invalid cursor", None),
        ToolError::Unavailable => ErrorData::internal_error("Tool service unavailable", None),
        ToolError::Cancelled => ErrorData::internal_error("Request cancelled", None),
        ToolError::Database(error) => {
            tracing::error!(%error, "MCP catalog lookup failed");
            ErrorData::internal_error("Tool service unavailable", None)
        }
    }
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;
    use crate::{
        access::Authorizer,
        catalog::{GatewayRegistration, RegisteredTool},
        database::Database,
        gateway::test_service,
    };

    async fn test_database() -> Database {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let database = Database::Sqlite(pool);
        database.migrate_identity().await.unwrap();
        database.migrate_catalog().await.unwrap();
        database
    }

    fn modern(database: Database) -> Modern {
        let authorizer = Authorizer::new(database.clone(), None, true);
        Modern::new(test_service(database, authorizer), true)
    }

    fn request(method: &str, params: Value) -> Request {
        Request::builder()
            .method(Method::POST)
            .uri("/mcp/")
            .header("host", "localhost")
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .header(ACCEPT, JSON_MEDIA_TYPE)
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method)
            .body(Body::from(
                json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}).to_string(),
            ))
            .unwrap()
    }

    fn metadata() -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}
        })
    }

    async fn json_response(modern: &Modern, request: Request) -> (StatusCode, Value) {
        let response = modern.handle(request).await;
        let (parts, body) = response.into_parts();
        assert!(!parts.headers.contains_key("mcp-session-id"));
        let bytes = to_bytes(body, 8192).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "{}: {error}: {}",
                parts.status,
                String::from_utf8_lossy(&bytes)
            )
        });
        (parts.status, body)
    }

    #[tokio::test]
    async fn stateless_sdk_validates_routing_and_metadata() {
        let modern = modern(test_database().await);
        let req = request("server/discover", json!({"_meta":metadata()}));
        let (status, body) = json_response(&modern, req).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let result = &body["result"];
        assert_eq!(result["supportedVersions"], json!(["2026-07-28"]));
        assert_eq!(result["cacheScope"], "private");
        assert_eq!(result["ttlMs"], 300_000);
        assert_eq!(result["capabilities"]["tools"]["listChanged"], false);

        let mut req = request("tools/list", json!({"_meta":metadata()}));
        req.headers_mut()
            .insert("mcp-method", HeaderValue::from_static("server/discover"));
        let (status, body) = json_response(&modern, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], -32020);

        let (status, body) = json_response(&modern, request("tools/list", json!({}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], -32602);

        let (status, body) =
            json_response(&modern, request("ping", json!({"_meta":metadata()}))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(
            body["error"],
            json!({"code": -32601, "message": "Method not found", "data": "ping"})
        );
    }

    #[tokio::test]
    async fn tool_header_validation_uses_only_visible_tool_schemas() {
        let database = test_database().await;
        let Database::Sqlite(pool) = &database else {
            unreachable!();
        };
        sqlx::query("INSERT INTO email_users (id, email) VALUES ('owner', 'owner@example.com')")
            .execute(pool)
            .await
            .unwrap();
        let capabilities = json!({"tools": {}});
        let definition = serde_json::from_value(json!({
            "name": "echo",
            "inputSchema": {
                "type": "object",
                "properties": {"message": {"type": "string", "x-mcp-header": "Message"}}
            }
        }))
        .unwrap();
        for (gateway, tool_id, name) in [
            ("public", "01", "public-echo"),
            ("private", "02", "private-echo"),
        ] {
            database
                .register_gateway(
                    &GatewayRegistration {
                        id: gateway,
                        name: gateway,
                        slug: gateway,
                        url: &format!("http://localhost:9000/{gateway}"),
                        description: None,
                        capabilities: &capabilities,
                        visibility: gateway,
                        team_id: None,
                        owner_email: "owner@example.com",
                        tags: &[],
                    },
                    &[RegisteredTool {
                        id: tool_id,
                        slug: "echo",
                        name,
                        definition: &definition,
                    }],
                )
                .await
                .unwrap();
        }
        let modern = modern(database);
        let request = |name: &'static str| {
            let mut request = request(
                "tools/call",
                json!({
                    "name":name,
                    "arguments":{"message":"hello"},
                    "_meta":metadata(),
                }),
            );
            request
                .headers_mut()
                .insert("mcp-name", HeaderValue::from_static(name));
            request
        };

        let (status, body) = json_response(&modern, request("public-echo")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], -32020);
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Mcp-Param-Message")
        );

        let (status, body) = json_response(&modern, request("private-echo")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["isError"], true);
        assert_eq!(
            body["result"]["content"][0]["text"],
            "Unknown tool: private-echo"
        );
    }
}
