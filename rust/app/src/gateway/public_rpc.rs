// SPDX-License-Identifier: Apache-2.0

use axum::{
    body::{Body, Bytes},
    extract::{FromRequest, Request},
};
use rmcp::model::{
    CompleteRequestParams, GetPromptRequestParams, GetPromptResponse, ReadResourceRequestParams,
    ReadResourceResponse, RequestId,
};
use serde_json::Map;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    mcp::{self, McpState, rpc_error, rpc_success},
    sessions::{PendingRequest, SessionAccess, SessionError},
};

const MAX_METHOD_LENGTH: usize = 128;
const MAX_PARAM_SIZE: usize = 262_144;
const MAX_PARAM_DEPTH: usize = 30;

struct RpcFault {
    code: i32,
    message: String,
    data: Option<Value>,
}

impl RpcFault {
    fn new(code: i32, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            code,
            message: message.into(),
            data,
        }
    }

    fn internal() -> Self {
        Self::new(-32603, "Internal error", None)
    }

    fn access_denied(method: &str) -> Self {
        Self::new(-32003, "Access denied", Some(json!({"method":method})))
    }

    fn response(self, id: &Value) -> Response {
        rpc_error(StatusCode::OK, id, self.code, &self.message, self.data)
    }
}

impl From<ErrorData> for RpcFault {
    fn from(error: ErrorData) -> Self {
        Self::new(error.code.0, error.message, error.data)
    }
}

impl From<ToolError> for RpcFault {
    fn from(error: ToolError) -> Self {
        match error {
            ToolError::Cursor => Self::new(-32602, "Invalid cursor", None),
            _ => Self::internal(),
        }
    }
}

pub(crate) async fn handle(State(state): State<Arc<McpState>>, request: Request) -> Response {
    let (mut parts, body) = request.into_parts();
    let body = match Bytes::from_request(Request::from_parts(parts.clone(), body), &()).await {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        return rpc_error(
            StatusCode::BAD_REQUEST,
            &Value::Null,
            -32700,
            "Parse error",
            None::<()>,
        );
    };
    let id = &message["id"];
    if !(id.is_null() || id.is_i64() || id.is_u64() || id.is_boolean() || id.is_string()) {
        return invalid_request(&Value::Null);
    }
    let Some(method) = message["method"].as_str().filter(|name| valid_method(name)) else {
        return invalid_request(id);
    };
    let mut params = match &message["params"] {
        Value::Null => Map::new(),
        Value::Object(params)
            if container_depth(&message["params"]) <= MAX_PARAM_DEPTH
                && message["params"].to_string().len() <= MAX_PARAM_SIZE =>
        {
            params.clone()
        }
        _ => return invalid_request(id),
    };
    if message["jsonrpc"] != "2.0" {
        return invalid_request(id);
    }
    let id = if id.is_null() {
        json!(Uuid::new_v4().to_string())
    } else {
        id.clone()
    };
    let principal = parts
        .extensions
        .get::<Principal>()
        .expect("RPC router authenticates before dispatch")
        .clone();
    let requested_server = match params.get("server_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(server)) => (!server.is_empty()).then_some(server.as_str()),
        _ => return RpcFault::new(-32602, "Invalid server identifier", None).response(&id),
    };
    if let (Some(requested), Some(restricted)) =
        (requested_server, principal.server_limit.as_deref())
        && requested != restricted
    {
        return rpc_error(
            StatusCode::FORBIDDEN,
            &id,
            -32003,
            &format!("Token not authorized for server: {requested}"),
            None::<()>,
        );
    }
    let server_id = requested_server.or(principal.server_limit.as_deref());
    let service = &state.service;
    if let Some(permission) = required_permission(method) {
        let allowed = service
            .access
            .allows(&principal, permission, RoleContext::AnyTeam, true)
            .await;
        match allowed {
            Ok(true) => {}
            Ok(false) => return RpcFault::access_denied(method).response(&id),
            Err(_) => return RpcFault::internal().response(&id),
        }
    }
    let server = if let Some(server_id) = server_id {
        match service.visible_server(server_id, Some(&principal)).await {
            Ok(Some(server)) => Some(server),
            Ok(None) => {
                return RpcFault::new(
                    -32002,
                    format!("Server not found: {server_id}"),
                    Some(json!({"server_id":server_id})),
                )
                .response(&id);
            }
            Err(_) => return RpcFault::internal().response(&id),
        }
    } else {
        None
    };

    if let Some(server) = &server {
        // A proxy header cannot redirect a server-scoped request to another catalog.
        parts.headers.remove(GATEWAY_ID_HEADER);
        parts.extensions.insert(server.clone());
    }
    let mut session = None;
    if let Some(sessions) = &state.sessions
        && method != "initialize"
    {
        let header = match mcp::session_header(&parts.headers) {
            Ok(header) => header.cloned(),
            Err(_) => {
                return RpcFault::new(-32002, "Session not found", Some(json!({"method":method})))
                    .response(&id);
            }
        };
        if let Some(header) = header {
            let forwarded = Request::from_parts(parts, Body::from(body));
            let forwarded = match mcp::forward_remote(&state, forwarded).await {
                Ok(request) => request,
                Err(response) => return *response,
            };
            (parts, _) = forwarded.into_parts();
            match sessions
                .access(
                    Some(&header),
                    Some(&principal.email),
                    server_id,
                    SessionAccess::Post,
                )
                .await
            {
                Ok(owned) => session = Some(owned),
                Err(SessionError::Forbidden) => {
                    return RpcFault::access_denied(method).response(&id);
                }
                Err(_) => {
                    return RpcFault::new(
                        -32002,
                        "Session not found",
                        Some(json!({"method":method})),
                    )
                    .response(&id);
                }
            }
        }
    }
    let request = RpcCall {
        id: &id,
        method,
        principal: &principal,
        server: server.as_ref(),
        headers: &parts.headers,
        session,
    };
    match dispatch(service, &request, &mut params).await {
        Ok(result) => rpc_success(&id, result),
        Err(error) => error.response(&id),
    }
}

fn invalid_request(id: &Value) -> Response {
    rpc_error(StatusCode::OK, id, -32600, "Invalid Request", None::<()>)
}

fn valid_method(method: &str) -> bool {
    let mut bytes = method.bytes();
    method.len() <= MAX_METHOD_LENGTH
        && bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"_./-".contains(&byte))
}

fn container_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(container_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(container_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn required_permission(method: &str) -> Option<&'static str> {
    match method {
        "tools/list" | "list_tools" | "completion/complete" => Some("tools.read"),
        "resources/list"
        | "resources/templates/list"
        | "resources/read"
        | "resources/subscribe"
        | "resources/unsubscribe" => Some("resources.read"),
        "prompts/list" | "prompts/get" => Some("prompts.read"),
        "list_gateways" => Some("gateways.read"),
        "roots/list" | "list_roots" | "logging/setLevel" => Some("admin.system_config"),
        "initialize"
        | "ping"
        | "sampling/createMessage"
        | "elicitation/create"
        | "subscriptions/listen" => None,
        _ if reserved(method) => None,
        _ => Some("tools.execute"),
    }
}

fn reserved(method: &str) -> bool {
    method.split_once('/').is_some_and(|(namespace, _)| {
        matches!(
            namespace,
            "roots"
                | "notifications"
                | "sampling"
                | "elicitation"
                | "completion"
                | "logging"
                | "extensions"
                | "io.modelcontextprotocol"
        )
    })
}

struct RpcCall<'a> {
    id: &'a Value,
    method: &'a str,
    principal: &'a Principal,
    server: Option<&'a CatalogServer>,
    headers: &'a HeaderMap,
    session: Option<Arc<Session>>,
}

impl RpcCall<'_> {
    fn tool_context<'a>(&'a self, cancellation: &'a CancellationToken) -> ToolContext<'a> {
        ToolContext {
            cancellation,
            progress: None,
            notifications: None,
            client_capabilities: None,
            request_headers: Some(self.headers),
        }
    }
}

#[allow(deprecated)]
async fn dispatch(
    service: &Arc<GatewayService>,
    call: &RpcCall<'_>,
    params: &mut Map<String, Value>,
) -> Result<Value, RpcFault> {
    let principal = Some(call.principal);
    let cursor = params.get("cursor").and_then(Value::as_str);
    match call.method {
        "initialize" => initialize(params, call.server),
        "ping" => Ok(json!({})),
        "tools/list" => {
            let mut page = service.list_tools(principal, call.server, cursor).await?;
            for tool in &mut page.tools {
                tool.annotations.get_or_insert_with(|| json!({}));
            }
            wire(page)
        }
        "list_tools" => {
            let mut result = tool_api::rpc_list(
                service,
                call.principal,
                call.server,
                cursor.map(str::to_owned),
            )
            .await
            .map_err(|_| RpcFault::internal())?;
            omit_null_fields(&mut result, "tools");
            Ok(result)
        }
        "list_gateways" => {
            if call.principal.server_limit.is_some() {
                return Err(RpcFault::access_denied(call.method));
            }
            let mut result = management::rpc_list(service.clone(), call.principal.clone())
                .await
                .map_err(|_| RpcFault::internal())?;
            omit_null_fields(&mut result, "gateways");
            Ok(result)
        }
        "roots/list" | "list_roots" => {
            if !call.principal.is_global_admin() || call.principal.server_limit.is_some() {
                return Err(RpcFault::access_denied(call.method));
            }
            Ok(json!({"roots": service.roots.export_configuration(None)}))
        }
        "resources/list" | "resources/templates/list" | "prompts/list" => {
            let list = match call.method {
                "resources/list" => CatalogList::Resources,
                "resources/templates/list" => CatalogList::Templates,
                _ => CatalogList::Prompts,
            };
            Ok(service
                .list_catalog_metadata(list, principal, call.server, cursor)
                .await?)
        }
        "resources/read" | "prompts/get" | "completion/complete" => {
            content(service, call, params).await
        }
        "logging/setLevel" => {
            if call.principal.server_limit.is_some() {
                return Err(RpcFault::access_denied(call.method));
            }
            let level = params
                .get("level")
                .and_then(|level| rmcp::model::LoggingLevel::deserialize(level).ok())
                .ok_or_else(RpcFault::internal)?;
            service.set_log_level(level, principal, call.server).await?;
            Ok(json!({}))
        }
        "notifications/cancelled" => {
            if let Some(session) = &call.session
                && let Some(id) = params
                    .get("requestId")
                    .and_then(|id| RequestId::deserialize(id).ok())
            {
                session.cancel_request(&id);
            }
            Ok(json!({}))
        }
        "subscriptions/listen"
        | "sampling/createMessage"
        | "elicitation/create"
        | "resources/subscribe"
        | "resources/unsubscribe" => Err(method_not_found(call.method)),
        method
            if method.starts_with("extensions/")
                || method.starts_with("io.modelcontextprotocol/") =>
        {
            Err(method_not_found(method))
        }
        method if reserved(method) => Ok(json!({})),
        _ => invoke(service, call, params).await,
    }
}

fn initialize(
    params: &Map<String, Value>,
    server: Option<&CatalogServer>,
) -> Result<Value, RpcFault> {
    let version = params
        .get("protocol_version")
        .or_else(|| params.get("protocolVersion"))
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())
        .ok_or_else(RpcFault::internal)?;
    let mut capabilities = mcp::catalog_event_capabilities();
    if let Some(resources) = &mut capabilities.resources {
        resources.subscribe = Some(false);
    }
    if version != "2026-07-28" {
        capabilities.logging = Some(Default::default());
    }
    let mut result = json!({
        "protocolVersion":version,
        "capabilities":capabilities,
        "serverInfo":{"name":"ContextForge","version":env!("CARGO_PKG_VERSION")},
    });
    if let Some(instructions) = server.map_or(Some(mcp::ROOT_INSTRUCTIONS), |server| {
        server.instructions.as_deref()
    }) {
        result["instructions"] = json!(instructions);
    }
    Ok(result)
}

async fn content(
    service: &GatewayService,
    call: &RpcCall<'_>,
    params: &Map<String, Value>,
) -> Result<Value, RpcFault> {
    let principal = Some(call.principal);
    let cancellation = CancellationToken::new();
    let context = call.tool_context(&cancellation);
    let session = call.session.as_deref();
    let params = Value::Object(params.clone());
    match call.method {
        "resources/read" => {
            let uri = required_string(&params, "uri", "Missing resource URI in parameters")?;
            let request = ReadResourceRequestParams::deserialize(&params)
                .map_err(|_| invalid_params(&params))?;
            match service
                .read_resource(request, principal, call.server, context, session)
                .await
            {
                Ok(ReadResourceResponse::Complete(mut result)) => {
                    result.result_type = None;
                    result.cache_scope = None;
                    result.ttl_ms = None;
                    wire(result)
                }
                Ok(_) => Err(RpcFault::internal()),
                Err(error) if error.message.starts_with("Unknown resource:") => Err(RpcFault::new(
                    -32002,
                    format!("Resource not found: {uri}"),
                    Some(json!({"uri":uri})),
                )),
                Err(error) => Err(error.into()),
            }
        }
        "prompts/get" => {
            let name = required_string(&params, "name", "Missing prompt name in parameters")?;
            let request = GetPromptRequestParams::deserialize(&params)
                .map_err(|_| invalid_params(&params))?;
            match service
                .get_prompt(request, principal, call.server, context, session)
                .await
            {
                Ok(GetPromptResponse::Complete(mut result)) => {
                    result.result_type = None;
                    wire(result)
                }
                Ok(_) => Err(RpcFault::internal()),
                Err(error) if error.message.starts_with("Unknown prompt:") => Err(RpcFault::new(
                    -32002,
                    format!("Prompt not found: {name}"),
                    Some(json!({"name":name})),
                )),
                Err(error) => Err(error.into()),
            }
        }
        _ => {
            let request =
                CompleteRequestParams::deserialize(&params).map_err(|_| invalid_params(&params))?;
            wire(
                service
                    .complete(request, principal, call.server, context, session)
                    .await?,
            )
        }
    }
}

async fn invoke(
    service: &GatewayService,
    call: &RpcCall<'_>,
    params: &mut Map<String, Value>,
) -> Result<Value, RpcFault> {
    let explicit = call.method == "tools/call";
    let payload = if explicit {
        Value::Object(std::mem::take(params))
    } else {
        json!({"name":call.method,"arguments":std::mem::take(params)})
    };
    let name = required_string(&payload, "name", "Missing tool name in parameters")?;
    let not_found = || {
        if explicit {
            RpcFault::new(-32601, format!("Tool not found: {name}"), None)
        } else {
            method_not_found(call.method)
        }
    };
    let mut request = CallToolRequestParams::deserialize(&payload).map_err(|_| not_found())?;
    request.input_responses = None;
    request.request_state = None;
    let pending: Option<PendingRequest> = call
        .session
        .as_ref()
        .and_then(|session| {
            RequestId::deserialize(call.id)
                .ok()
                .map(|id| session.clone().track(id))
        })
        .transpose()
        .map_err(|_| RpcFault::new(-32600, "Request ID already in use", None))?;
    let cancellation = pending
        .as_ref()
        .map(|pending| pending.token.clone())
        .unwrap_or_default();
    match service
        .call_tool(
            Some(call.principal),
            call.server,
            request,
            call.tool_context(&cancellation),
            call.session.as_deref(),
        )
        .await
    {
        Ok(mut result) => {
            if let Some(fields) = result.as_object_mut() {
                fields.entry("isError").or_insert(json!(false));
                fields.remove("resultType");
            }
            Ok(rest_tool::for_caller(result, false))
        }
        Err(ToolError::NotFound) => Err(not_found()),
        Err(ToolError::Denied) => Err(RpcFault::access_denied(call.method)),
        Err(ToolError::Cancelled) => Err(RpcFault::new(
            -32800,
            format!("Tool execution cancelled: {name}"),
            Some(json!({"requestId":call.id.to_string(),"partial":false})),
        )),
        Err(error) => Err(error.into()),
    }
}

fn wire(value: impl Serialize) -> Result<Value, RpcFault> {
    serde_json::to_value(value).map_err(|_| RpcFault::internal())
}

fn method_not_found(method: &str) -> RpcFault {
    RpcFault::new(
        -32601,
        format!("Method not found: {method}"),
        Some(json!({})),
    )
}

fn invalid_params(params: &Value) -> RpcFault {
    RpcFault::new(-32602, "Invalid params", Some(params.clone()))
}

fn required_string<'a>(params: &'a Value, key: &str, message: &str) -> Result<&'a str, RpcFault> {
    params[key]
        .as_str()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| RpcFault::new(-32602, message, Some(params.clone())))
}

fn omit_null_fields(result: &mut Value, list: &str) {
    if let Some(fields) = result.as_object_mut() {
        fields.retain(|_, value| !value.is_null());
    }
    if let Some(items) = result[list].as_array_mut() {
        for item in items {
            if let Some(fields) = item.as_object_mut() {
                fields.retain(|_, value| !value.is_null());
            }
        }
    }
}
