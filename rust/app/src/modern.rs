// SPDX-License-Identifier: Apache-2.0
//! Modern stateless MCP Streamable HTTP.

use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

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
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ClientCapabilities,
        ClientJsonRpcMessage, ClientRequest, CompleteRequestParams, CompleteResult, ContentBlock,
        CustomRequest, CustomResult, DiscoverResult, ElicitRequestParams, ErrorCode, ErrorData,
        GetPromptRequestParams, GetPromptResponse, Implementation, InitializeRequestParams,
        InitializeResult, InputRequest, InputRequiredResult, JsonRpcError, ListPromptsResult,
        ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, MetaObject,
        PaginatedRequestParams, ProgressNotification, ProgressNotificationParam, ProtocolVersion,
        ReadResourceRequestParams, ReadResourceResponse, ResultType, ServerConfig,
        SubscriptionFilter, Tool,
    },
    service::{RequestContext, SubscriptionContext},
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
    },
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    access::Principal,
    catalog::{CatalogList, CatalogServer, ToolDefinition},
    gateway::{GatewayService, ToolError},
    mcp::{
        JSON_MEDIA_TYPE, MAX_REQUEST_BODY_BYTES, ROOT_INSTRUCTIONS, accepts_event_stream,
        accepts_json, accepts_post_stream, catalog_event_capabilities, rpc_error,
    },
    modern_validation::reject_invalid_request,
    subscriptions::AcceptedSubscription,
    upstream::{ProxyCatalogKind, ToolContext, ToolProgress},
};

const SERVER_INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";
const MODERN_VERSIONS: &[ProtocolVersion] = &[ProtocolVersion::V_2026_07_28];

type Transport = StreamableHttpService<GatewayHandler, NeverSessionManager>;

#[derive(Clone)]
struct AcceptsProgress;

#[derive(Clone, Default)]
struct HandlerErrorStatus(Arc<AtomicU16>);

impl HandlerErrorStatus {
    fn record<T>(parts: &Parts, reply: &Result<T, ErrorData>) {
        if let Err(error) = reply
            && let Some(marker) = parts.extensions.get::<Self>()
        {
            let status = match error.code {
                ErrorCode::INVALID_PARAMS => StatusCode::BAD_REQUEST,
                ErrorCode::METHOD_NOT_FOUND => StatusCode::NOT_FOUND,
                _ => return,
            };
            marker.0.store(status.as_u16(), Ordering::Release);
        }
    }
}

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
            transport: transport(gateway.clone(), None, None, config),
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

        let (mut parts, body) = request.into_parts();
        let bytes = match Bytes::from_request(Request::from_parts(parts.clone(), body), &()).await {
            Ok(bytes) => bytes,
            Err(error) => return error.into_response(),
        };
        let Ok(mut body) = serde_json::from_slice::<Value>(&bytes) else {
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
        if body["method"] == "subscriptions/listen"
            && let Ok(ClientJsonRpcMessage::Request(message)) =
                ClientJsonRpcMessage::deserialize(&body)
            && let ClientRequest::SubscriptionsListenRequest(listen) = message.request
        {
            if parts.extensions.get::<AcceptsProgress>().is_none() {
                return StatusCode::NOT_ACCEPTABLE.into_response();
            }
            let subscription = match self
                .gateway
                .prepare_subscription(
                    listen.params.notifications,
                    parts.extensions.get::<Principal>(),
                    parts.extensions.get::<CatalogServer>(),
                )
                .await
            {
                Ok(subscription) => subscription,
                Err(error) => {
                    return rpc_error(
                        StatusCode::OK,
                        &body["id"],
                        error.code.0,
                        &error.message,
                        error.data,
                    );
                }
            };
            body["params"]["notifications"] = serde_json::to_value(&subscription.filter)
                .expect("serialize MCP notification filter");
            let body = serde_json::to_vec(&body).expect("serialize authorized MCP request");
            let transport = transport(
                self.gateway.clone(),
                None,
                Some(subscription),
                self.transport.config.clone(),
            );
            return handle(&transport, Request::from_parts(parts, Body::from(body))).await;
        }
        if matches!(
            body["method"].as_str(),
            Some("resources/read" | "prompts/get" | "completion/complete")
        ) {
            parts.extensions.insert(HandlerErrorStatus::default());
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
            None,
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
    let handler_status = request.extensions().get::<HandlerErrorStatus>().cloned();
    let mut response = transport.handle(request).await.into_response();
    if response.headers().get(CONTENT_TYPE) == Some(&HeaderValue::from_static(JSON_MEDIA_TYPE))
        && let Some(status) = handler_status
            .and_then(|marker| StatusCode::from_u16(marker.0.load(Ordering::Acquire)).ok())
        && matches!(
            response.status(),
            StatusCode::OK | StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
        )
    {
        *response.status_mut() = status;
        return response;
    }
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
    subscription: Option<AcceptedSubscription>,
    config: StreamableHttpServerConfig,
) -> Transport {
    StreamableHttpService::new(
        move || {
            Ok(GatewayHandler {
                gateway: gateway.clone(),
                scoped_tool: scoped_tool.clone(),
                subscription: subscription.clone(),
            })
        },
        Arc::new(NeverSessionManager::default()),
        config,
    )
}

struct GatewayHandler {
    gateway: Arc<GatewayService>,
    scoped_tool: Option<Tool>,
    subscription: Option<AcceptedSubscription>,
}

impl GatewayHandler {
    async fn catalog_metadata<R: DeserializeOwned>(
        &self,
        list: CatalogList,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<R, ErrorData> {
        let parts = request_parts(&context)?;
        let server = parts.extensions.get::<CatalogServer>();
        let principal = parts.extensions.get::<Principal>();
        let cursor = request.as_ref().and_then(|params| params.cursor.as_deref());
        let proxy_page = if matches!(list, CatalogList::Resources) {
            let result = self
                .gateway
                .direct_catalog(
                    ProxyCatalogKind::Resources,
                    principal,
                    server,
                    Some(&parts.headers),
                    cursor,
                )
                .await;
            HandlerErrorStatus::record(parts, &result);
            result?
        } else {
            None
        };
        let page = match proxy_page {
            Some(page) => page,
            None => self
                .gateway
                .list_catalog_metadata(list, principal, server, cursor)
                .await
                .map_err(tool_error)?,
        };
        self.catalog_result(page, server, list.method()).await
    }

    async fn catalog_result<R: DeserializeOwned>(
        &self,
        mut page: Value,
        server: Option<&CatalogServer>,
        method: &str,
    ) -> Result<R, ErrorData> {
        let mut meta = None;
        stamp_server_info(&mut meta);
        page["_meta"] = json!(meta);
        page["resultType"] = json!(ResultType::COMPLETE);
        page["cacheScope"] = json!("private");
        page["ttlMs"] = json!(self.gateway.catalog_ttl_ms(server).await);
        serde_json::from_value(page).map_err(|error| {
            tracing::warn!(%error, method, "invalid catalog metadata");
            ErrorData::internal_error("Invalid catalog metadata", None)
        })
    }
}

impl ServerHandler for GatewayHandler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(catalog_event_capabilities())
            .with_server_info(implementation())
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
    }

    fn accepted_subscription_filter(
        &self,
        _requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.subscription
            .as_ref()
            .map(|subscription| subscription.filter.clone())
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        let Some(subscription) = &self.subscription else {
            return Err(method_not_found("subscriptions/listen"));
        };
        subscription.listen(context).await
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
        let principal = parts.extensions.get::<Principal>();
        let cursor = request.as_ref().and_then(|params| params.cursor.as_deref());
        let proxy_page = self
            .gateway
            .direct_catalog(
                ProxyCatalogKind::Tools,
                principal,
                server,
                Some(&parts.headers),
                cursor,
            )
            .await;
        HandlerErrorStatus::record(parts, &proxy_page);
        if let Some(page) = proxy_page? {
            return self.catalog_result(page, server, "tools/list").await;
        }
        let page = self
            .gateway
            .list_tools(principal, server, cursor)
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

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        self.catalog_metadata(CatalogList::Resources, request, context)
            .await
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        self.catalog_metadata(CatalogList::Templates, request, context)
            .await
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        self.catalog_metadata(CatalogList::Prompts, request, context)
            .await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let parts = request_parts(&context)?;
        let capabilities = upstream_client_capabilities(&context);
        let name = request.name.clone();
        let (relay, updates) = progress_relay(parts, &context);
        let invocation = self.gateway.call_tool(
            parts.extensions.get::<Principal>(),
            parts.extensions.get::<CatalogServer>(),
            request,
            ToolContext {
                cancellation: &context.ct,
                progress: relay.as_ref(),
                notifications: None,
                client_capabilities: Some(&capabilities),
                request_headers: Some(&parts.headers),
            },
            None,
        );
        let mut result = match with_progress(invocation, updates, &context).await {
            Ok(value) if value["resultType"] == "input_required" => {
                let mut result: InputRequiredResult = serde_json::from_value(value)
                    .map_err(|_| ErrorData::internal_error("Invalid upstream tool result", None))?;
                check_required_input(&result, &capabilities, &format!("tool '{name}'"))?;
                stamp_server_info(&mut result.meta);
                return Ok(result.into());
            }
            Ok(value) => serde_json::from_value::<CallToolResult>(value)
                .map_err(|_| ErrorData::internal_error("Invalid upstream tool result", None))?,
            Err(ToolError::NotFound) => {
                CallToolResult::error(vec![ContentBlock::text(format!("Unknown tool: {name}"))])
            }
            Err(error) => return Err(tool_error(error)),
        };
        result.result_type = Some(ResultType::COMPLETE);
        stamp_server_info(&mut result.meta);
        Ok(CallToolResponse::Complete(result))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let parts = request_parts(&context)?;
        let capabilities = upstream_client_capabilities(&context);
        let (relay, updates) = progress_relay(parts, &context);
        let uri = request.uri.clone();
        let invocation = self.gateway.read_resource(
            request,
            parts.extensions.get::<Principal>(),
            parts.extensions.get::<CatalogServer>(),
            ToolContext {
                cancellation: &context.ct,
                progress: relay.as_ref(),
                notifications: None,
                client_capabilities: Some(&capabilities),
                request_headers: Some(&parts.headers),
            },
            None,
        );
        let reply = with_progress(invocation, updates, &context).await;
        HandlerErrorStatus::record(parts, &reply);
        match reply? {
            ReadResourceResponse::Complete(mut result) => {
                result.result_type = Some(ResultType::COMPLETE);
                result.ttl_ms.get_or_insert(0);
                if parts.extensions.get::<Principal>().is_some() {
                    result.cache_scope = Some(CacheScope::Private);
                } else {
                    result.cache_scope.get_or_insert(CacheScope::Private);
                }
                stamp_server_info(&mut result.meta);
                Ok(result.into())
            }
            ReadResourceResponse::InputRequired(mut result) => {
                check_required_input(&result, &capabilities, &format!("resource '{uri}'"))?;
                stamp_server_info(&mut result.meta);
                Ok(result.into())
            }
            _ => Err(ErrorData::internal_error("Invalid resource result", None)),
        }
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let parts = request_parts(&context)?;
        let capabilities = upstream_client_capabilities(&context);
        let (relay, updates) = progress_relay(parts, &context);
        let name = request.name.clone();
        let invocation = self.gateway.get_prompt(
            request,
            parts.extensions.get::<Principal>(),
            parts.extensions.get::<CatalogServer>(),
            ToolContext {
                cancellation: &context.ct,
                progress: relay.as_ref(),
                notifications: None,
                client_capabilities: Some(&capabilities),
                request_headers: Some(&parts.headers),
            },
            None,
        );
        let reply = with_progress(invocation, updates, &context).await;
        HandlerErrorStatus::record(parts, &reply);
        match reply? {
            GetPromptResponse::Complete(mut result) => {
                result.result_type = Some(ResultType::COMPLETE);
                stamp_server_info(&mut result.meta);
                Ok(result.into())
            }
            GetPromptResponse::InputRequired(mut result) => {
                check_required_input(&result, &capabilities, &format!("prompt '{name}'"))?;
                stamp_server_info(&mut result.meta);
                Ok(result.into())
            }
            _ => Err(ErrorData::internal_error("Invalid prompt result", None)),
        }
    }

    async fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, ErrorData> {
        let parts = request_parts(&context)?;
        let capabilities = upstream_client_capabilities(&context);
        let (relay, updates) = progress_relay(parts, &context);
        let invocation = self.gateway.complete(
            request,
            parts.extensions.get::<Principal>(),
            parts.extensions.get::<CatalogServer>(),
            ToolContext {
                cancellation: &context.ct,
                progress: relay.as_ref(),
                notifications: None,
                client_capabilities: Some(&capabilities),
                request_headers: Some(&parts.headers),
            },
            None,
        );
        let reply = with_progress(invocation, updates, &context).await;
        HandlerErrorStatus::record(parts, &reply);
        let mut result = reply?;
        stamp_server_info(&mut result.meta);
        Ok(result)
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

#[allow(deprecated)]
fn check_required_input(
    result: &InputRequiredResult,
    capabilities: &ClientCapabilities,
    subject: &str,
) -> Result<(), ErrorData> {
    let Some(requests) = &result.input_requests else {
        return Ok(());
    };
    let elicitation = capabilities.elicitation.as_ref();
    for request in requests.values() {
        let (capability, required) = match request {
            InputRequest::Elicitation(request) => match &request.params {
                ElicitRequestParams::UrlElicitationParams { .. }
                    if !elicitation.is_some_and(|c| c.url.is_some()) =>
                {
                    ("url elicitation", json!({"elicitation":{"url":{}}}))
                }
                ElicitRequestParams::FormElicitationParams { .. }
                    if !elicitation.is_some_and(|c| c.form.is_some() || c.url.is_none()) =>
                {
                    ("form elicitation", json!({"elicitation":{"form":{}}}))
                }
                _ => continue,
            },
            InputRequest::CreateMessage(request) => {
                let sampling = capabilities.sampling.as_ref();
                let needs_tools = request.params.tool_choice.is_some()
                    || request
                        .params
                        .tools
                        .as_ref()
                        .is_some_and(|tools| !tools.is_empty());
                if needs_tools && !sampling.is_some_and(|c| c.tools.is_some()) {
                    ("sampling.tools", json!({"sampling":{"tools":{}}}))
                } else if sampling.is_none() {
                    ("sampling", json!({"sampling":{}}))
                } else {
                    continue;
                }
            }
            InputRequest::ListRoots(_) if capabilities.roots.is_none() => {
                ("roots", json!({"roots":{}}))
            }
            _ => continue,
        };
        return Err(ErrorData::new(
            ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY,
            format!("Client did not declare the {capability} capability required by {subject}"),
            Some(json!({"requiredCapabilities":required})),
        ));
    }
    Ok(())
}

fn upstream_client_capabilities(context: &RequestContext<RoleServer>) -> ClientCapabilities {
    let mut capabilities = context.client_capabilities().unwrap_or_default();
    capabilities.experimental = None;
    capabilities.extensions = None;
    capabilities.extra.clear();
    capabilities
}

fn progress_relay(
    parts: &Parts,
    context: &RequestContext<RoleServer>,
) -> (
    Option<ToolProgress>,
    Option<tokio::sync::mpsc::Receiver<ProgressNotificationParam>>,
) {
    let progress = parts
        .extensions
        .get::<AcceptsProgress>()
        .and_then(|_| context.meta.get_progress_token())
        .map(ToolProgress::channel);
    match progress {
        Some((relay, updates)) => (Some(relay), Some(updates)),
        None => (None, None),
    }
}

async fn with_progress<T, E>(
    invocation: impl Future<Output = Result<T, E>>,
    updates: Option<tokio::sync::mpsc::Receiver<ProgressNotificationParam>>,
    context: &RequestContext<RoleServer>,
) -> Result<T, E> {
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
        assert_eq!(result["capabilities"]["tools"]["listChanged"], true);

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
                        transport: crate::upstream::UpstreamTransport::StreamableHttp,
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
