// SPDX-License-Identifier: Apache-2.0
//! Outbound MCP Streamable HTTP over a validated, pinned destination.

use std::{
    collections::HashSet,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ipnet::IpNet;
use reqwest::{
    Client, Method, Response,
    dns::{Name, Resolve, Resolving},
    header::{ACCEPT, CONTENT_TYPE, HeaderValue},
};
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, ClientCapabilities, ClientJsonRpcMessage,
    ClientRequest, Implementation, InitializeRequest, InitializeRequestParams,
    InitializedNotification, JsonRpcMessage, ListToolsRequest, PaginatedRequestParams,
    ProtocolVersion, RequestId,
};
use rustls_platform_verifier::BuilderVerifierExt;
use serde_json::Value;
use thiserror::Error;
use tokio::{
    net::lookup_host,
    time::{Instant, timeout, timeout_at},
};
use url::{Host, Url};

const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::LATEST_WITH_INITIALIZE;
const PROTOCOL_HEADER: &str = "mcp-protocol-version";
const SESSION_HEADER: &str = "mcp-session-id";
const ACCEPT_VALUE: &str = "application/json, text/event-stream";
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CATALOG_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOOL_PAGES: usize = 100;
const MAX_TOOLS: usize = 10_000;
const MAX_SESSION_ID_BYTES: usize = 512;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TERMINATION_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Default)]
pub struct EgressPolicy {
    pub allow_localhost: bool,
    pub allow_private_networks: bool,
    pub allowed_networks: Vec<IpNet>,
    pub blocked_networks: Vec<IpNet>,
    pub blocked_hosts: Vec<String>,
}

impl EgressPolicy {
    fn allows_address(&self, ip: IpAddr) -> bool {
        let canonical = ip.to_canonical();
        if self
            .blocked_networks
            .iter()
            .any(|network| network.contains(&ip) || network.contains(&canonical))
        {
            return false;
        }
        if canonical.is_loopback() {
            return self.allow_localhost;
        }
        let allowed_private = self.allow_private_networks
            || self
                .allowed_networks
                .iter()
                .any(|network| network.contains(&canonical));
        match canonical {
            IpAddr::V4(ip) => {
                if ip.is_private() {
                    return allowed_private;
                }
                !ip.is_link_local()
                    && !ip.is_documentation()
                    && !matches!(
                        ip.octets(),
                        [0, ..]
                            | [100, 64..=127, ..]
                            | [192, 0, 0, _]
                            | [192, 88, 99, _]
                            | [198, 18..=19, ..]
                            | [224..=255, ..]
                    )
            }
            IpAddr::V6(ip) => match ip.segments() {
                [0xfd00, 0, 0, 0, 0, 0, 0, 1] => false,
                [0xfc00..=0xfdff, ..] => allowed_private,
                [0x2001, 0..=0x01ff | 0x0db8, ..] | [0x2002, ..] | [0x3fff, 0..=0x0fff, ..] => {
                    false
                }
                [0x2000..=0x3fff, ..] => true,
                _ => false,
            },
        }
    }

    fn allows_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        !matches!(host, "metadata.google.internal" | "metadata.internal")
            && (self.allow_localhost || !matches!(host, "localhost" | "localhost.localdomain"))
            && !self
                .blocked_hosts
                .iter()
                .any(|blocked| blocked.trim_end_matches('.').eq_ignore_ascii_case(host))
    }

    fn validate_url(&self, endpoint: &str) -> Result<Url, UpstreamError> {
        let (scheme, authority_and_path) = endpoint
            .split_once("://")
            .ok_or(UpstreamError::InvalidUrl)?;
        let authority = authority_and_path
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if !["http", "https"]
            .iter()
            .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
            || authority.is_empty()
            || authority.contains('@')
            || endpoint.contains('\\')
            || endpoint
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(UpstreamError::InvalidUrl);
        }
        let url = Url::parse(endpoint).map_err(|_| UpstreamError::InvalidUrl)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.port() == Some(0)
        {
            return Err(UpstreamError::InvalidUrl);
        }

        let allowed = match url.host().ok_or(UpstreamError::InvalidUrl)? {
            Host::Domain(host) => self.allows_host(host),
            Host::Ipv4(ip) => self.allows_address(ip.into()) && self.allows_host(&ip.to_string()),
            Host::Ipv6(ip) => self.allows_address(ip.into()) && self.allows_host(&ip.to_string()),
        };
        if allowed {
            Ok(url)
        } else {
            Err(UpstreamError::BlockedDestination)
        }
    }
}

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("invalid upstream HTTP URL")]
    InvalidUrl,
    #[error("upstream destination is blocked by egress policy")]
    BlockedDestination,
    #[error("upstream hostname could not be resolved")]
    Resolve,
    #[error("upstream request timed out")]
    Timeout,
    #[error("upstream transport failed")]
    Transport,
    #[error("upstream returned HTTP {0}")]
    Status(u16),
    #[error("upstream message exceeded a size or pagination limit")]
    LimitExceeded,
    #[error("upstream returned an invalid MCP response")]
    InvalidResponse,
    #[error("upstream returned JSON-RPC error {code}")]
    Rpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },
}

impl From<reqwest::Error> for UpstreamError {
    fn from(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else {
            Self::Transport
        }
    }
}

#[derive(Clone)]
pub struct UpstreamClient {
    policy: EgressPolicy,
    timeout: Duration,
}

pub struct DiscoveredCatalog {
    pub capabilities: Value,
    pub tools: Vec<Value>,
}

impl UpstreamClient {
    pub fn new(policy: EgressPolicy, timeout: Duration) -> Self {
        Self { policy, timeout }
    }

    pub async fn list_tools(&self, url: &str) -> Result<DiscoveredCatalog, UpstreamError> {
        let (mut session, deadline) = self.open_session(url).await?;
        let result = timeout_at(deadline, session.list_tools()).await;
        session.close().await;
        result.map_err(|_| UpstreamError::Timeout)?
    }

    pub async fn call_tool(
        &self,
        url: &str,
        name: &str,
        arguments: Value,
    ) -> Result<Value, UpstreamError> {
        let Value::Object(arguments) = arguments else {
            return Err(UpstreamError::InvalidResponse);
        };
        let request = CallToolRequest::new(
            CallToolRequestParams::new(name.to_owned()).with_arguments(arguments),
        );
        let (mut session, deadline) = self.open_session(url).await?;
        let result = timeout_at(deadline, session.request(request.into())).await;
        session.close().await;
        result
            .map_err(|_| UpstreamError::Timeout)?
            .map(|reply| reply.result)
    }

    async fn open_session(&self, endpoint: &str) -> Result<(Session, Instant), UpstreamError> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(UpstreamError::Timeout)?;
        let mut session = timeout_at(deadline, self.connect(endpoint))
            .await
            .map_err(|_| UpstreamError::Timeout)??;
        let result = timeout_at(deadline, session.initialize())
            .await
            .unwrap_or(Err(UpstreamError::Timeout));
        if let Err(error) = result {
            session.close().await;
            return Err(error);
        }
        Ok((session, deadline))
    }

    async fn connect(&self, endpoint: &str) -> Result<Session, UpstreamError> {
        let url = self.policy.validate_url(endpoint)?;
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            .connect_timeout(CONNECT_TIMEOUT.min(self.timeout))
            .timeout(self.timeout)
            .dns_resolver(Arc::new(DenyDns))
            .tls_backend_preconfigured(tls_config()?);
        if let Some(domain) = url.domain() {
            let port = url
                .port_or_known_default()
                .ok_or(UpstreamError::InvalidUrl)?;
            let addresses = lookup_host((domain, port))
                .await
                .map_err(|_| UpstreamError::Resolve)?;
            let addresses = check_addresses(&self.policy, addresses)?;
            builder = builder.resolve_to_addrs(domain, &addresses);
        }
        Ok(Session {
            client: builder.build()?,
            url,
            capabilities: Value::Null,
            protocol_version: None,
            session_id: None,
            next_id: 1,
        })
    }
}

fn tls_config() -> Result<rustls::ClientConfig, UpstreamError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| UpstreamError::Transport)?
    .with_platform_verifier()
    .map_err(|_| UpstreamError::Transport)?
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tls)
}

fn check_addresses(
    policy: &EgressPolicy,
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, UpstreamError> {
    let mut seen = HashSet::new();
    let mut approved = Vec::new();
    for addr in addrs {
        if !policy.allows_address(addr.ip()) {
            return Err(UpstreamError::BlockedDestination);
        }
        if seen.insert(addr) {
            approved.push(addr);
        }
    }
    if approved.is_empty() {
        return Err(UpstreamError::Resolve);
    }
    Ok(approved)
}

struct DenyDns;

impl Resolve for DenyDns {
    fn resolve(&self, _name: Name) -> Resolving {
        Box::pin(async { Err(io::Error::other("the destination was not pinned").into()) })
    }
}

struct Session {
    client: Client,
    url: Url,
    capabilities: Value,
    protocol_version: Option<HeaderValue>,
    session_id: Option<HeaderValue>,
    next_id: i64,
}

impl Session {
    async fn initialize(&mut self) -> Result<(), UpstreamError> {
        let id = self.next_id;
        self.next_id += 1;
        let params = InitializeRequestParams::new(
            ClientCapabilities::default(),
            Implementation::new("context-forge-rs", env!("CARGO_PKG_VERSION")),
        )
        .with_protocol_version(PROTOCOL_VERSION);
        let request = InitializeRequest::new(params);
        let response = self
            .post(&ClientJsonRpcMessage::request(
                request.into(),
                RequestId::Number(id),
            ))
            .await?;

        self.session_id = read_session_id(&response)?;
        let reply = read_reply(response, id).await?;
        let requested = reply.result.get("protocolVersion").and_then(Value::as_str);
        let version = ProtocolVersion::KNOWN_VERSIONS
            .iter()
            .find(|known| known.has_initialize() && Some(known.as_str()) == requested)
            .ok_or(UpstreamError::InvalidResponse)?;
        self.capabilities = reply
            .result
            .get("capabilities")
            .filter(|capabilities| capabilities.is_object())
            .ok_or(UpstreamError::InvalidResponse)?
            .clone();
        self.protocol_version = Some(HeaderValue::from_static(version.as_str()));
        self.post(&ClientJsonRpcMessage::notification(
            InitializedNotification::default().into(),
        ))
        .await?;
        Ok(())
    }

    async fn list_tools(&mut self) -> Result<DiscoveredCatalog, UpstreamError> {
        let mut listed = Vec::new();
        let mut cursors = HashSet::new();
        let mut cursor = None;
        let mut received = 0usize;
        for _ in 0..MAX_TOOL_PAGES {
            let params = PaginatedRequestParams::default().with_cursor(cursor.take());
            let reply = self
                .request(ListToolsRequest::with_param(params).into())
                .await?;
            received += reply.bytes;
            let Value::Object(mut result) = reply.result else {
                return Err(UpstreamError::InvalidResponse);
            };
            let Some(Value::Array(tools)) = result.remove("tools") else {
                return Err(UpstreamError::InvalidResponse);
            };
            if received > MAX_CATALOG_BYTES || listed.len() + tools.len() > MAX_TOOLS {
                return Err(UpstreamError::LimitExceeded);
            }
            if tools.iter().any(|tool| {
                tool.get("name")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
            }) {
                return Err(UpstreamError::InvalidResponse);
            }
            listed.extend(tools);
            match result.remove("nextCursor") {
                Some(Value::String(next_cursor)) if !next_cursor.is_empty() => {
                    if !cursors.insert(next_cursor.clone()) {
                        return Err(UpstreamError::LimitExceeded);
                    }
                    cursor = Some(next_cursor);
                }
                None | Some(Value::Null | Value::String(_)) => {
                    return Ok(DiscoveredCatalog {
                        capabilities: self.capabilities.clone(),
                        tools: listed,
                    });
                }
                _ => return Err(UpstreamError::InvalidResponse),
            }
        }
        Err(UpstreamError::LimitExceeded)
    }

    async fn request(&mut self, request: ClientRequest) -> Result<Reply, UpstreamError> {
        let id = self.next_id;
        self.next_id += 1;
        let response = self
            .post(&ClientJsonRpcMessage::request(
                request,
                RequestId::Number(id),
            ))
            .await?;
        read_reply(response, id).await
    }

    fn request_builder(&self, method: Method) -> reqwest::RequestBuilder {
        let mut request = self
            .client
            .request(method, self.url.clone())
            .header(ACCEPT, ACCEPT_VALUE);
        if let Some(version) = &self.protocol_version {
            request = request.header(PROTOCOL_HEADER, version);
        }
        if let Some(id) = &self.session_id {
            request = request.header(SESSION_HEADER, id);
        }
        request
    }

    async fn post(&self, message: &ClientJsonRpcMessage) -> Result<Response, UpstreamError> {
        let bytes = serde_json::to_vec(message).map_err(|_| UpstreamError::InvalidResponse)?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(UpstreamError::LimitExceeded);
        }
        let response = self
            .request_builder(Method::POST)
            .header(CONTENT_TYPE, "application/json")
            .body(bytes)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(UpstreamError::Status(response.status().as_u16()));
        }
        Ok(response)
    }

    async fn close(self) {
        if self.session_id.is_some() {
            let _ = timeout(
                TERMINATION_TIMEOUT,
                self.request_builder(Method::DELETE).send(),
            )
            .await;
        }
    }
}

fn read_session_id(response: &Response) -> Result<Option<HeaderValue>, UpstreamError> {
    let mut ids = response.headers().get_all(SESSION_HEADER).iter();
    let Some(id) = ids.next() else {
        return Ok(None);
    };
    let bytes = id.as_bytes();
    if ids.next().is_some()
        || bytes.is_empty()
        || bytes.len() > MAX_SESSION_ID_BYTES
        || !bytes.iter().all(|b| (0x21..=0x7e).contains(b))
    {
        return Err(UpstreamError::InvalidResponse);
    }
    Ok(Some(id.clone()))
}

struct Reply {
    result: Value,
    bytes: usize,
}

async fn read_reply(mut response: Response, id: i64) -> Result<Reply, UpstreamError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MESSAGE_BYTES as u64)
    {
        return Err(UpstreamError::LimitExceeded);
    }
    let mut media_types = response.headers().get_all(CONTENT_TYPE).iter();
    let media_type = media_types
        .next()
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.split(';').next())
        .map(str::trim);
    if media_types.next().is_some() {
        return Err(UpstreamError::InvalidResponse);
    }
    let sse = match media_type {
        Some(media) if media.eq_ignore_ascii_case("application/json") => false,
        Some(media) if media.eq_ignore_ascii_case("text/event-stream") => true,
        _ => return Err(UpstreamError::InvalidResponse),
    };

    let mut received = 0;
    let mut body = Vec::new();
    let mut stream = SseDecoder::default();
    while let Some(chunk) = response.chunk().await? {
        received += chunk.len();
        if received > MAX_MESSAGE_BYTES {
            return Err(UpstreamError::LimitExceeded);
        }
        if sse {
            if let Some(result) = stream.feed(&chunk, id)? {
                return Ok(Reply {
                    result,
                    bytes: received,
                });
            }
        } else {
            body.extend_from_slice(&chunk);
        }
    }

    let result = if sse {
        return Err(UpstreamError::InvalidResponse);
    } else {
        take_result(&body, id)?.ok_or(UpstreamError::InvalidResponse)?
    };
    Ok(Reply {
        result,
        bytes: received,
    })
}

fn take_result(body: &[u8], id: i64) -> Result<Option<Value>, UpstreamError> {
    let message: JsonRpcMessage<Value, Value, Value> =
        serde_json::from_slice(body).map_err(|_| UpstreamError::InvalidResponse)?;
    let expected = RequestId::Number(id);
    match message {
        JsonRpcMessage::Response(response) if response.id == expected => Ok(Some(response.result)),
        JsonRpcMessage::Error(response) if response.id.as_ref() == Some(&expected) => {
            Err(UpstreamError::Rpc {
                code: i64::from(response.error.code.0),
                message: response.error.message.into_owned(),
                data: response.error.data,
            })
        }
        _ => Ok(None),
    }
}

#[derive(Default)]
struct SseDecoder {
    line: Vec<u8>,
    event: Vec<u8>,
    after_cr: bool,
    read_first_line: bool,
}

impl SseDecoder {
    fn feed(&mut self, chunk: &[u8], id: i64) -> Result<Option<Value>, UpstreamError> {
        for &byte in chunk {
            if std::mem::take(&mut self.after_cr) && byte == b'\n' {
                continue;
            }
            if byte != b'\r' && byte != b'\n' {
                self.line.push(byte);
                continue;
            }
            self.after_cr = byte == b'\r';
            let line = if !std::mem::replace(&mut self.read_first_line, true) {
                self.line
                    .strip_prefix(b"\xef\xbb\xbf")
                    .unwrap_or(&self.line)
            } else {
                &self.line
            };
            if line.is_empty() && !self.event.is_empty() {
                let result = take_result(&self.event, id)?;
                self.event.clear();
                if result.is_some() {
                    return Ok(result);
                }
            } else if let Some(data) = line.strip_prefix(b"data:") {
                if !self.event.is_empty() {
                    self.event.push(b'\n');
                }
                self.event
                    .extend_from_slice(data.strip_prefix(b" ").unwrap_or(data));
            }
            self.line.clear();
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        body::Body,
        http::{HeaderMap, StatusCode, header::LOCATION},
        response::{IntoResponse, Response as AxumResponse},
        routing::post,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{net::TcpListener, task::JoinHandle};

    async fn serve(router: Router, host: &str) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{host}:{port}/mcp"), task)
    }

    fn local_client() -> UpstreamClient {
        UpstreamClient::new(
            EgressPolicy {
                allow_localhost: true,
                ..EgressPolicy::default()
            },
            Duration::from_secs(5),
        )
    }

    fn check_session(headers: &HeaderMap) {
        assert_eq!(headers[SESSION_HEADER], "fixture-session");
        assert_eq!(headers[PROTOCOL_HEADER], "2025-06-18");
        assert_eq!(headers[ACCEPT], ACCEPT_VALUE);
    }

    async fn fixture(headers: HeaderMap, Json(request): Json<Value>) -> AxumResponse {
        let id = &request["id"];
        match request["method"].as_str().unwrap() {
            "initialize" => {
                assert_eq!(headers[ACCEPT], ACCEPT_VALUE);
                assert!(headers.get(PROTOCOL_HEADER).is_none());
                assert!(headers.get(SESSION_HEADER).is_none());
                assert_eq!(
                    request["params"]["protocolVersion"],
                    PROTOCOL_VERSION.as_str()
                );
                (
                    [(SESSION_HEADER, "fixture-session")],
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": { "tools": { "listChanged": true } },
                            "serverInfo": { "name": "fixture", "version": "1" },
                        }
                    })),
                )
                    .into_response()
            }
            "notifications/initialized" => {
                check_session(&headers);
                assert!(request.get("id").is_none());
                StatusCode::ACCEPTED.into_response()
            }
            "tools/list" => {
                check_session(&headers);
                let result = match request["params"]["cursor"].as_str() {
                    None => json!({"tools": [{"name": "first"}], "nextCursor": "page-two"}),
                    Some("page-two") => json!({"tools": [{"name": "second"}]}),
                    _ => panic!("unexpected cursor"),
                };
                Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
            }
            "tools/call" => {
                check_session(&headers);
                let reply = if request["params"]["name"] == "unknown" {
                    json!({"jsonrpc": "2.0", "id": id, "error":{"code": -32602, "message": "unknown tool", "data": {"field": "name"}}})
                } else {
                    let input = &request["params"]["arguments"]["input"];
                    json!({"jsonrpc": "2.0", "id": id, "result":{"content":[{"type":"text", "text":input}], "isError":false}})
                };
                (
                    [(CONTENT_TYPE, "text/event-stream; charset=utf-8")],
                    format!(": keepalive\r\n\r\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}}\r\n\r\nevent: message\r\ndata: {reply}\r\n\r\n"),
                ).into_response()
            }
            _ => StatusCode::BAD_REQUEST.into_response(),
        }
    }

    async fn end_fixture_session(headers: HeaderMap) -> StatusCode {
        check_session(&headers);
        StatusCode::NO_CONTENT
    }

    #[tokio::test]
    async fn legacy_catalog_and_invocation_follow_pinned_session() {
        let terminated = Arc::new(AtomicUsize::new(0));
        let terminated_sessions = terminated.clone();
        let (url, server) = serve(
            Router::new().route(
                "/mcp",
                post(fixture).delete(async move |headers| {
                    terminated_sessions.fetch_add(1, Ordering::Relaxed);
                    end_fixture_session(headers).await
                }),
            ),
            "localhost",
        )
        .await;
        let denied = UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(5));
        assert!(matches!(
            denied.list_tools(&url).await,
            Err(UpstreamError::BlockedDestination)
        ));

        let client = local_client();
        let catalog = client.list_tools(&url).await.unwrap();
        assert_eq!(catalog.capabilities, json!({"tools":{"listChanged":true}}));
        assert_eq!(
            catalog.tools,
            vec![json!({"name":"first"}), json!({"name":"second"})]
        );

        let result = client
            .call_tool(&url, "first", json!({"input":"hello"}))
            .await
            .unwrap();
        assert_eq!(
            result,
            json!({"content":[{"type":"text","text":"hello"}],"isError": false})
        );
        assert!(matches!(
            client.call_tool(&url, "unknown", json!({})).await,
            Err(UpstreamError::Rpc { code: -32602, message, data: Some(data) })
                if message == "unknown tool" && data == json!({"field": "name"})
        ));
        assert_eq!(terminated.load(Ordering::Relaxed), 3);
        server.abort();
    }

    #[tokio::test]
    async fn refuses_to_follow_a_repeated_cursor() {
        let app = Router::new().route(
            "/mcp",
            post(async |headers, Json(request): Json<Value>| {
                if request["method"] == "tools/list" {
                    return Json(json!({
                    "jsonrpc":"2.0", "id":request["id"], "result":{"tools":[],"nextCursor":"loop"}
                })).into_response();
                }
                fixture(headers, Json(request)).await
            })
            .delete(end_fixture_session),
        );
        let (url, server) = serve(app, "127.0.0.1").await;
        assert!(matches!(
            local_client().list_tools(&url).await,
            Err(UpstreamError::LimitExceeded)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn refuses_redirects() {
        let route = Router::new().route(
            "/mcp",
            post(|| async { (StatusCode::TEMPORARY_REDIRECT, [(LOCATION, "/archive")]) }),
        );
        let (url, server) = serve(route, "127.0.0.1").await;
        assert!(matches!(
            local_client().list_tools(&url).await,
            Err(UpstreamError::Status(307))
        ));
        server.abort();
    }

    #[tokio::test]
    async fn enforces_response_size_and_deadline() {
        let oversized = Router::new().route(
            "/mcp",
            post(|| async {
                (
                    [(CONTENT_TYPE, "application/json")],
                    Body::from(vec![b' '; MAX_MESSAGE_BYTES + 1]),
                )
            }),
        );
        let (url, server) = serve(oversized, "127.0.0.1").await;
        assert!(matches!(
            local_client().list_tools(&url).await,
            Err(UpstreamError::LimitExceeded)
        ));
        server.abort();

        let stalled = Router::new().route(
            "/mcp",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                StatusCode::OK
            }),
        );
        let (url, server) = serve(stalled, "127.0.0.1").await;
        let mut client = local_client();
        client.timeout = Duration::from_millis(50);
        assert!(matches!(
            client.list_tools(&url).await,
            Err(UpstreamError::Timeout)
        ));
        server.abort();
    }

    #[test]
    fn blocked_destinations_and_mixed_resolution_fail_closed() {
        let public = EgressPolicy::default();
        for url in [
            "http://localhost./mcp",
            "http://127.0.0.1/mcp",
            "http://[::ffff:127.0.0.1]/mcp",
            "https://10.0.0.1/mcp",
            "http://[fd00::1]/mcp",
            "https://metadata.google.internal/mcp",
        ] {
            assert!(
                matches!(
                    public.validate_url(url),
                    Err(UpstreamError::BlockedDestination)
                ),
                "{url}"
            );
        }
        for url in [
            "file:///etc/hosts",
            "http:///example.org/mcp",
            "http://user@example.org/mcp",
            "http://example.org/mcp#path",
            "http://example.org:0/mcp",
        ] {
            assert!(
                matches!(public.validate_url(url), Err(UpstreamError::InvalidUrl)),
                "{url}"
            );
        }
        let open = "8.8.8.8:443".parse().unwrap();
        let local = "127.0.0.1:443".parse().unwrap();
        assert_eq!(check_addresses(&public, [open, open]).unwrap(), vec![open]);
        assert!(matches!(
            check_addresses(&public, [open, local]),
            Err(UpstreamError::BlockedDestination)
        ));
        assert!(matches!(
            check_addresses(&public, []),
            Err(UpstreamError::Resolve)
        ));

        let internal = EgressPolicy {
            allow_localhost: true,
            allowed_networks: vec!["10.0.0.0/8".parse().unwrap()],
            blocked_networks: vec!["10.1.0.0/16".parse().unwrap()],
            ..EgressPolicy::default()
        };
        assert!(internal.validate_url("http://10.2.1.1/mcp").is_ok());
        assert!(internal.validate_url("http://127.0.0.1/mcp").is_ok());
        assert!(internal.validate_url("http://10.1.1.1/mcp").is_err());
        assert!(internal.validate_url("http://169.254.1.1/mcp").is_err());
    }

    #[test]
    fn sse_accepts_split_multiline_events_and_ignores_unmatched_ids() {
        let mut stream = SseDecoder::default();
        for chunk in [
            b"\xef\xbb".as_slice(),
            b"\xbfdata: {\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{}}\r",
            b"\n\r\ndata: {\"jsonrpc\":\"2.0\",\r\n",
            b"data: \"id\":2,\"result\":",
            b"{\"ok\":true}}\r\n",
        ] {
            assert!(stream.feed(chunk, 2).unwrap().is_none());
        }
        assert_eq!(stream.feed(b"\r\n", 2).unwrap(), Some(json!({"ok": true})));
    }
}
