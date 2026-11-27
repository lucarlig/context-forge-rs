// SPDX-License-Identifier: Apache-2.0
//! Outbound MCP Streamable HTTP and SSE over validated, pinned destinations.

use std::{
    collections::HashSet,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use axum::body::Bytes;
use base64::{Engine, prelude::BASE64_STANDARD};
use ipnet::IpNet;
use reqwest::{
    Client, Method, Response,
    dns::{Name, Resolve, Resolving},
    header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue},
};
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CancelledNotification, CancelledNotificationParam,
    ClientCapabilities, ClientJsonRpcMessage, ClientRequest, ClientResult, DiscoverRequest,
    DiscoverRequestParams, DiscoverResult, ErrorCode, ErrorData, GetMeta, Implementation,
    InitializeRequest, InitializeRequestParams, InitializedNotification, JsonRpcMessage,
    JsonRpcRequest, ListPromptsRequest, ListResourceTemplatesRequest, ListResourcesRequest,
    ListToolsRequest, PaginatedRequestParams, ProgressNotificationParam, ProgressToken, Prompt,
    ProtocolVersion, RequestId, RequestMetaObject, Resource, ResourceTemplate,
    ServerJsonRpcMessage, ServerNotification, ServerRequest, SubscriptionFilter,
    SubscriptionsListenRequest, SubscriptionsListenRequestParams,
};
use rustls_platform_verifier::BuilderVerifierExt;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    net::lookup_host,
    sync::{Mutex, mpsc},
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use crate::{
    credentials::{QueryValues, UpstreamCredentials},
    events::PassiveEvents,
    sessions::SessionLifetime,
};

const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::LATEST_WITH_INITIALIZE;
const MODERN_VERSION: ProtocolVersion = ProtocolVersion::V_2026_07_28;
const PROTOCOL_HEADER: &str = "mcp-protocol-version";
const SESSION_HEADER: &str = "mcp-session-id";
const METHOD_HEADER: &str = "mcp-method";
const NAME_HEADER: &str = "mcp-name";
const ACCEPT_VALUE: &str = "application/json, text/event-stream";
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CATALOG_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOOL_PAGES: usize = 100;
const MAX_TOOLS: usize = 10_000;
const MAX_SESSION_ID_BYTES: usize = 512;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const TERMINATION_TIMEOUT: Duration = Duration::from_millis(250);
const PROGRESS_SEND_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct ToolContext<'a> {
    pub(crate) cancellation: &'a CancellationToken,
    pub(crate) progress: Option<&'a ToolProgress>,
    pub(crate) notifications: Option<Arc<PassiveEvents>>,
    pub(crate) client_capabilities: Option<&'a ClientCapabilities>,
    pub(crate) request_headers: Option<&'a HeaderMap>,
}

pub(crate) struct ToolProgress {
    token: ProgressToken,
    sender: mpsc::Sender<ProgressNotificationParam>,
}

impl ToolProgress {
    pub(crate) fn channel(
        token: ProgressToken,
    ) -> (Self, mpsc::Receiver<ProgressNotificationParam>) {
        let (sender, receiver) = mpsc::channel(16);
        (Self { token, sender }, receiver)
    }
}

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
    #[error("upstream request cancelled")]
    Cancelled,
    #[error("upstream MCP session expired")]
    SessionExpired,
    #[error("upstream transport failed")]
    Transport,
    #[error("upstream returned HTTP {0}")]
    Status(u16),
    #[error("upstream message exceeded a size or pagination limit")]
    LimitExceeded,
    #[error("upstream returned an invalid MCP response")]
    InvalidResponse,
    #[error("upstream does not advertise MCP completions")]
    CompletionUnsupported,
    #[error("upstream returned JSON-RPC error {code}")]
    Rpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },
}

pub(crate) enum ResourceListenEvent {
    Acknowledged,
    Updated,
}

pub(crate) enum ResourceListenEnd {
    Legacy,
    Declined,
    Disconnected,
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

fn method_unavailable(error: &UpstreamError) -> bool {
    matches!(error, UpstreamError::Rpc { code, .. } if *code == i64::from(ErrorCode::METHOD_NOT_FOUND.0))
}

#[derive(Clone)]
pub struct UpstreamClient {
    policy: EgressPolicy,
    timeout: Duration,
    mode: ConnectMode,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConnectMode {
    #[default]
    Auto,
    Legacy,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UpstreamTransport {
    StreamableHttp,
    Sse,
}

impl UpstreamTransport {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("STREAMABLEHTTP") {
            Some(Self::StreamableHttp)
        } else if name.eq_ignore_ascii_case("SSE") {
            Some(Self::Sse)
        } else {
            None
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::StreamableHttp => "STREAMABLEHTTP",
            Self::Sse => "SSE",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct UpstreamEndpoint<'a> {
    pub url: &'a str,
    pub transport: UpstreamTransport,
    pub credentials: Option<&'a UpstreamCredentials>,
}

impl<'a> UpstreamEndpoint<'a> {
    fn streamable(url: &'a str) -> Self {
        Self {
            url,
            transport: UpstreamTransport::StreamableHttp,
            credentials: None,
        }
    }

    pub(crate) fn credential_fingerprint(self) -> Option<[u8; 32]> {
        let credentials = self.credentials.filter(|credentials| {
            !credentials.headers.is_empty() || !credentials.query.is_empty()
        })?;
        let mut entries: Vec<_> = credentials.headers.iter().collect();
        entries.sort_unstable_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));
        let mut hash = Sha256::new();
        hash.update((entries.len() as u64).to_be_bytes());
        for (name, value) in entries {
            hash_field(&mut hash, name.as_str().as_bytes());
            hash_field(&mut hash, value.as_bytes());
        }
        for (name, value) in &credentials.query {
            hash_field(&mut hash, name.as_bytes());
            hash_field(&mut hash, value.as_bytes());
        }
        Some(hash.finalize().into())
    }
}

fn hash_field(hash: &mut Sha256, field: &[u8]) {
    hash.update((field.len() as u64).to_be_bytes());
    hash.update(field);
}

pub struct DiscoveredCatalog {
    pub capabilities: Value,
    pub tools: Vec<Value>,
}

#[derive(Default)]
pub(crate) struct DiscoveredMetadata {
    pub(crate) resources: Vec<Resource>,
    pub(crate) templates: Vec<ResourceTemplate>,
    pub(crate) prompts: Vec<Prompt>,
}

pub(crate) struct UpstreamAssociation {
    lifetime: Arc<SessionLifetime>,
    connection: Mutex<Option<AssociatedConnection>>,
    operation: Mutex<()>,
}

struct AssociatedConnection {
    session: Arc<Session>,
    stop: CancellationToken,
}

impl Drop for AssociatedConnection {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl UpstreamAssociation {
    pub(crate) fn new(lifetime: Arc<SessionLifetime>) -> Self {
        Self {
            lifetime,
            connection: Mutex::new(None),
            operation: Mutex::new(()),
        }
    }

    async fn session(
        &self,
        upstream: &UpstreamClient,
        endpoint: UpstreamEndpoint<'_>,
        deadline: Instant,
        context: &ToolContext<'_>,
    ) -> Result<Arc<Session>, UpstreamError> {
        let mut connection = tokio::select! {
            biased;
            () = context.cancellation.cancelled() => return Err(UpstreamError::Cancelled),
            lock = timeout_at(deadline, self.connection.lock()) => lock.map_err(|_| UpstreamError::Timeout)?,
        };
        if let Some(connection) = connection.as_ref() {
            return Ok(connection.session.clone());
        }
        let session = Arc::new(upstream.open_session(endpoint, deadline).await?);
        let stop = CancellationToken::new();
        if session.session_id.is_some() || session.sse.is_some() {
            let session = session.clone();
            let stop = stop.clone();
            let lifetime = self.lifetime.clone();
            let notifications = context.notifications.clone();
            tokio::spawn(async move {
                let listener = async {
                    if session.sse.is_none()
                        && let Some(journal) = notifications.as_deref()
                    {
                        session.follow_notifications(journal).await;
                    }
                    std::future::pending::<()>().await;
                };
                tokio::select! {
                    biased;
                    () = stop.cancelled() => {},
                    () = lifetime.wait_until_closed() => {},
                    () = listener => {},
                }
                session.close().await;
            });
        }
        *connection = Some(AssociatedConnection {
            session: session.clone(),
            stop,
        });
        Ok(session)
    }

    async fn invalidate(&self, expired: &Arc<Session>) {
        let mut connection = self.connection.lock().await;
        if connection
            .as_ref()
            .is_some_and(|connection| Arc::ptr_eq(&connection.session, expired))
        {
            connection.take();
        }
    }
}

impl UpstreamClient {
    pub(crate) fn with_timeout_cap(&self, timeout: Duration) -> Self {
        Self {
            timeout: self.timeout.min(timeout),
            ..self.clone()
        }
    }

    pub fn new(policy: EgressPolicy, timeout: Duration) -> Self {
        Self {
            policy,
            timeout,
            mode: ConnectMode::default(),
        }
    }

    pub fn with_connect_mode(mut self, mode: ConnectMode) -> Self {
        self.mode = mode;
        self
    }

    pub async fn list_tools(&self, url: &str) -> Result<DiscoveredCatalog, UpstreamError> {
        let deadline = self.deadline()?;
        let session = self
            .open_session(UpstreamEndpoint::streamable(url), deadline)
            .await?;
        let result = timeout_at(deadline, session.list_tools()).await;
        session.close().await;
        result.map_err(|_| UpstreamError::Timeout)?
    }

    pub(crate) async fn discover_catalog(
        &self,
        endpoint: UpstreamEndpoint<'_>,
    ) -> Result<(DiscoveredCatalog, DiscoveredMetadata), UpstreamError> {
        let deadline = self.deadline()?;
        let session = self.open_session(endpoint, deadline).await?;
        let result = timeout_at(deadline, async {
            let catalog = match session.list_tools().await {
                Err(error)
                    if session.capabilities["tools"].is_null() && method_unavailable(&error) =>
                {
                    DiscoveredCatalog {
                        capabilities: session.capabilities.clone(),
                        tools: Vec::new(),
                    }
                }
                result => result?,
            };
            let mut metadata = DiscoveredMetadata::default();
            if session.capabilities["resources"].is_object() {
                metadata.resources = session
                    .list_metadata("resources", |params| {
                        ListResourcesRequest::with_param(params).into()
                    })
                    .await?;
                metadata.templates = match session
                    .list_metadata("resourceTemplates", |params| {
                        ListResourceTemplatesRequest::with_param(params).into()
                    })
                    .await
                {
                    Err(error) if method_unavailable(&error) => Vec::new(),
                    result => result?,
                };
            }
            if session.capabilities["prompts"].is_object() {
                metadata.prompts = session
                    .list_metadata("prompts", |params| {
                        ListPromptsRequest::with_param(params).into()
                    })
                    .await?;
            }
            Ok((catalog, metadata))
        })
        .await;
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
        self.call_tool_with_context(
            UpstreamEndpoint::streamable(url),
            CallToolRequestParams::new(name.to_owned()).with_arguments(arguments),
            ToolContext {
                cancellation: &CancellationToken::new(),
                progress: None,
                notifications: None,
                client_capabilities: None,
                request_headers: None,
            },
            None,
        )
        .await
    }

    pub(crate) async fn call_tool_with_context(
        &self,
        endpoint: UpstreamEndpoint<'_>,
        mut params: CallToolRequestParams,
        context: ToolContext<'_>,
        association: Option<&UpstreamAssociation>,
    ) -> Result<Value, UpstreamError> {
        params.meta = None;
        params.arguments.get_or_insert_default();
        self.request_with_context(
            endpoint,
            CallToolRequest::new(params).into(),
            context,
            association,
        )
        .await
    }

    pub(crate) async fn request_with_context(
        &self,
        endpoint: UpstreamEndpoint<'_>,
        mut request: ClientRequest,
        context: ToolContext<'_>,
        association: Option<&UpstreamAssociation>,
    ) -> Result<Value, UpstreamError> {
        let cancellation = context.cancellation;
        if cancellation.is_cancelled() {
            return Err(UpstreamError::Cancelled);
        }
        if let Some(identity) = endpoint
            .credentials
            .and_then(|credentials| credentials.identity_meta.as_ref())
        {
            request
                .get_meta_mut()
                .insert("user".into(), identity.clone());
        }
        let deadline = self.deadline()?;
        let _operation = if let Some(association) = association {
            Some(tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(UpstreamError::Cancelled),
                lock = timeout_at(deadline, association.operation.lock()) => {
                    lock.map_err(|_| UpstreamError::Timeout)?
                }
            })
        } else {
            None
        };
        let session = match association {
            Some(association) => {
                association
                    .session(self, endpoint, deadline, &context)
                    .await?
            }
            None => Arc::new(self.open_session(endpoint, deadline).await?),
        };
        if cancellation.is_cancelled() {
            if association.is_none() {
                session.close().await;
            }
            return Err(UpstreamError::Cancelled);
        }
        let id = session.next_request_id();
        let mut started = false;
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(UpstreamError::Cancelled),
            result = timeout_at(deadline, async {
                if matches!(request, ClientRequest::CompleteRequest(_))
                    && !session.capabilities["completions"].is_object()
                {
                    return Err(UpstreamError::CompletionUnsupported);
                }
                started = true;
                session.request_with_id(request, id, Some(&context)).await
            }) => {
                result.unwrap_or(Err(UpstreamError::Timeout)).map(|reply| reply.result)
            }
        };
        if started
            && matches!(
                result,
                Err(UpstreamError::Cancelled | UpstreamError::Timeout)
            )
        {
            session.cancel(id).await;
        }
        match association {
            Some(association) if matches!(result, Err(UpstreamError::SessionExpired)) => {
                association.invalidate(&session).await;
            }
            None => session.close().await,
            _ => {}
        }
        result
    }

    pub(crate) async fn listen_resource(
        &self,
        endpoint: &str,
        uri: &str,
        mut on_event: impl FnMut(ResourceListenEvent),
    ) -> Result<ResourceListenEnd, UpstreamError> {
        let deadline = self.deadline()?;
        let session = self
            .open_session(UpstreamEndpoint::streamable(endpoint), deadline)
            .await?;
        let Some(version) = session
            .protocol_version
            .as_ref()
            .filter(|version| !version.has_initialize())
        else {
            session.close().await;
            return Ok(ResourceListenEnd::Legacy);
        };
        let filter = SubscriptionFilter::builder()
            .resource_subscription(uri)
            .build();
        let request =
            SubscriptionsListenRequest::new(SubscriptionsListenRequestParams::new(filter));
        let (mut response, id) = timeout_at(
            deadline,
            session.send_request(request.into(), Some(version), false),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)??;
        if !response.status().is_success() {
            return Err(UpstreamError::Status(response.status().as_u16()));
        }
        if !response_media_type(&response)
            .is_some_and(|media| media.eq_ignore_ascii_case("text/event-stream"))
        {
            return Err(UpstreamError::InvalidResponse);
        }

        let subscription_id = RequestId::Number(id);
        let mut decoder = SseDecoder::default();
        let mut acknowledged = false;
        loop {
            let chunk = if acknowledged {
                response.chunk().await?
            } else {
                timeout_at(deadline, response.chunk())
                    .await
                    .map_err(|_| UpstreamError::Timeout)??
            };
            let Some(chunk) = chunk else {
                break;
            };
            if chunk.len() > MAX_MESSAGE_BYTES {
                return Err(UpstreamError::LimitExceeded);
            }
            let mut bytes = chunk.as_ref();
            while let Some(frame) = decoder.next_frame(&mut bytes) {
                if frame.len() > MAX_MESSAGE_BYTES {
                    return Err(UpstreamError::LimitExceeded);
                }
                let message = decode_message(&frame)?;
                let JsonRpcMessage::Notification(notification) = message else {
                    if take_result(message, id)?.is_some() {
                        return Ok(ResourceListenEnd::Disconnected);
                    }
                    continue;
                };
                let Ok(notification) = ServerNotification::deserialize(notification.notification)
                else {
                    continue;
                };
                if notification.get_meta().subscription_id() != Some(subscription_id.clone()) {
                    continue;
                }
                match notification {
                    ServerNotification::SubscriptionsAcknowledgedNotification(ack)
                        if !acknowledged =>
                    {
                        if !ack
                            .params
                            .notifications
                            .resource_subscriptions
                            .as_ref()
                            .is_some_and(|uris| uris.iter().any(|accepted| accepted == uri))
                        {
                            return Ok(ResourceListenEnd::Declined);
                        }
                        acknowledged = true;
                        on_event(ResourceListenEvent::Acknowledged);
                    }
                    ServerNotification::ResourceUpdatedNotification(update)
                        if acknowledged && update.params.uri == uri =>
                    {
                        on_event(ResourceListenEvent::Updated);
                    }
                    ServerNotification::CancelledNotification(cancel)
                        if cancel.params.request_id == Some(subscription_id.clone()) =>
                    {
                        return Ok(ResourceListenEnd::Disconnected);
                    }
                    _ => {}
                }
            }
            if decoder.line.len() + decoder.event.len() > MAX_MESSAGE_BYTES {
                return Err(UpstreamError::LimitExceeded);
            }
        }
        Ok(ResourceListenEnd::Disconnected)
    }

    fn deadline(&self) -> Result<Instant, UpstreamError> {
        Instant::now()
            .checked_add(self.timeout)
            .ok_or(UpstreamError::Timeout)
    }

    async fn open_session(
        &self,
        endpoint: UpstreamEndpoint<'_>,
        deadline: Instant,
    ) -> Result<Session, UpstreamError> {
        let mut session = timeout_at(deadline, self.connect(endpoint))
            .await
            .map_err(|_| UpstreamError::Timeout)??;
        let result = timeout_at(deadline, async {
            match (endpoint.transport, self.mode) {
                (UpstreamTransport::Sse, _) => {
                    session.open_sse().await?;
                    session.initialize().await
                }
                (UpstreamTransport::StreamableHttp, ConnectMode::Auto) => session.negotiate().await,
                (UpstreamTransport::StreamableHttp, ConnectMode::Legacy) => {
                    session.initialize().await
                }
            }
        })
        .await
        .unwrap_or(Err(UpstreamError::Timeout));
        if let Err(error) = result {
            session.close().await;
            return Err(error);
        }
        Ok(session)
    }

    async fn connect(&self, endpoint: UpstreamEndpoint<'_>) -> Result<Session, UpstreamError> {
        let url = self.policy.validate_url(endpoint.url)?;
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            .connect_timeout(CONNECT_TIMEOUT.min(self.timeout))
            .dns_resolver(Arc::new(DenyDns))
            .tls_backend_preconfigured(tls_config()?);
        if let Some(credentials) = endpoint.credentials {
            builder = builder.default_headers(credentials.headers.clone());
        }
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
            sse: None,
            query: endpoint
                .credentials
                .map_or_else(QueryValues::new, |credentials| credentials.query.clone()),
            next_id: AtomicI64::new(1),
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
    protocol_version: Option<ProtocolVersion>,
    session_id: Option<HeaderValue>,
    sse: Option<Mutex<Option<SseStream>>>,
    query: QueryValues,
    next_id: AtomicI64,
}

impl Session {
    async fn open_sse(&mut self) -> Result<(), UpstreamError> {
        let response = self.request_builder(Method::GET, None).send().await?;
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        if !response_media_type(&response)
            .is_some_and(|media| media.eq_ignore_ascii_case("text/event-stream"))
        {
            return Err(UpstreamError::InvalidResponse);
        }
        let mut inbox = SseStream::new(response);
        while let Some(frame) = inbox.next().await? {
            if inbox.decoder.event_type.as_deref() != Some("endpoint") {
                continue;
            }
            self.url = resolve_sse_endpoint(&self.url, &frame)?;
            self.sse = Some(Mutex::new(Some(inbox)));
            return Ok(());
        }
        Err(UpstreamError::InvalidResponse)
    }

    async fn negotiate(&mut self) -> Result<(), UpstreamError> {
        for first_attempt in [true, false] {
            match timeout(DISCOVERY_TIMEOUT, self.discover()).await {
                Ok(Ok(true)) => return Ok(()),
                Ok(Ok(false)) => return self.initialize().await,
                Ok(Err(error)) => {
                    if let Some(supported) = supported_versions(&error) {
                        if first_attempt && supported.contains(&MODERN_VERSION) {
                            continue;
                        }
                        if !supported.iter().any(is_handshake_version) {
                            return Err(error);
                        }
                    }
                    if !matches!(
                        error,
                        UpstreamError::Rpc { .. }
                            | UpstreamError::Status(300..=599)
                            | UpstreamError::InvalidResponse
                    ) {
                        return Err(error);
                    }
                }
                Err(_) => {}
            }

            let result = self.initialize().await;
            if first_attempt
                && result
                    .as_ref()
                    .err()
                    .and_then(supported_versions)
                    .is_some_and(|supported| supported.contains(&MODERN_VERSION))
            {
                self.close().await;
                self.session_id = None;
                self.protocol_version = None;
            } else {
                return result;
            }
        }
        Err(UpstreamError::InvalidResponse)
    }

    async fn discover(&mut self) -> Result<bool, UpstreamError> {
        let (response, id) = self
            .send_request(
                DiscoverRequest::new(DiscoverRequestParams {}).into(),
                Some(&MODERN_VERSION),
                false,
            )
            .await?;
        let mut reply = read_reply(self, response, id, None, None).await?;
        let Some(fields) = reply.result.as_object_mut() else {
            return Ok(false);
        };
        fields
            .entry("resultType")
            .or_insert_with(|| "complete".into());
        fields
            .entry("cacheScope")
            .or_insert_with(|| "private".into());
        let ttl = fields.entry("ttlMs").or_insert_with(|| 0.into());
        if ttl.as_f64().is_some_and(|ttl| ttl < 0.) {
            *ttl = 0.into();
        }
        let Ok(discovery) = DiscoverResult::deserialize(&reply.result) else {
            return Ok(false);
        };
        if !discovery.supported_versions.contains(&MODERN_VERSION) {
            return Ok(false);
        }
        self.capabilities = reply
            .result
            .get("capabilities")
            .cloned()
            .ok_or(UpstreamError::InvalidResponse)?;
        self.protocol_version = Some(MODERN_VERSION);
        Ok(true)
    }

    async fn initialize(&mut self) -> Result<(), UpstreamError> {
        let params = InitializeRequestParams::new(ClientCapabilities::default(), client_info())
            .with_protocol_version(PROTOCOL_VERSION);
        let request = InitializeRequest::new(params);
        let (response, id) = self.send_request(request.into(), None, false).await?;

        if self.sse.is_none() {
            self.session_id = read_session_id(&response)?;
        }
        let reply = read_reply(self, response, id, None, None).await?;
        let requested = reply.result.get("protocolVersion").and_then(Value::as_str);
        let version = ProtocolVersion::KNOWN_VERSIONS
            .iter()
            .find(|known| is_handshake_version(known) && Some(known.as_str()) == requested)
            .ok_or(UpstreamError::InvalidResponse)?;
        self.capabilities = reply
            .result
            .get("capabilities")
            .filter(|capabilities| capabilities.is_object())
            .ok_or(UpstreamError::InvalidResponse)?
            .clone();
        self.protocol_version = Some(version.clone());
        self.post(
            &ClientJsonRpcMessage::notification(InitializedNotification::default().into()),
            Some(version),
        )
        .await?;
        Ok(())
    }

    async fn list_tools(&self) -> Result<DiscoveredCatalog, UpstreamError> {
        let tools = self
            .list_items("tools", |params| {
                ListToolsRequest::with_param(params).into()
            })
            .await?;
        Ok(DiscoveredCatalog {
            capabilities: self.capabilities.clone(),
            tools,
        })
    }

    async fn list_metadata<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        request: impl Fn(PaginatedRequestParams) -> ClientRequest,
    ) -> Result<Vec<T>, UpstreamError> {
        self.list_items(key, request)
            .await?
            .into_iter()
            .map(|item| serde_json::from_value(item).map_err(|_| UpstreamError::InvalidResponse))
            .collect()
    }

    async fn list_items(
        &self,
        key: &str,
        request: impl Fn(PaginatedRequestParams) -> ClientRequest,
    ) -> Result<Vec<Value>, UpstreamError> {
        let mut listed = Vec::new();
        let mut cursors = HashSet::new();
        let mut cursor = None;
        let mut received = 0usize;
        for _ in 0..MAX_TOOL_PAGES {
            let params = PaginatedRequestParams::default().with_cursor(cursor.take());
            let reply = self
                .request_with_id(request(params), self.next_request_id(), None)
                .await?;
            received += reply.bytes;
            let Value::Object(mut result) = reply.result else {
                return Err(UpstreamError::InvalidResponse);
            };
            let Some(Value::Array(items)) = result.remove(key) else {
                return Err(UpstreamError::InvalidResponse);
            };
            if received > MAX_CATALOG_BYTES || listed.len() + items.len() > MAX_TOOLS {
                return Err(UpstreamError::LimitExceeded);
            }
            if items.iter().any(|item| {
                item.get("name")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
            }) {
                return Err(UpstreamError::InvalidResponse);
            }
            listed.extend(items);
            match result.remove("nextCursor") {
                Some(Value::String(next_cursor)) if !next_cursor.is_empty() => {
                    if !cursors.insert(next_cursor.clone()) {
                        return Err(UpstreamError::LimitExceeded);
                    }
                    cursor = Some(next_cursor);
                }
                None | Some(Value::Null | Value::String(_)) => {
                    return Ok(listed);
                }
                _ => return Err(UpstreamError::InvalidResponse),
            }
        }
        Err(UpstreamError::LimitExceeded)
    }

    async fn request_with_id(
        &self,
        request: ClientRequest,
        id: i64,
        context: Option<&ToolContext<'_>>,
    ) -> Result<Reply, UpstreamError> {
        let progress = context.and_then(|context| context.progress);
        let response = self
            .post_request(
                request,
                id,
                self.protocol_version.as_ref(),
                progress.is_some(),
                context.and_then(|context| context.client_capabilities),
            )
            .await?;
        let notifications = context.and_then(|context| context.notifications.as_deref());
        read_reply(self, response, id, progress, notifications).await
    }

    fn next_request_id(&self) -> i64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn send_request(
        &self,
        request: ClientRequest,
        version: Option<&ProtocolVersion>,
        report_progress: bool,
    ) -> Result<(Response, i64), UpstreamError> {
        let id = self.next_request_id();
        let response = self
            .post_request(request, id, version, report_progress, None)
            .await?;
        Ok((response, id))
    }

    async fn post_request(
        &self,
        mut request: ClientRequest,
        id: i64,
        version: Option<&ProtocolVersion>,
        report_progress: bool,
        client_capabilities: Option<&ClientCapabilities>,
    ) -> Result<Response, UpstreamError> {
        if let Some(version) = version.filter(|version| !version.has_initialize()) {
            let client = RequestMetaObject::with_client_context(
                version.clone(),
                client_info(),
                client_capabilities.cloned().unwrap_or_default(),
            );
            request.get_meta_mut().extend(client);
        }
        if report_progress {
            request
                .get_meta_mut()
                .set_progress_token(ProgressToken(RequestId::Number(id)));
        }
        self.post(
            &ClientJsonRpcMessage::request(request, RequestId::Number(id)),
            version,
        )
        .await
    }

    fn request_builder(
        &self,
        method: Method,
        version: Option<&ProtocolVersion>,
    ) -> reqwest::RequestBuilder {
        let mut url = self.url.clone();
        if !self.query.is_empty() {
            let retained: Vec<_> = url
                .query_pairs()
                .filter(|(name, _)| !self.query.contains_key(name.as_ref()))
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect();
            url.query_pairs_mut()
                .clear()
                .extend_pairs(retained)
                .extend_pairs(&self.query);
        }
        let mut request = self.client.request(method.clone(), url).header(
            ACCEPT,
            if method == Method::GET {
                "text/event-stream"
            } else {
                ACCEPT_VALUE
            },
        );
        if let Some(version) = version {
            request = request.header(PROTOCOL_HEADER, version.as_str());
        }
        if version.is_none_or(ProtocolVersion::has_initialize)
            && let Some(id) = &self.session_id
        {
            request = request.header(SESSION_HEADER, id);
        }
        request
    }

    async fn post(
        &self,
        message: &ClientJsonRpcMessage,
        version: Option<&ProtocolVersion>,
    ) -> Result<Response, UpstreamError> {
        let bytes = serde_json::to_vec(message).map_err(|_| UpstreamError::InvalidResponse)?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(UpstreamError::LimitExceeded);
        }
        let mut request = self.request_builder(Method::POST, version);
        if version.is_some_and(|version| !version.has_initialize())
            && let ClientJsonRpcMessage::Request(message) = message
        {
            request = request.header(METHOD_HEADER, message.request.method());
            let name = match &message.request {
                ClientRequest::CallToolRequest(call) => Some(call.params.name.as_ref()),
                ClientRequest::ReadResourceRequest(read) => Some(read.params.uri.as_str()),
                ClientRequest::GetPromptRequest(prompt) => Some(prompt.params.name.as_str()),
                _ => None,
            };
            if let Some(name) = name {
                request = request.header(NAME_HEADER, scoped_name_header(name)?);
            }
        }
        let response = request
            .header(CONTENT_TYPE, "application/json")
            .body(bytes)
            .send()
            .await?;
        if response.status().is_success() {
            Ok(response)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND
            && (self.session_id.is_some() || self.sse.is_some())
            && version.is_some_and(ProtocolVersion::has_initialize)
        {
            Err(UpstreamError::SessionExpired)
        } else {
            Err(http_error(response).await)
        }
    }

    async fn cancel(&self, id: i64) {
        let message = ClientJsonRpcMessage::notification(
            CancelledNotification::new(CancelledNotificationParam::new(
                Some(RequestId::Number(id)),
                None,
            ))
            .into(),
        );
        let _ = timeout(
            TERMINATION_TIMEOUT,
            self.post(&message, self.protocol_version.as_ref()),
        )
        .await;
    }

    async fn close(&self) {
        if let Some(inbox) = &self.sse
            && let Ok(mut inbox) = timeout(TERMINATION_TIMEOUT, inbox.lock()).await
        {
            inbox.take();
        }
        if self.session_id.is_some() {
            let request = self.request_builder(Method::DELETE, self.protocol_version.as_ref());
            let _ = timeout(TERMINATION_TIMEOUT, request.send()).await;
        }
    }

    async fn answer_server_request(&self, request: JsonRpcRequest<Value>) {
        let Some(version) = self
            .protocol_version
            .as_ref()
            .filter(|version| version.has_initialize())
        else {
            return;
        };
        let Ok(method) = ServerRequest::deserialize(&request.request) else {
            return;
        };
        let unavailable = match method {
            ServerRequest::PingRequest(_) => None,
            ServerRequest::ListRootsRequest(_) => Some("List roots not supported"),
            ServerRequest::CreateMessageRequest(_) => Some("Sampling not supported"),
            ServerRequest::ElicitRequest(_) => Some("Elicitation not supported"),
            _ => return,
        };
        let reply = match unavailable {
            Some(message) => ClientJsonRpcMessage::error(
                ErrorData::invalid_request(message, None),
                Some(request.id),
            ),
            None => ClientJsonRpcMessage::response(ClientResult::empty(()), request.id),
        };
        if !matches!(
            timeout(CONNECT_TIMEOUT, self.post(&reply, Some(version))).await,
            Ok(Ok(_))
        ) {
            tracing::debug!("upstream MCP server request reply failed");
        }
    }

    async fn follow_notifications(&self, journal: &PassiveEvents) {
        let mut cursor = None;
        loop {
            match self.notification_stream(journal, &mut cursor).await {
                Ok(())
                | Err(
                    UpstreamError::Transport
                    | UpstreamError::Timeout
                    | UpstreamError::Status(429 | 500..=599),
                ) => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(error) => {
                    tracing::debug!(%error, "upstream passive MCP stream ended");
                    return;
                }
            }
        }
    }

    async fn notification_stream(
        &self,
        journal: &PassiveEvents,
        cursor: &mut Option<HeaderValue>,
    ) -> Result<(), UpstreamError> {
        let mut request = self.request_builder(Method::GET, self.protocol_version.as_ref());
        if let Some(id) = cursor {
            request = request.header("last-event-id", id.clone());
        }
        let mut response = timeout(CONNECT_TIMEOUT, request.send())
            .await
            .map_err(|_| UpstreamError::Timeout)??;
        if !response.status().is_success() {
            return Err(UpstreamError::Status(response.status().as_u16()));
        }
        if !response_media_type(&response)
            .is_some_and(|media| media.eq_ignore_ascii_case("text/event-stream"))
        {
            return Err(UpstreamError::InvalidResponse);
        }
        let mut stream = SseDecoder {
            last_event_id: cursor.clone(),
            ..SseDecoder::default()
        };
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > MAX_MESSAGE_BYTES {
                return Err(UpstreamError::LimitExceeded);
            }
            let mut bytes = chunk.as_ref();
            while let Some(frame) = stream.next_frame(&mut bytes) {
                if frame.len() > MAX_MESSAGE_BYTES {
                    return Err(UpstreamError::LimitExceeded);
                }
                match decode_message(&frame) {
                    Ok(JsonRpcMessage::Notification(notification)) => {
                        publish_notification(journal, &notification.notification).await;
                    }
                    Ok(JsonRpcMessage::Request(request)) => {
                        self.answer_server_request(request).await
                    }
                    _ => {}
                }
            }
            if stream.line.len() + stream.event.len() > MAX_MESSAGE_BYTES {
                return Err(UpstreamError::LimitExceeded);
            }
            *cursor = stream.last_event_id.clone();
        }
        Ok(())
    }
}

pub struct SseStream {
    response: Response,
    buffered: Bytes,
    decoder: SseDecoder,
}

impl SseStream {
    pub fn new(response: Response) -> Self {
        Self {
            response,
            buffered: Bytes::new(),
            decoder: SseDecoder::default(),
        }
    }

    pub fn event_type(&self) -> Option<&str> {
        self.decoder.event_type.as_deref()
    }

    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, UpstreamError> {
        loop {
            if self.buffered.is_empty() {
                let Some(chunk) = self.response.chunk().await? else {
                    return Ok(None);
                };
                if chunk.len() > MAX_MESSAGE_BYTES {
                    return Err(UpstreamError::LimitExceeded);
                }
                self.buffered = chunk;
            }
            let mut remaining = self.buffered.as_ref();
            let frame = self.decoder.next_frame(&mut remaining);
            self.buffered = self.buffered.slice(self.buffered.len() - remaining.len()..);
            if frame
                .as_ref()
                .is_some_and(|frame| frame.len() > MAX_MESSAGE_BYTES)
                || self.decoder.line.len() + self.decoder.event.len() > MAX_MESSAGE_BYTES
            {
                return Err(UpstreamError::LimitExceeded);
            }
            if frame.is_some() {
                return Ok(frame);
            }
        }
    }
}

pub fn resolve_sse_endpoint(origin: &Url, event: &[u8]) -> Result<Url, UpstreamError> {
    let address = std::str::from_utf8(event).map_err(|_| UpstreamError::InvalidResponse)?;
    let endpoint = origin
        .join(address.trim())
        .map_err(|_| UpstreamError::InvalidResponse)?;
    if endpoint.origin() != origin.origin()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(UpstreamError::BlockedDestination);
    }
    Ok(endpoint)
}

fn client_info() -> Implementation {
    Implementation::new("context-forge-rs", env!("CARGO_PKG_VERSION"))
}

fn is_handshake_version(version: &ProtocolVersion) -> bool {
    version.has_initialize() && ProtocolVersion::KNOWN_VERSIONS.contains(version)
}

#[derive(Deserialize)]
struct UnsupportedVersion {
    supported: Vec<ProtocolVersion>,
    #[serde(rename = "requested")]
    _requested: String,
}

fn supported_versions(error: &UpstreamError) -> Option<Vec<ProtocolVersion>> {
    let UpstreamError::Rpc {
        code,
        data: Some(data),
        ..
    } = error
    else {
        return None;
    };
    if *code == i64::from(ErrorCode::UNSUPPORTED_PROTOCOL_VERSION.0) {
        return UnsupportedVersion::deserialize(data)
            .ok()
            .map(|error| error.supported);
    }
    None
}

fn scoped_name_header(name: &str) -> Result<HeaderValue, UpstreamError> {
    if name == name.trim()
        && name.bytes().all(|value| (0x20..=0x7e).contains(&value))
        && !(name.starts_with("=?base64?") && name.ends_with("?="))
    {
        HeaderValue::from_str(name).map_err(|_| UpstreamError::InvalidResponse)
    } else {
        let encoded = format!("=?base64?{}?=", BASE64_STANDARD.encode(name));
        HeaderValue::from_str(&encoded).map_err(|_| UpstreamError::InvalidResponse)
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

fn check_message_length(response: &Response) -> Result<(), UpstreamError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MESSAGE_BYTES as u64)
    {
        return Err(UpstreamError::LimitExceeded);
    }
    Ok(())
}

fn response_media_type(response: &Response) -> Option<&str> {
    let mut media_types = response.headers().get_all(CONTENT_TYPE).iter();
    let media_type = media_types
        .next()
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.split(';').next())
        .map(str::trim);
    media_type.filter(|_| media_types.next().is_none())
}

async fn read_json_body(mut response: Response) -> Result<Vec<u8>, UpstreamError> {
    check_message_length(&response)?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_MESSAGE_BYTES {
            return Err(UpstreamError::LimitExceeded);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn http_error(response: Response) -> UpstreamError {
    let status = response.status();
    if (status.is_client_error() || status.is_server_error())
        && response_media_type(&response)
            .is_some_and(|media| media.eq_ignore_ascii_case("application/json"))
    {
        let body = match read_json_body(response).await {
            Ok(body) => body,
            Err(error) => return error,
        };
        if let Ok(JsonRpcMessage::Error(response)) =
            serde_json::from_slice::<JsonRpcMessage<Value, Value, Value>>(&body)
        {
            return rpc_error(response.error);
        }
    }
    UpstreamError::Status(status.as_u16())
}

type WireMessage = JsonRpcMessage<Value, Value, Value>;

async fn read_reply(
    session: &Session,
    mut response: Response,
    id: i64,
    mut progress: Option<&ToolProgress>,
    notifications: Option<&PassiveEvents>,
) -> Result<Reply, UpstreamError> {
    if let Some(inbox) = &session.sse {
        let mut inbox = inbox.lock().await;
        let inbox = inbox.as_mut().ok_or(UpstreamError::SessionExpired)?;
        let mut received = 0;
        while let Some(frame) = inbox.next().await? {
            received += frame.len();
            if received > MAX_MESSAGE_BYTES {
                return Err(UpstreamError::LimitExceeded);
            }
            if !matches!(inbox.decoder.event_type.as_deref(), None | Some("message")) {
                continue;
            }
            if let Some(result) =
                handle_reply_frame(session, &frame, id, &mut progress, notifications).await?
            {
                return Ok(Reply {
                    result,
                    bytes: received,
                });
            }
        }
        return Err(UpstreamError::SessionExpired);
    }
    check_message_length(&response)?;
    match response_media_type(&response) {
        Some(media) if media.eq_ignore_ascii_case("application/json") => {
            let body = read_json_body(response).await?;
            let result =
                take_result(decode_message(&body)?, id)?.ok_or(UpstreamError::InvalidResponse)?;
            return Ok(Reply {
                result,
                bytes: body.len(),
            });
        }
        Some(media) if media.eq_ignore_ascii_case("text/event-stream") => {}
        _ => return Err(UpstreamError::InvalidResponse),
    }

    let mut received = 0;
    let mut stream = SseDecoder::default();
    while let Some(chunk) = response.chunk().await? {
        received += chunk.len();
        if received > MAX_MESSAGE_BYTES {
            return Err(UpstreamError::LimitExceeded);
        }
        let mut bytes = chunk.as_ref();
        while let Some(frame) = stream.next_frame(&mut bytes) {
            if let Some(result) =
                handle_reply_frame(session, &frame, id, &mut progress, notifications).await?
            {
                return Ok(Reply {
                    result,
                    bytes: received,
                });
            }
        }
    }
    Err(UpstreamError::InvalidResponse)
}

async fn handle_reply_frame(
    session: &Session,
    frame: &[u8],
    id: i64,
    progress: &mut Option<&ToolProgress>,
    notifications: Option<&PassiveEvents>,
) -> Result<Option<Value>, UpstreamError> {
    let message = decode_message(frame)?;
    if let JsonRpcMessage::Request(request) = message {
        session.answer_server_request(request).await;
        return Ok(None);
    }
    if let JsonRpcMessage::Notification(notification) = &message {
        if let Some(relay) = progress
            && let Some(params) = matching_progress(&notification.notification, id, &relay.token)
            && !matches!(
                timeout(PROGRESS_SEND_TIMEOUT, relay.sender.send(params)).await,
                Ok(Ok(()))
            )
        {
            *progress = None;
        }
        if let Some(journal) = notifications {
            publish_notification(journal, &notification.notification).await;
        }
    }
    take_result(message, id)
}

async fn publish_notification(journal: &PassiveEvents, payload: &Value) {
    let Ok(notification) = ServerNotification::deserialize(payload) else {
        return;
    };
    if !matches!(
        notification,
        ServerNotification::LoggingMessageNotification(_)
            | ServerNotification::ToolListChangedNotification(_)
            | ServerNotification::ResourceListChangedNotification(_)
            | ServerNotification::ResourceUpdatedNotification(_)
            | ServerNotification::PromptListChangedNotification(_)
    ) {
        return;
    }
    if let Ok(encoded) = serde_json::to_string(&ServerJsonRpcMessage::notification(notification)) {
        journal.publish(encoded).await;
    }
}

fn decode_message(body: &[u8]) -> Result<WireMessage, UpstreamError> {
    serde_json::from_slice(body).map_err(|_| UpstreamError::InvalidResponse)
}

fn matching_progress(
    message: &Value,
    id: i64,
    token: &ProgressToken,
) -> Option<ProgressNotificationParam> {
    if message.get("method")?.as_str()? != "notifications/progress" {
        return None;
    }
    let params = ProgressNotificationParam::deserialize(message.get("params")?).ok()?;
    if params.progress_token != ProgressToken(RequestId::Number(id)) {
        return None;
    }
    let mut progress = ProgressNotificationParam::new(token.clone(), params.progress);
    progress.total = params.total;
    progress.message = params.message;
    Some(progress)
}

fn take_result(message: WireMessage, id: i64) -> Result<Option<Value>, UpstreamError> {
    let expected = RequestId::Number(id);
    match message {
        JsonRpcMessage::Response(response) if response.id == expected => Ok(Some(response.result)),
        JsonRpcMessage::Error(response) if response.id.as_ref() == Some(&expected) => {
            Err(rpc_error(response.error))
        }
        _ => Ok(None),
    }
}

fn rpc_error(error: ErrorData) -> UpstreamError {
    UpstreamError::Rpc {
        code: i64::from(error.code.0),
        message: error.message.into_owned(),
        data: error.data,
    }
}

#[derive(Default)]
struct SseDecoder {
    line: Vec<u8>,
    event: Vec<u8>,
    after_cr: bool,
    read_first_line: bool,
    pending_id: Option<HeaderValue>,
    last_event_id: Option<HeaderValue>,
    pending_event_type: Option<String>,
    event_type: Option<String>,
}

impl SseDecoder {
    fn next_frame(&mut self, chunk: &mut &[u8]) -> Option<Vec<u8>> {
        while let Some((&byte, rest)) = chunk.split_first() {
            *chunk = rest;
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
            if line.is_empty() {
                if let Some(id) = self.pending_id.take() {
                    self.last_event_id = (!id.is_empty()).then_some(id);
                }
                self.event_type = self.pending_event_type.take();
                if !self.event.is_empty() {
                    self.line.clear();
                    return Some(std::mem::take(&mut self.event));
                }
            } else if let Some(data) = line.strip_prefix(b"data:") {
                if !self.event.is_empty() {
                    self.event.push(b'\n');
                }
                self.event
                    .extend_from_slice(data.strip_prefix(b" ").unwrap_or(data));
            } else if let Some(id) = line.strip_prefix(b"id:") {
                self.pending_id = HeaderValue::from_bytes(id.strip_prefix(b" ").unwrap_or(id)).ok();
            } else if let Some(kind) = line.strip_prefix(b"event:") {
                self.pending_event_type =
                    std::str::from_utf8(kind.strip_prefix(b" ").unwrap_or(kind))
                        .ok()
                        .map(str::to_owned);
            }
            self.line.clear();
        }
        None
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
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
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

    fn check_modern_request(headers: &HeaderMap, request: &Value) {
        assert_eq!(headers[METHOD_HEADER], request["method"].as_str().unwrap());
        assert_eq!(headers[PROTOCOL_HEADER], MODERN_VERSION.as_str());
        assert!(headers.get(SESSION_HEADER).is_none());
        let meta = &request["params"]["_meta"];
        assert_eq!(
            meta["io.modelcontextprotocol/protocolVersion"],
            MODERN_VERSION.as_str()
        );
        assert_eq!(
            meta["io.modelcontextprotocol/clientCapabilities"],
            json!({})
        );
        assert_eq!(
            meta["io.modelcontextprotocol/clientInfo"]["name"],
            "context-forge-rs"
        );
    }

    fn discovery_result(version: &str) -> Value {
        json!({"supportedVersions":["2025-11-25",version],
            "capabilities":{"tools":{},"custom":{"visible":true}}, "ttlMs":-100})
    }

    fn result(id: &Value, result: Value) -> AxumResponse {
        Json(json!({"jsonrpc":"2.0", "id":id, "result":result})).into_response()
    }

    fn version_error(supported: &str) -> AxumResponse {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"jsonrpc":"2.0", "id":null,
            "error":{"code":-32022,"message":"unsupported","data":{
                "supported":[supported], "requested":MODERN_VERSION.as_str()
            }}})),
        )
            .into_response()
    }

    #[tokio::test]
    async fn discovers_modern_catalog_and_stamps_each_tool_call() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let requests = events.clone();
        let deletions = events.clone();
        let app = Router::new().route(
            "/mcp",
            post(
                async move |headers: HeaderMap, Json(request): Json<Value>| {
                    check_modern_request(&headers, &request);
                    let method = request["method"].as_str().unwrap();
                    requests.lock().unwrap().push(method.to_owned());
                    let id = &request["id"];
                    match method {
                        "server/discover" => {
                            assert!(!headers.contains_key(NAME_HEADER));
                            (
                                [(SESSION_HEADER, "unused-session")],
                                result(id, discovery_result(MODERN_VERSION.as_str())),
                            )
                                .into_response()
                        }
                        "tools/list" => {
                            assert!(!headers.contains_key(NAME_HEADER));
                            let page = if request["params"]["cursor"] == "tail" {
                                json!({"tools":[{"name":"second"}]})
                            } else {
                                json!({"tools":[{"name":"first"}],"nextCursor":"tail"})
                            };
                            result(id, page)
                        }
                        "tools/call" => {
                            let name = request["params"]["name"].as_str().unwrap();
                            if name == "café" {
                                assert_eq!(headers[NAME_HEADER], "=?base64?Y2Fmw6k=?=");
                            } else {
                                assert_eq!(headers[NAME_HEADER], name);
                            }
                            if name == "mismatch" {
                                return (
                                    StatusCode::BAD_REQUEST,
                                    Json(json!({"jsonrpc":"2.0", "id":null,
                           "error":{"code":-32020,"message":"header mismatch"}})),
                                )
                                    .into_response();
                            }
                            result(id, json!({"content":[],"raw":true}))
                        }
                        other => panic!("unexpected modern request {other}"),
                    }
                },
            )
            .delete(async move || {
                deletions.lock().unwrap().push("delete".to_owned());
                StatusCode::NO_CONTENT
            }),
        );
        let (url, server) = serve(app, "127.0.0.1").await;
        let client = local_client();
        let catalog = client.list_tools(&url).await.unwrap();
        assert_eq!(
            catalog.capabilities,
            json!({"tools":{},"custom":{"visible":true}})
        );
        assert_eq!(catalog.tools.len(), 2);
        assert_eq!(
            client.call_tool(&url, "café", json!({})).await.unwrap(),
            json!({"content":[],"raw":true})
        );
        assert!(matches!(
            client.call_tool(&url, "mismatch", json!({})).await,
            Err(UpstreamError::Rpc { code: -32020, .. })
        ));
        assert_eq!(
            *events.lock().unwrap(),
            [
                "server/discover",
                "tools/list",
                "tools/list",
                "server/discover",
                "tools/call",
                "server/discover",
                "tools/call"
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn connects_to_legacy_peers_after_discovery_rejection() {
        for probe in ["http", "rpc", "version", "legacy-only", "invalid-result"] {
            let paths = Arc::new(Mutex::new(Vec::new()));
            let requests = paths.clone();
            let app = Router::new().route(
                "/mcp",
                post(async move |headers, Json(request): Json<Value>| {
                    let method = request["method"].as_str().unwrap();
                    requests.lock().unwrap().push(method.to_owned());
                    if method != "server/discover" {
                        return fixture(headers, Json(request)).await;
                    }
                    check_modern_request(&headers, &request);
                    let id = &request["id"];
                    match probe {
                        "http" => StatusCode::NOT_FOUND.into_response(),
                        "rpc" => (
                            StatusCode::NOT_FOUND,
                            Json(json!({"jsonrpc":"2.0", "id":null,
                        "error":{"code":-32601,"message":"method not found"}})),
                        )
                            .into_response(),
                        "version" => version_error("2025-11-25"),
                        "legacy-only" => result(id, discovery_result("2025-06-18")),
                        _ => result(id, json!({})),
                    }
                })
                .delete(end_fixture_session),
            );
            let (url, server) = serve(app, "127.0.0.1").await;
            assert_eq!(
                local_client().list_tools(&url).await.unwrap().tools.len(),
                2
            );
            assert_eq!(
                *paths.lock().unwrap(),
                [
                    "server/discover",
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                    "tools/list"
                ],
                "{probe}"
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn probes_again_only_for_a_mutual_modern_version() {
        for mode in ["direct", "corrective", "disjoint"] {
            let paths = Arc::new(Mutex::new(Vec::new()));
            let requests = paths.clone();
            let app = Router::new().route(
                "/mcp",
                post(
                    async move |headers: HeaderMap, Json(request): Json<Value>| {
                        let method = request["method"].as_str().unwrap();
                        let count = {
                            let mut requests = requests.lock().unwrap();
                            requests.push(method.to_owned());
                            requests.len()
                        };
                        let id = &request["id"];
                        if method == "server/discover" && count > 1 {
                            check_modern_request(&headers, &request);
                            return result(id, discovery_result(MODERN_VERSION.as_str()));
                        }
                        if method == "tools/list" {
                            check_modern_request(&headers, &request);
                            return result(id, json!({"tools":[]}));
                        }
                        if mode == "corrective" && method == "server/discover" {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        version_error(if mode == "disjoint" {
                            "2027-01-01"
                        } else {
                            MODERN_VERSION.as_str()
                        })
                    },
                ),
            );
            let (url, server) = serve(app, "127.0.0.1").await;
            let discovered = local_client().list_tools(&url).await;
            let expected = match mode {
                "direct" => &["server/discover", "server/discover", "tools/list"][..],
                "corrective" => &[
                    "server/discover",
                    "initialize",
                    "server/discover",
                    "tools/list",
                ],
                _ => &["server/discover"],
            };
            if mode == "disjoint" {
                assert!(matches!(
                    discovered,
                    Err(UpstreamError::Rpc { code: -32022, .. })
                ));
            } else {
                assert!(discovered.is_ok(), "{mode}: {:?}", discovered.err());
            }
            assert_eq!(paths.lock().unwrap().as_slice(), expected, "{mode}");
            server.abort();
        }
    }

    #[tokio::test]
    async fn legacy_catalog_and_invocation_follow_pinned_session() {
        let terminated = Arc::new(AtomicUsize::new(0));
        let terminated_sessions = terminated.clone();
        let probes = Arc::new(AtomicUsize::new(0));
        let probe_count = probes.clone();
        let (url, server) = serve(
            Router::new().route(
                "/mcp",
                post(async move |headers, Json(request): Json<Value>| {
                    if request["method"] == "server/discover" {
                        probe_count.fetch_add(1, Ordering::Relaxed);
                    }
                    fixture(headers, Json(request)).await
                })
                .delete(async move |headers| {
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

        let client = local_client().with_connect_mode(ConnectMode::Legacy);
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
        assert_eq!(probes.load(Ordering::Relaxed), 0);
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
        for mut chunk in [
            b"\xef\xbb".as_slice(),
            b"\xbfdata: {\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{}}\r",
            b"\n\r\ndata: {\"jsonrpc\":\"2.0\",\r\n",
            b"data: \"id\":2,\"result\":",
            b"{\"ok\":true}}\r\n",
        ] {
            while let Some(frame) = stream.next_frame(&mut chunk) {
                assert!(
                    take_result(decode_message(&frame).unwrap(), 2)
                        .unwrap()
                        .is_none()
                );
            }
        }
        let frame = stream.next_frame(&mut b"\r\n".as_slice()).unwrap();
        assert_eq!(
            take_result(decode_message(&frame).unwrap(), 2).unwrap(),
            Some(json!({"ok": true}))
        );
    }
}
