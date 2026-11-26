// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Query, Request, State},
    http::{HeaderValue, StatusCode, header, uri::Authority},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::stream;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    access::{self, Principal},
    catalog::CatalogServer,
    database::Database,
    gateway::GatewayService,
    legacy_sse_cache::{Access, CacheResult, RedisQueue, Scope, SharedQueue},
    legacy_sse_database::DatabaseQueue,
    mcp::{MAX_REQUEST_BODY_BYTES, legacy_transport_reply},
    redis_sessions::RedisSessionDirectory,
};

const MAX_CONNECTIONS: usize = 4096;
const QUEUE_LENGTH: usize = 128;

pub struct SseSettings {
    pub retry_ms: u64,
    pub keepalive: Option<Duration>,
    pub shutdown: CancellationToken,
    pub backend: SseBackend,
    pub session_ttl: Duration,
    pub message_ttl: Duration,
}

pub enum SseBackend {
    Memory,
    Redis(Arc<RedisSessionDirectory>),
    Database,
    Disabled,
}

impl Default for SseSettings {
    fn default() -> Self {
        Self {
            retry_ms: 5000,
            keepalive: Some(Duration::from_secs(30)),
            shutdown: CancellationToken::new(),
            backend: SseBackend::Memory,
            session_ttl: Duration::from_secs(3600),
            message_ttl: Duration::from_secs(600),
        }
    }
}

struct SseState {
    gateway: Arc<GatewayService>,
    database: Database,
    capacity: Arc<Semaphore>,
    connections: Mutex<HashMap<Uuid, Connection>>,
    settings: SseSettings,
}

struct Connection {
    owner: Option<String>,
    server: Option<String>,
    incoming: mpsc::Sender<Value>,
}

enum Inbox {
    Local(mpsc::Receiver<Value>),
    Shared(SharedQueue),
    Disabled,
}

impl SseState {
    fn shared_queue(&self, id: Uuid) -> Option<SharedQueue> {
        match &self.settings.backend {
            SseBackend::Memory | SseBackend::Disabled => None,
            SseBackend::Redis(redis) => {
                Some(SharedQueue::Redis(RedisQueue::new(redis.clone(), id)))
            }
            SseBackend::Database => Some(SharedQueue::Database(DatabaseQueue::new(
                self.database.clone(),
                id,
            ))),
        }
    }
}

pub(crate) fn router(
    gateway: Arc<GatewayService>,
    database: Database,
    require_auth: bool,
    settings: SseSettings,
) -> Router {
    let routes = Router::new()
        .route("/sse", get(open))
        .route("/message", post(enqueue))
        .route("/servers/{server_id}/sse", get(open))
        .route("/servers/{server_id}/message", post(enqueue))
        .route("/v1/virtual-servers/{server_id}/sse", get(open))
        .route("/v1/virtual-servers/{server_id}/message", post(enqueue))
        .with_state(Arc::new(SseState {
            gateway: gateway.clone(),
            database,
            capacity: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            connections: Mutex::default(),
            settings,
        }));
    gateway
        .access
        .protect_legacy_transport(routes, require_auth)
        .layer(middleware::map_response(async |mut response: Response| {
            response
                .headers_mut()
                .entry(header::VARY)
                .or_insert(HeaderValue::from_static("Origin"));
            response
        }))
}

async fn open(State(state): State<Arc<SseState>>, request: Request) -> Response {
    let principal = request.extensions().get::<Principal>().cloned();
    let server = request.extensions().get::<CatalogServer>().cloned();
    let authority = request.uri().authority().cloned().or_else(|| {
        request
            .headers()
            .get(header::HOST)?
            .to_str()
            .ok()?
            .parse::<Authority>()
            .ok()
    });
    let Some(authority) = authority else {
        return detail(StatusCode::BAD_REQUEST, "Missing or invalid Host");
    };
    let scheme = request.uri().scheme_str().unwrap_or("http");
    let path = match server.as_ref() {
        Some(server) => format!("/servers/{}/message", server.id),
        None => "/message".to_owned(),
    };
    let id = Uuid::new_v4();
    let endpoint = format!("{scheme}://{authority}{path}?session_id={id}");
    let Ok(permit) = state.capacity.clone().try_acquire_owned() else {
        return detail(StatusCode::SERVICE_UNAVAILABLE, "SSE connection failed");
    };
    let (outbox, outgoing) = mpsc::channel(QUEUE_LENGTH);
    let cancel = state.settings.shutdown.child_token();
    let connection = StreamConnection {
        state,
        id,
        cancel,
        _permit: permit,
    };
    let inbox = if let Some(queue) = connection.state.shared_queue(id) {
        let scope = session_scope(principal.as_ref(), server.as_ref());
        if let Err(error) = queue
            .register(scope, connection.state.settings.session_ttl)
            .await
        {
            tracing::warn!(%error, "legacy SSE session registration failed");
            return detail(StatusCode::SERVICE_UNAVAILABLE, "SSE connection failed");
        }
        Inbox::Shared(queue)
    } else if matches!(connection.state.settings.backend, SseBackend::Disabled) {
        Inbox::Disabled
    } else {
        let (incoming, inbox) = mpsc::channel(QUEUE_LENGTH);
        connection
            .state
            .connections
            .lock()
            .expect("SSE connections")
            .insert(
                id,
                Connection {
                    owner: principal.as_ref().map(|user| user.email.clone()),
                    server: server.as_ref().map(|server| server.id.clone()),
                    incoming,
                },
            );
        Inbox::Local(inbox)
    };
    tokio::spawn(respond(
        connection.state.gateway.clone(),
        principal,
        server,
        connection.cancel.clone(),
        inbox,
        outbox,
    ));
    let stream = stream::unfold(
        Output {
            connection,
            endpoint: Some(endpoint),
            initial_keepalive: true,
            outgoing,
        },
        |mut output| async move {
            let frame = output.next().await?;
            Some((Ok::<_, Infallible>(frame), output))
        },
    );
    (
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::CONNECTION, "keep-alive"),
            (header::VARY, "Origin, Accept-Encoding"),
            ("x-accel-buffering".parse().expect("valid header"), "no"),
            ("x-mcp-sse".parse().expect("valid header"), "true"),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

#[derive(Deserialize)]
struct MessageQuery {
    session_id: Option<String>,
}

async fn enqueue(
    State(state): State<Arc<SseState>>,
    Query(query): Query<MessageQuery>,
    request: Request,
) -> Response {
    let principal = request.extensions().get::<Principal>();
    let server = request.extensions().get::<CatalogServer>();
    if server.is_none()
        && let Some(principal) = principal
    {
        match state
            .gateway
            .access
            .allows(principal, "tools.execute", access::role_context(None), true)
            .await
        {
            Ok(true) => {}
            Ok(false) => return detail(StatusCode::FORBIDDEN, "Access denied"),
            Err(error) => {
                tracing::error!(%error, "legacy SSE permission lookup failed");
                return detail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authorization service unavailable",
                );
            }
        }
    }
    let Some(id) = query.session_id.filter(|id| !id.is_empty()) else {
        return detail(StatusCode::BAD_REQUEST, "Missing session_id");
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return detail(StatusCode::NOT_FOUND, "Session not found");
    };
    if let Some(queue) = state.shared_queue(id) {
        let principal = principal.cloned();
        let server = server.cloned();
        let shared_scope = || session_scope(principal.as_ref(), server.as_ref());
        let ttl = state.settings.message_ttl;
        if let Err(response) = check_cache_access(queue.access(shared_scope(), None, ttl).await) {
            return *response;
        }
        let message = match parse_message(request).await {
            Ok(message) => message,
            Err(response) => return *response,
        };
        return match check_cache_access(queue.access(shared_scope(), Some(&message), ttl).await) {
            Ok(()) => accepted(),
            Err(response) => *response,
        };
    }
    let incoming = {
        let connections = state.connections.lock().expect("SSE connections");
        let Some(connection) = connections.get(&id).filter(|connection| {
            connection.server.as_deref() == server.map(|server| server.id.as_str())
        }) else {
            return detail(StatusCode::NOT_FOUND, "Session not found");
        };
        if connection.owner.as_deref() != principal.map(|user| user.email.as_str())
            && !principal.is_some_and(Principal::is_global_admin)
        {
            return detail(StatusCode::FORBIDDEN, "Session access denied");
        }
        connection.incoming.clone()
    };
    let message = match parse_message(request).await {
        Ok(message) => message,
        Err(response) => return *response,
    };
    match incoming.try_send(message) {
        Ok(()) => accepted(),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            detail(StatusCode::NOT_FOUND, "Session not found")
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            detail(StatusCode::TOO_MANY_REQUESTS, "SSE message queue is full")
        }
    }
}

async fn parse_message(request: Request) -> Result<Value, Box<Response>> {
    let bytes = to_bytes(request.into_body(), MAX_REQUEST_BODY_BYTES)
        .await
        .map_err(|_| {
            Box::new(detail(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Request body too large",
            ))
        })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        Box::new(detail(
            StatusCode::BAD_REQUEST,
            "Invalid JSON in request body",
        ))
    })
}

fn session_scope<'a>(
    principal: Option<&'a Principal>,
    server: Option<&'a CatalogServer>,
) -> Scope<'a> {
    Scope {
        owner: principal.map(|user| user.email.as_str()),
        server: server.map(|server| server.id.as_str()),
        admin: principal.is_some_and(Principal::is_global_admin),
    }
}

fn check_cache_access(result: CacheResult<Access>) -> Result<(), Box<Response>> {
    let response = match result {
        Ok(Access::Allowed) => return Ok(()),
        Ok(Access::Missing) => detail(StatusCode::NOT_FOUND, "Session not found"),
        Ok(Access::Denied) => detail(StatusCode::FORBIDDEN, "Session access denied"),
        Ok(Access::Full) => detail(StatusCode::TOO_MANY_REQUESTS, "SSE message queue is full"),
        Err(error) => {
            tracing::warn!(%error, "legacy SSE session lookup failed");
            detail(
                StatusCode::SERVICE_UNAVAILABLE,
                "SSE session cache unavailable",
            )
        }
    };
    Err(Box::new(response))
}

fn accepted() -> Response {
    (StatusCode::ACCEPTED, Json(json!({"status":"success"}))).into_response()
}

struct StreamConnection {
    state: Arc<SseState>,
    id: Uuid,
    cancel: CancellationToken,
    _permit: OwnedSemaphorePermit,
}

impl Drop for StreamConnection {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.state
            .connections
            .lock()
            .expect("SSE connections")
            .remove(&self.id);
    }
}

struct Output {
    connection: StreamConnection,
    endpoint: Option<String>,
    initial_keepalive: bool,
    outgoing: mpsc::Receiver<Value>,
}

impl Output {
    async fn next(&mut self) -> Option<String> {
        let settings = &self.connection.state.settings;
        let (event, data) = if let Some(endpoint) = self.endpoint.take() {
            ("endpoint", endpoint)
        } else if std::mem::take(&mut self.initial_keepalive) && settings.keepalive.is_some() {
            ("keepalive", "{}".to_owned())
        } else {
            let idle = async {
                match settings.keepalive {
                    Some(interval) => sleep(interval).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                biased;
                () = self.connection.cancel.cancelled() => return None,
                message = self.outgoing.recv() => ("message", message?.to_string()),
                () = idle => ("keepalive", "{}".to_owned()),
            }
        };
        Some(format!(
            "event: {event}\r\ndata: {data}\r\nretry: {}\r\n\r\n",
            settings.retry_ms
        ))
    }
}

async fn respond(
    gateway: Arc<GatewayService>,
    principal: Option<Principal>,
    server: Option<CatalogServer>,
    cancel: CancellationToken,
    mut incoming: Inbox,
    outgoing: mpsc::Sender<Value>,
) {
    let run = async {
        while let Some(request) = incoming.receive().await {
            let initialized = request["method"] == "initialize";
            let Some(reply) =
                legacy_transport_reply(&gateway, principal.as_ref(), server.as_ref(), request)
                    .await
            else {
                continue;
            };
            let reply = if reply.get("result").is_none() {
                json!({"jsonrpc":"2.0","id":reply["id"],"result":{}})
            } else {
                reply
            };
            if outgoing.send(reply).await.is_err() {
                return;
            }
            if initialized {
                for method in [
                    "notifications/initialized",
                    "notifications/tools/list_changed",
                    "notifications/resources/list_changed",
                    "notifications/prompts/list_changed",
                ] {
                    if outgoing
                        .send(json!({"jsonrpc":"2.0","method":method,"params":{}}))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    };
    tokio::select! {
        biased;
        () = cancel.cancelled() => {},
        () = run => {},
    }
    cancel.cancel();
    if let Inbox::Shared(queue) = incoming {
        queue.remove().await;
    }
}

impl Inbox {
    async fn receive(&mut self) -> Option<Value> {
        match self {
            Self::Local(inbox) => inbox.recv().await,
            Self::Disabled => std::future::pending().await,
            Self::Shared(queue) => match queue.receive().await {
                Ok(message) => message,
                Err(error) => {
                    tracing::warn!(%error, "legacy SSE session receive failed");
                    None
                }
            },
        }
    }
}

fn detail(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"detail":message}))).into_response()
}
