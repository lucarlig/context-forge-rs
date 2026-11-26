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
use tokio::{sync::mpsc, time::sleep};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    access::{self, Principal},
    catalog::CatalogServer,
    gateway::GatewayService,
    mcp::{MAX_REQUEST_BODY_BYTES, legacy_transport_reply},
};

const MAX_CONNECTIONS: usize = 4096;
const QUEUE_LENGTH: usize = 128;

pub struct SseSettings {
    pub retry_ms: u64,
    pub keepalive: Option<Duration>,
    pub shutdown: CancellationToken,
}

impl Default for SseSettings {
    fn default() -> Self {
        Self {
            retry_ms: 5000,
            keepalive: Some(Duration::from_secs(30)),
            shutdown: CancellationToken::new(),
        }
    }
}

struct SseState {
    gateway: Arc<GatewayService>,
    connections: Mutex<HashMap<Uuid, Connection>>,
    settings: SseSettings,
}

struct Connection {
    owner: Option<String>,
    server: Option<String>,
    incoming: mpsc::Sender<Value>,
}

pub(crate) fn router(
    gateway: Arc<GatewayService>,
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
    let (incoming, inbox) = mpsc::channel(QUEUE_LENGTH);
    let (outbox, outgoing) = mpsc::channel(QUEUE_LENGTH);
    {
        let mut connections = state.connections.lock().expect("SSE connections");
        if connections.len() >= MAX_CONNECTIONS {
            return detail(StatusCode::SERVICE_UNAVAILABLE, "SSE connection failed");
        }
        connections.insert(
            id,
            Connection {
                owner: principal.as_ref().map(|user| user.email.clone()),
                server: server.as_ref().map(|server| server.id.clone()),
                incoming,
            },
        );
    }
    let cancel = state.settings.shutdown.child_token();
    tokio::spawn(respond(
        state.gateway.clone(),
        principal,
        server,
        cancel.clone(),
        inbox,
        outbox,
    ));
    let stream = stream::unfold(
        Output {
            connection: StreamConnection { state, id, cancel },
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
    let Ok(bytes) = to_bytes(request.into_body(), MAX_REQUEST_BODY_BYTES).await else {
        return detail(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large");
    };
    let Ok(message) = serde_json::from_slice(&bytes) else {
        return detail(StatusCode::BAD_REQUEST, "Invalid JSON in request body");
    };
    match incoming.try_send(message) {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({"status":"success"}))).into_response(),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            detail(StatusCode::NOT_FOUND, "Session not found")
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            detail(StatusCode::TOO_MANY_REQUESTS, "SSE message queue is full")
        }
    }
}

struct StreamConnection {
    state: Arc<SseState>,
    id: Uuid,
    cancel: CancellationToken,
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
    mut incoming: mpsc::Receiver<Value>,
    outgoing: mpsc::Sender<Value>,
) {
    let run = async {
        while let Some(request) = incoming.recv().await {
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
}

fn detail(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"detail":message}))).into_response()
}
