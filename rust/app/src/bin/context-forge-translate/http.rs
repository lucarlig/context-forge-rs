// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    convert::Infallible,
    error::Error,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Query, Request, State},
    http::{HeaderValue, StatusCode, header, uri::Authority},
    response::{IntoResponse, Response, Sse, sse::Event},
    routing::{get, post},
};
use context_forge_rs::mcp::SseSettings;
use futures_util::stream::{self, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    sync::{broadcast, mpsc, watch},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use uuid::Uuid;

use super::{
    environment::{DynamicEnvironment, EnvironmentRequest},
    stdio::{MAX_MESSAGE_BYTES, StdioBridge},
};

const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 1024;

pub(super) struct Expose {
    pub(super) sse: bool,
    pub(super) streamable_http: bool,
    pub(super) sse_path: String,
    pub(super) message_path: String,
    pub(super) cors: Vec<String>,
    pub(super) settings: SseSettings,
    pub(super) environment: Option<Arc<DynamicEnvironment>>,
}

impl Expose {
    pub(super) fn router(
        self,
        bridge: Arc<StdioBridge>,
    ) -> Result<Router, Box<dyn Error + Send + Sync>> {
        let mut app = Router::new().route("/healthz", get(|| async { "ok" }));
        if self.streamable_http {
            app = app.route("/mcp", post(streamable_post));
        }
        if self.sse {
            for path in [&self.sse_path, &self.message_path] {
                if !path.starts_with('/') || path.contains(['{', '}', '?', '#']) {
                    return Err("SSE paths must be absolute HTTP paths".into());
                }
            }
            if self.sse_path == "/healthz" || (self.streamable_http && self.message_path == "/mcp")
            {
                return Err("SSE paths must leave the enabled HTTP endpoints accessible".into());
            }
            app = app
                .route(&self.sse_path, get(sse_open))
                .route(&self.message_path, post(sse_post));
        }
        if !self.cors.is_empty() {
            let origins = if self.cors.iter().any(|origin| origin == "*") {
                AllowOrigin::mirror_request()
            } else {
                AllowOrigin::list(
                    self.cors
                        .iter()
                        .map(|origin| origin.parse::<HeaderValue>())
                        .collect::<Result<Vec<_>, _>>()?,
                )
            };
            app = app.layer(
                CorsLayer::new()
                    .allow_origin(origins)
                    .allow_credentials(true)
                    .allow_methods(AllowMethods::mirror_request())
                    .allow_headers(AllowHeaders::mirror_request()),
            );
        }
        Ok(app
            .method_not_allowed_fallback(|| async {
                (
                    StatusCode::METHOD_NOT_ALLOWED,
                    Json(json!({"detail":"Method Not Allowed"})),
                )
            })
            .fallback(|| async { (StatusCode::NOT_FOUND, Json(json!({"detail":"Not Found"}))) })
            .with_state(Arc::new(StateData {
                bridge,
                sessions: Mutex::default(),
                message_path: self.message_path,
                settings: self.settings,
                environment: self.environment,
            })))
    }
}

struct StateData {
    bridge: Arc<StdioBridge>,
    sessions: Mutex<HashMap<Uuid, Connection>>,
    message_path: String,
    settings: SseSettings,
    environment: Option<Arc<DynamicEnvironment>>,
}

#[derive(Clone)]
struct Connection {
    send: mpsc::Sender<Value>,
    close: CancellationToken,
    scoped: Option<mpsc::Sender<EnvironmentRequest>>,
}

#[derive(Deserialize)]
struct MessageQuery {
    session_id: Option<String>,
}

async fn streamable_post(State(state): State<Arc<StateData>>, request: Request) -> Response {
    let message = match read_message(request).await {
        Ok(message) => message,
        Err(error) => return *error,
    };
    match state.bridge.submit(message).await {
        Ok(Some(reply)) => match timeout(REPLY_TIMEOUT, reply.receive()).await {
            Ok(Some(reply)) => Json(reply).into_response(),
            _ => (StatusCode::ACCEPTED, "accepted (no response yet)").into_response(),
        },
        Ok(None) => (StatusCode::ACCEPTED, "accepted").into_response(),
        Err(error) => bridge_error(error),
    }
}

async fn sse_open(State(state): State<Arc<StateData>>, request: Request) -> Response {
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
        return (StatusCode::BAD_REQUEST, "Missing or invalid Host").into_response();
    };
    let scheme = request.uri().scheme_str().unwrap_or("http");
    let id = Uuid::new_v4();
    let (send, receive) = mpsc::channel(64);
    let close = state.settings.shutdown.child_token();
    let active = {
        let mut sessions = state.sessions.lock().expect("stdio SSE sessions");
        if sessions.len() >= MAX_CONNECTIONS {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let (scoped, active) = match &state.environment {
            Some(environment) => match environment.start_session(
                environment.values(request.headers()),
                close.clone(),
                send.clone(),
            ) {
                Ok(connection) => (Some(connection.incoming), Some(connection.active)),
                Err(error) => return bridge_error(error),
            },
            None => (None, None),
        };
        sessions.insert(
            id,
            Connection {
                send,
                close: close.clone(),
                scoped,
            },
        );
        active
    };
    let keepalive = state.settings.keepalive;
    let retry = keepalive.unwrap_or(Duration::from_secs(30));
    let mut initial = vec![Ok::<_, Infallible>(
        Event::default()
            .event("endpoint")
            .data(format!(
                "{scheme}://{authority}{}?session_id={}",
                state.message_path,
                id.simple()
            ))
            .retry(retry),
    )];
    if keepalive.is_some() {
        initial.push(Ok(Event::default()
            .event("keepalive")
            .data("{}")
            .retry(retry)));
    }
    let events = match &active {
        Some(active) => active.borrow().events.subscribe(),
        None => state.bridge.events.subscribe(),
    };
    let stream = stream::unfold(
        StreamState {
            state,
            id,
            close,
            receive,
            events,
            active,
            keepalive,
        },
        |mut stream| async move {
            let event = stream.next().await?;
            Some((Ok::<_, Infallible>(event), stream))
        },
    );
    (
        [
            (header::CACHE_CONTROL, "no-cache"),
            (header::CONNECTION, "keep-alive"),
            ("x-accel-buffering".parse().expect("valid header"), "no"),
        ],
        Sse::new(stream::iter(initial).chain(stream)),
    )
        .into_response()
}

async fn sse_post(
    State(state): State<Arc<StateData>>,
    Query(query): Query<MessageQuery>,
    request: Request,
) -> Response {
    let values = state
        .environment
        .as_ref()
        .map(|environment| environment.values(request.headers()))
        .unwrap_or_default();
    let message = match read_message(request).await {
        Ok(message) => message,
        Err(error) => return *error,
    };
    let connection = if let Some(id) = query.session_id {
        let connection = Uuid::parse_str(&id).ok().and_then(|id| {
            state
                .sessions
                .lock()
                .expect("stdio SSE sessions")
                .get(&id)
                .cloned()
        });
        let Some(connection) = connection else {
            return (StatusCode::NOT_FOUND, "Session not found").into_response();
        };
        Some(connection)
    } else {
        None
    };
    if let Some(scoped) = connection
        .as_ref()
        .and_then(|connection| connection.scoped.as_ref())
    {
        return match scoped.try_send(EnvironmentRequest { message, values }) {
            Ok(()) => (StatusCode::ACCEPTED, "forwarded").into_response(),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                (StatusCode::NOT_FOUND, "Session not found").into_response()
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                StatusCode::TOO_MANY_REQUESTS.into_response()
            }
        };
    }
    if !values.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing session_id").into_response();
    }
    match state.bridge.submit(message).await {
        Ok(reply) => {
            if let (Some(reply), Some(connection)) = (reply, connection) {
                tokio::spawn(async move {
                    tokio::select! {
                        () = connection.close.cancelled() => {},
                        result = timeout(REPLY_TIMEOUT, reply.receive()) => {
                            if let Ok(Some(reply)) = result {
                                let _ = connection.send.send(reply).await;
                            }
                        }
                    }
                });
            }
            (StatusCode::ACCEPTED, "forwarded").into_response()
        }
        Err(error) => bridge_error(error),
    }
}

struct StreamState {
    state: Arc<StateData>,
    id: Uuid,
    close: CancellationToken,
    receive: mpsc::Receiver<Value>,
    events: broadcast::Receiver<Value>,
    active: Option<watch::Receiver<Arc<StdioBridge>>>,
    keepalive: Option<Duration>,
}

impl StreamState {
    async fn next(&mut self) -> Option<Event> {
        loop {
            let idle = async {
                match self.keepalive {
                    Some(interval) => sleep(interval).await,
                    None => std::future::pending().await,
                }
            };
            let scoped = self.active.is_some();
            let message = tokio::select! {
                biased;
                () = self.close.cancelled() => return None,
                changed = async { self.active.as_mut().expect("scoped bridge").changed().await }, if scoped => {
                    changed.ok()?;
                    self.events = self.active.as_mut().expect("scoped bridge").borrow_and_update().events.subscribe();
                    continue;
                },
                reply = self.receive.recv() => reply?,
                event = self.events.recv() => match event {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                },
                () = idle => return Some(Event::default().event("keepalive").data("{}").retry(self.keepalive?)),
            };
            return Some(Event::default().event("message").data(message.to_string()));
        }
    }
}

impl Drop for StreamState {
    fn drop(&mut self) {
        self.close.cancel();
        self.state
            .sessions
            .lock()
            .expect("stdio SSE sessions")
            .remove(&self.id);
    }
}

async fn read_message(request: Request) -> Result<Value, Box<Response>> {
    let body = to_bytes(request.into_body(), MAX_MESSAGE_BYTES)
        .await
        .map_err(|_| {
            Box::new((StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response())
        })?;
    serde_json::from_slice(&body).map_err(|error| {
        let error = if error.is_eof() && !body.is_empty() {
            format!(
                "unexpected end of data: line {} column {} (char {})",
                error.line(),
                error.column() + 1,
                body.len()
            )
        } else {
            error.to_string()
        };
        Box::new(
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON payload: {error}"),
            )
                .into_response(),
        )
    })
}

fn bridge_error(error: std::io::Error) -> Response {
    tracing::debug!(%error, "stdio bridge request failed");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"detail":"Stdio process unavailable"})),
    )
        .into_response()
}
