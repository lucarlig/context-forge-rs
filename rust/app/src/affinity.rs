// SPDX-License-Identifier: Apache-2.0
//! Redis transport for requests whose MCP session belongs to another worker.

use std::{
    collections::HashMap,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    sync::{Arc, Weak},
    task::Poll,
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{ConnectInfo, Request},
    http::{HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{StreamExt, stream};
use redis::aio::PubSubStream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    sync::{Mutex, OwnedMutexGuard, Semaphore, mpsc},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    forward_headers::{hop_header_name, nominated_hop_header},
    gateway::GATEWAY_ID_HEADER,
    mcp::MAX_REQUEST_BODY_BYTES,
    redis_sessions::RedisSessionDirectory,
};

const HEADERS: u8 = 1;
const DATA: u8 = 2;
const END: u8 = 3;
const MAX_CHUNK: usize = 64 * 1024;
const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ACTIVE_FORWARDS: usize = 8192;
fn forwardable_header(name: &str) -> bool {
    !hop_header_name(name) && !matches!(name, "host" | "content-length" | "expect")
}

const CORE_HEADERS: &[&str] = &[
    "accept",
    "authorization",
    "content-type",
    "last-event-id",
    "mcp-protocol-version",
    "mcp-session-id",
    "x-upstream-authorization",
    GATEWAY_ID_HEADER,
];

#[derive(Clone)]
pub(crate) struct Forwarded;

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Command {
    Request { id: String, request: WireRequest },
    Ack { id: String },
    Cancel { id: String },
}

#[derive(Serialize, Deserialize)]
struct WireRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    peer: Option<SocketAddr>,
    body: String,
}

impl WireRequest {
    fn is_control(&self) -> bool {
        self.method == "DELETE"
            || (self.method == "POST"
                && serde_json::from_str::<serde_json::Value>(&self.body).is_ok_and(|body| {
                    body.get("id").is_none() && body["method"] == "notifications/cancelled"
                }))
    }

    fn ordered_session(&self, control: bool) -> Option<&str> {
        if self.method != "POST" || control {
            return None;
        }
        self.headers
            .iter()
            .find_map(|(name, value)| (name == "mcp-session-id").then_some(value.as_str()))
    }

    fn into_request(self) -> Option<Request> {
        let method = Method::from_bytes(self.method.as_bytes()).ok()?;
        if !matches!(method, Method::GET | Method::POST | Method::DELETE)
            || !self.path.starts_with('/')
        {
            return None;
        }
        let mut request = Request::builder()
            .method(method)
            .uri(self.path)
            .body(Body::from(self.body))
            .ok()?;
        for (name, value) in self.headers {
            let name = HeaderName::try_from(name).ok()?;
            if !forwardable_header(name.as_str()) {
                return None;
            }
            request
                .headers_mut()
                .append(name, HeaderValue::from_str(&value).ok()?);
        }
        if let Some(peer) = self.peer {
            request.extensions_mut().insert(ConnectInfo(peer));
        }
        request.extensions_mut().insert(Forwarded);
        Some(request)
    }
}

#[derive(Serialize, Deserialize)]
struct WireHeaders {
    status: u16,
    headers: Vec<(String, String)>,
}

struct ForwardBody {
    directory: Arc<RedisSessionDirectory>,
    worker: String,
    id: String,
    finished: bool,
}

impl ForwardBody {
    async fn ack(&self) -> io::Result<()> {
        send(
            &self.directory,
            &self.worker,
            Command::Ack {
                id: self.id.clone(),
            },
        )
        .await
    }
}

impl Drop for ForwardBody {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let directory = self.directory.clone();
        let worker = self.worker.clone();
        let id = self.id.clone();
        runtime.spawn(async move {
            let _ = send(&directory, &worker, Command::Cancel { id }).await;
        });
    }
}

pub(crate) async fn forward(
    directory: Arc<RedisSessionDirectory>,
    worker: Uuid,
    request: Request,
    wait: Duration,
    client_headers: bool,
) -> Response {
    match exchange(directory, worker, request, wait, client_headers).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "MCP affinity forwarding failed");
            relay_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Session worker unavailable",
            )
        }
    }
}

async fn exchange(
    directory: Arc<RedisSessionDirectory>,
    worker: Uuid,
    request: Request,
    wait: Duration,
    client_headers: bool,
) -> io::Result<Response> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_REQUEST_BODY_BYTES)
        .await
        .map_err(io::Error::other)?;
    let body = std::str::from_utf8(&bytes)
        .map_err(io::Error::other)?
        .to_owned();
    let wire = WireRequest {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        headers: parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                let header = name.as_str();
                if (!client_headers && !CORE_HEADERS.contains(&header))
                    || !forwardable_header(header)
                    || nominated_hop_header(&parts.headers, header)
                {
                    return None;
                }
                Some((header.to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect(),
        peer: parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|peer| peer.0),
        body,
    };
    let id = Uuid::new_v4().simple().to_string();
    let mut subscription = directory
        .subscribe(&reply_channel(&id))
        .await
        .map_err(io::Error::other)?;
    let mut guard = ForwardBody {
        directory,
        worker: worker.simple().to_string(),
        id,
        finished: false,
    };
    let submitted = serde_json::to_vec(&Command::Request {
        id: guard.id.clone(),
        request: wire,
    })
    .map_err(io::Error::other)?;
    if guard
        .directory
        .publish(&request_channel(&guard.worker), &submitted)
        .await
        .map_err(io::Error::other)?
        == 0
    {
        guard.finished = true;
        return Ok(relay_error(
            StatusCode::NOT_FOUND,
            "Session worker no longer owns a live session",
        ));
    }
    let headers = next_packet(&mut subscription, wait).await?;
    let Some((&HEADERS, payload)) = headers.split_first() else {
        return Err(io::Error::other("invalid forwarded response headers"));
    };
    let headers: WireHeaders = serde_json::from_slice(payload).map_err(io::Error::other)?;
    guard.ack().await?;

    // A worker sends one chunk at a time. Grant credit only when HTTP polls
    // again, so a slow client cannot fill a Redis subscription's queue.
    let stream = stream::unfold(Some((subscription, guard, false)), |state| async move {
        let (mut subscription, mut guard, ack) = state?;
        if ack && let Err(error) = guard.ack().await {
            return Some((Err(error), None));
        }
        match next_packet(&mut subscription, BODY_IDLE_TIMEOUT).await {
            Ok(packet) if packet.first() == Some(&END) => {
                guard.finished = true;
                None
            }
            Ok(packet) if packet.first() == Some(&DATA) => {
                Some((Ok(packet.slice(1..)), Some((subscription, guard, true))))
            }
            Ok(_) => Some((
                Err(io::Error::other("invalid forwarded response frame")),
                None,
            )),
            Err(error) => Some((Err(error), None)),
        }
    });
    let mut response = Response::builder().status(headers.status);
    for (name, value) in headers.headers {
        response = response.header(name, value);
    }
    response
        .body(Body::from_stream(stream))
        .map_err(io::Error::other)
}

async fn next_packet(stream: &mut PubSubStream, wait: Duration) -> io::Result<Bytes> {
    let message = timeout(wait, stream.next())
        .await?
        .ok_or_else(|| io::Error::other("Redis reply subscription ended"))?;
    Ok(Bytes::copy_from_slice(message.get_payload_bytes()))
}

async fn send(directory: &RedisSessionDirectory, worker: &str, command: Command) -> io::Result<()> {
    let bytes = serde_json::to_vec(&command).map_err(io::Error::other)?;
    publish(directory, &request_channel(worker), &bytes).await
}

async fn publish(directory: &RedisSessionDirectory, channel: &str, bytes: &[u8]) -> io::Result<()> {
    let receivers = directory
        .publish(channel, bytes)
        .await
        .map_err(io::Error::other)?;
    if receivers == 0 {
        return Err(io::Error::other("MCP affinity subscriber is absent"));
    }
    Ok(())
}

struct Active {
    ack: mpsc::Sender<()>,
    cancel: CancellationToken,
}

#[derive(Default)]
struct Forwards {
    requests: HashMap<String, Active>,
    sessions: HashMap<String, Weak<Mutex<()>>>,
}

#[derive(Clone)]
struct Worker {
    directory: Arc<RedisSessionDirectory>,
    router: Router,
    wait: Duration,
    lock_timeout: Duration,
    permits: Arc<Semaphore>,
    control_permits: Arc<Semaphore>,
    active: Arc<std::sync::Mutex<Forwards>>,
    shutdown: CancellationToken,
}

pub(crate) fn spawn(
    directory: Arc<RedisSessionDirectory>,
    router: Router,
    wait: Duration,
    concurrency: usize,
    lock_timeout: Duration,
    shutdown: CancellationToken,
) {
    tokio::spawn(
        Worker {
            directory,
            router,
            wait,
            lock_timeout,
            permits: Arc::new(Semaphore::new(concurrency)),
            control_permits: Arc::new(Semaphore::new(concurrency.min(32))),
            active: Arc::default(),
            shutdown,
        }
        .run(),
    );
}

impl Worker {
    async fn run(self) {
        let inbox = request_channel(self.directory.worker_id());
        loop {
            let subscription = tokio::select! {
                () = self.shutdown.cancelled() => return,
                subscription = self.directory.subscribe(&inbox) => subscription,
            };
            match subscription {
                Ok(mut messages) => loop {
                    let message = tokio::select! {
                        () = self.shutdown.cancelled() => return,
                        message = messages.next() => message,
                    };
                    let Some(message) = message else {
                        break;
                    };
                    if let Ok(command) = serde_json::from_slice(message.get_payload_bytes()) {
                        self.handle(command).await;
                    }
                },
                Err(error) => tracing::warn!(%error, "MCP affinity subscription unavailable"),
            }
            tokio::select! {
                () = self.shutdown.cancelled() => return,
                () = sleep(Duration::from_millis(250)) => {},
            }
        }
    }

    async fn handle(&self, command: Command) {
        match command {
            Command::Ack { id } => {
                if let Some(active) = self
                    .active
                    .lock()
                    .expect("affinity worker lock")
                    .requests
                    .get(&id)
                {
                    let _ = active.ack.try_send(());
                }
            }
            Command::Cancel { id } => {
                if let Some(active) = self
                    .active
                    .lock()
                    .expect("affinity worker lock")
                    .requests
                    .get(&id)
                {
                    active.cancel.cancel();
                }
            }
            Command::Request { id, request } => self.start(id, request).await,
        }
    }

    async fn start(&self, id: String, request: WireRequest) {
        if Uuid::parse_str(&id).is_err() {
            return;
        }
        let channel = reply_channel(&id);
        let saturated = self
            .active
            .lock()
            .expect("affinity worker lock")
            .requests
            .len()
            >= MAX_ACTIVE_FORWARDS;
        if saturated {
            let _ = send_busy(&self.directory, &channel).await;
            return;
        }
        let control = request.is_control();
        let cancellation = self.shutdown.child_token();
        let (ack, credit) = mpsc::channel(1);
        let ordering = {
            let mut active = self.active.lock().expect("affinity worker lock");
            if active.requests.contains_key(&id) {
                return;
            }
            active.requests.insert(
                id.clone(),
                Active {
                    ack,
                    cancel: cancellation.clone(),
                },
            );
            request.ordered_session(control).map(|session| {
                let entry = active.sessions.entry(session.to_owned()).or_default();
                let lock = entry.upgrade().unwrap_or_else(|| {
                    let lock = Arc::new(Mutex::new(()));
                    *entry = Arc::downgrade(&lock);
                    lock
                });
                (session.to_owned(), lock)
            })
        };
        // Join the mutex queue in Redis receive order, before scheduling dispatch.
        let order = if let Some((_, lock)) = &ordering {
            let mut acquire = Box::pin(lock.clone().lock_owned());
            let ready = poll_fn(|cx| Poll::Ready(acquire.as_mut().poll(cx))).await;
            Some(async move {
                match ready {
                    Poll::Ready(guard) => guard,
                    Poll::Pending => acquire.await,
                }
            })
        } else {
            None
        };
        let worker = self.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = cancellation.cancelled() => {},
                _ = worker.dispatch(&channel, request, credit, control, order) => {},
            }
            let mut active = worker.active.lock().expect("affinity worker lock");
            active.requests.remove(&id);
            if let Some((session, lock)) = ordering
                && Arc::strong_count(&lock) == 1
            {
                active.sessions.remove(&session);
            }
        });
    }

    async fn dispatch(
        &self,
        channel: &str,
        request: WireRequest,
        credit: mpsc::Receiver<()>,
        control: bool,
        order: Option<impl Future<Output = OwnedMutexGuard<()>>>,
    ) -> io::Result<()> {
        let (_ordered, _permit) = timeout(self.wait, async {
            let ordered = if let Some(order) = order {
                match timeout(self.lock_timeout, order).await {
                    Ok(guard) => Some(guard),
                    Err(_) => {
                        tracing::debug!("MCP affinity exceeded the per-session lock timeout");
                        None
                    }
                }
            } else {
                None
            };
            let permits = if control {
                &self.control_permits
            } else {
                &self.permits
            };
            let permit = if request.method == "GET" {
                None
            } else {
                Some(permits.acquire().await.map_err(io::Error::other)?)
            };
            Ok::<_, io::Error>((ordered, permit))
        })
        .await??;
        dispatch(
            &self.directory,
            channel,
            self.router.clone(),
            request,
            self.wait,
            credit,
        )
        .await
    }
}

async fn dispatch(
    directory: &RedisSessionDirectory,
    reply: &str,
    router: Router,
    request: WireRequest,
    wait: Duration,
    mut credit: mpsc::Receiver<()>,
) -> io::Result<()> {
    let response = match request.into_request() {
        Some(request) => match timeout(wait, router.oneshot(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => match error {},
            Err(_) => relay_error(StatusCode::GATEWAY_TIMEOUT, "Session worker timed out"),
        },
        None => relay_error(StatusCode::BAD_REQUEST, "Invalid forwarded MCP request"),
    };
    send_frame(
        directory,
        reply,
        &header_packet(&response)?,
        &mut credit,
        wait,
    )
    .await?;
    let mut body = response.into_body().into_data_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(io::Error::other)?;
        for bytes in chunk.chunks(MAX_CHUNK) {
            let mut frame = Vec::with_capacity(bytes.len() + 1);
            frame.push(DATA);
            frame.extend_from_slice(bytes);
            send_frame(directory, reply, &frame, &mut credit, wait).await?;
        }
    }
    publish(directory, reply, &[END]).await
}

async fn send_busy(directory: &RedisSessionDirectory, reply: &str) -> io::Result<()> {
    let response = relay_error(StatusCode::SERVICE_UNAVAILABLE, "Session worker is busy");
    publish(directory, reply, &header_packet(&response)?).await?;
    let body = to_bytes(response.into_body(), 1024)
        .await
        .map_err(io::Error::other)?;
    let mut frame = Vec::with_capacity(body.len() + 1);
    frame.push(DATA);
    frame.extend_from_slice(&body);
    publish(directory, reply, &frame).await?;
    publish(directory, reply, &[END]).await
}

async fn send_frame(
    directory: &RedisSessionDirectory,
    channel: &str,
    bytes: &[u8],
    credit: &mut mpsc::Receiver<()>,
    wait: Duration,
) -> io::Result<()> {
    publish(directory, channel, bytes).await?;
    timeout(wait, credit.recv())
        .await?
        .ok_or_else(|| io::Error::other("MCP relay client disconnected"))
}

fn header_packet(response: &Response) -> io::Result<Vec<u8>> {
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            if matches!(
                name.as_str(),
                "connection" | "transfer-encoding" | "content-length"
            ) {
                return None;
            }
            Some((name.to_string(), value.to_str().ok()?.to_owned()))
        })
        .collect();
    let mut bytes = vec![HEADERS];
    serde_json::to_writer(
        &mut bytes,
        &WireHeaders {
            status: response.status().as_u16(),
            headers,
        },
    )
    .map_err(io::Error::other)?;
    Ok(bytes)
}

fn relay_error(status: StatusCode, detail: &'static str) -> Response {
    (status, Json(json!({"detail":detail}))).into_response()
}

fn request_channel(worker: &str) -> String {
    format!("context-forge-rs:mcp:worker:{worker}")
}

fn reply_channel(id: &str) -> String {
    format!("context-forge-rs:mcp:reply:{id}")
}
