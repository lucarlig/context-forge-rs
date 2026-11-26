// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, io, sync::Arc, time::Duration};

use context_forge_rs::upstream::{SseStream, resolve_sse_endpoint};
use reqwest::{
    Client, Response, Url,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue},
};
use serde_json::Value;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt, BufReader},
    process::{ChildStdin, ChildStdout},
    sync::{Mutex, watch},
    time::{sleep, timeout},
};

use super::stdio::{self, MAX_MESSAGE_BYTES};

type RemoteResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const SESSION_HEADER: &str = "mcp-session-id";
const VERSION_HEADER: &str = "mcp-protocol-version";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Transport {
    Sse,
    StreamableHttp,
}

struct Remote {
    client: Client,
    url: Url,
    transport: Transport,
}

#[derive(Clone)]
struct Connection {
    post_url: Option<Url>,
    session: Option<HeaderValue>,
    version: Option<String>,
}

pub(super) async fn run(
    url: &str,
    transport: Transport,
    bearer: Option<&str>,
    command: Option<&str>,
) -> RemoteResult<()> {
    let mut url = Url::parse(url)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("remote endpoint must be an HTTP URL".into());
    }
    if transport == Transport::StreamableHttp && !url.path().trim_end_matches('/').ends_with("/mcp")
    {
        url.set_path(&format!("{}/mcp", url.path().trim_end_matches('/')));
    }
    let mut headers = HeaderMap::new();
    if let Some(bearer) = bearer {
        let mut value = format!("Bearer {bearer}").parse::<HeaderValue>()?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::builder()
        .no_proxy()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(READ_TIMEOUT)
        .build()?;
    let connection = watch::Sender::new(Connection {
        post_url: (transport == Transport::StreamableHttp).then(|| url.clone()),
        session: None,
        version: None,
    });
    let remote = Remote {
        client,
        url,
        transport,
    };

    let Some(command) = command else {
        let stdout = Arc::new(Mutex::new(tokio::io::stdout()));
        return tokio::select! {
            result = remote.pump_events(&connection, stdout) => result,
            () = super::shutdown_signal() => Ok(()),
        };
    };
    let (mut child, stdin, stdout) = stdio::spawn(command, None)?;
    let input = Arc::new(Mutex::new(stdin));
    let result = tokio::select! {
        result = remote.pump_events(&connection, input.clone()) => result,
        result = remote.post_child_messages(&connection, input, stdout) => result,
        result = child.wait() => result.map(|_| ()).map_err(Into::into),
        () = super::shutdown_signal() => Ok(()),
    };
    let _ = child.kill().await;
    result
}

impl Remote {
    async fn pump_events<W: AsyncWrite + Unpin>(
        &self,
        connection: &watch::Sender<Connection>,
        output: Arc<Mutex<W>>,
    ) -> RemoteResult<()> {
        let mut failures = 0;
        let mut changes = connection.subscribe();
        loop {
            let mut reconnect = false;
            let state = changes.borrow_and_update().clone();
            let mut request = self
                .client
                .get(self.url.clone())
                .header(ACCEPT, "text/event-stream");
            request = with_session_headers(request, &state);
            let receive = async {
                let response = tokio::select! {
                    response = request.send() => response.map_err(reqwest::Error::without_url)?
                        .error_for_status().map_err(reqwest::Error::without_url)?,
                    change = changes.changed(), if self.transport == Transport::StreamableHttp => {
                        change?;
                        reconnect = true;
                        return Ok(());
                    }
                };
                if !is_event_stream(&response) {
                    return Err("remote endpoint did not return an SSE stream".into());
                }
                let mut stream = SseStream::new(response);
                loop {
                    let frame = tokio::select! {
                        frame = stream.next() => frame?,
                        change = changes.changed(), if self.transport == Transport::StreamableHttp => {
                            change?;
                            reconnect = true;
                            return Ok(());
                        }
                    };
                    let Some(frame) = frame else {
                        break;
                    };
                    match (self.transport, stream.event_type()) {
                        (Transport::Sse, Some("endpoint")) => {
                            let endpoint = resolve_sse_endpoint(&self.url, &frame)?;
                            connection.send_modify(|state| state.post_url = Some(endpoint));
                        }
                        (Transport::Sse, None | Some("message"))
                        | (Transport::StreamableHttp, _) => {
                            write_frame(&output, &frame).await?;
                        }
                        _ => {}
                    }
                }
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            };
            let result = receive.await;
            if reconnect {
                continue;
            }
            if self.transport == Transport::Sse {
                connection.send_modify(|state| state.post_url = None);
            }
            let delay = match result {
                Ok(()) => {
                    failures = 0;
                    Duration::from_secs(1)
                }
                Err(error) => {
                    failures += 1;
                    if failures >= 5 {
                        return Err(error);
                    }
                    tracing::debug!(attempt = failures, "remote SSE connection interrupted");
                    Duration::from_secs(1 << (failures - 1))
                }
            };
            tokio::select! {
                () = sleep(delay) => {},
                change = changes.changed(), if self.transport == Transport::StreamableHttp => {
                    change?;
                    failures = 0;
                }
            }
        }
    }

    async fn post_child_messages(
        &self,
        connection: &watch::Sender<Connection>,
        stdin: Arc<Mutex<ChildStdin>>,
        stdout: ChildStdout,
    ) -> RemoteResult<()> {
        let mut reader = BufReader::new(stdout);
        let mut line = Vec::new();
        let mut state = connection.subscribe();
        while stdio::read_line(&mut reader, &mut line).await? {
            let Ok(message) = serde_json::from_slice::<Value>(&line) else {
                continue;
            };
            let mut ready = match timeout(
                READ_TIMEOUT,
                state.wait_for(|state| state.post_url.is_some()),
            )
            .await
            {
                Ok(Ok(ready)) => ready.clone(),
                _ => {
                    tracing::debug!("remote SSE message endpoint unavailable");
                    continue;
                }
            };
            if message["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"].is_string() {
                ready.version = None;
                ready.session = None;
            }
            let Some(url) = ready.post_url.clone() else {
                continue;
            };
            let request = self
                .client
                .post(url)
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/json, text/event-stream")
                .body(std::mem::take(&mut line));
            let request = with_rpc_headers(with_session_headers(request, &ready), &message);
            let response = match request.send().await {
                Ok(response) if response.status().is_success() => response,
                Ok(response) => {
                    tracing::debug!(status = %response.status(), "remote MCP message rejected");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(error = %error.without_url(), "remote MCP message failed");
                    continue;
                }
            };
            if self.transport == Transport::StreamableHttp {
                if let Some(session) = response.headers().get(SESSION_HEADER) {
                    connection.send_if_modified(|state| {
                        if state.session.as_ref() == Some(session) {
                            return false;
                        }
                        state.session = Some(session.clone());
                        true
                    });
                }
                forward_post_reply(response, message.get("id"), &stdin, connection).await?;
            }
        }
        Ok(())
    }
}

fn with_session_headers(
    mut request: reqwest::RequestBuilder,
    state: &Connection,
) -> reqwest::RequestBuilder {
    if let Some(session) = &state.session {
        request = request.header(SESSION_HEADER, session);
    }
    if let Some(version) = &state.version {
        request = request.header(VERSION_HEADER, version);
    }
    request
}

fn with_rpc_headers(
    mut request: reqwest::RequestBuilder,
    message: &Value,
) -> reqwest::RequestBuilder {
    let Some(version) =
        message["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str()
    else {
        return request;
    };
    request = request.header(VERSION_HEADER, version);
    if let Some(method) = message["method"].as_str() {
        request = request.header("mcp-method", method);
        let name_key = match method {
            "tools/call" | "prompts/get" => "name",
            "resources/read" => "uri",
            _ => return request,
        };
        if let Some(name) = message["params"][name_key].as_str() {
            request = request.header("mcp-name", name);
        }
    }
    request
}

async fn forward_post_reply(
    mut response: Response,
    id: Option<&Value>,
    output: &Arc<Mutex<ChildStdin>>,
    connection: &watch::Sender<Connection>,
) -> RemoteResult<()> {
    if response.status() != reqwest::StatusCode::OK {
        return Ok(());
    }
    if is_event_stream(&response) {
        let mut frames = SseStream::new(response);
        while let Some(frame) = frames.next().await? {
            if forward_json_reply(&frame, id, output, connection).await? {
                break;
            }
        }
    } else {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_MESSAGE_BYTES {
                return Err("remote MCP response exceeds the size limit".into());
            }
            body.extend_from_slice(&chunk);
        }
        if !body.is_empty() {
            forward_json_reply(&body, id, output, connection).await?;
        }
    }
    Ok(())
}

async fn forward_json_reply(
    frame: &[u8],
    id: Option<&Value>,
    output: &Arc<Mutex<ChildStdin>>,
    connection: &watch::Sender<Connection>,
) -> RemoteResult<bool> {
    let value = serde_json::from_slice::<Value>(frame)?;
    if let Some(version) = value["result"]["protocolVersion"].as_str() {
        connection.send_if_modified(|state| {
            if state.version.as_deref() == Some(version) {
                return false;
            }
            state.version = Some(version.to_owned());
            true
        });
    }
    write_frame(output, &serde_json::to_vec(&value)?).await?;
    Ok(id.is_some() && value.get("id") == id)
}

fn is_event_stream(response: &Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
}

async fn write_frame(output: &Mutex<impl AsyncWrite + Unpin>, frame: &[u8]) -> io::Result<()> {
    let mut output = output.lock().await;
    output.write_all(frame).await?;
    output.write_all(b"\n").await?;
    output.flush().await
}
