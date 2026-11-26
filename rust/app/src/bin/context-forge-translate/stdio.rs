// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    io,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use serde_json::Value;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{broadcast, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::environment::{DynamicEnvironment, EnvironmentValues};

pub(super) const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PENDING: usize = 128;
type PendingReplies = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;
type Environment<'a> = Option<(&'a DynamicEnvironment, &'a EnvironmentValues)>;

pub(super) struct StdioProcess {
    child: Child,
    tasks: [JoinHandle<()>; 2],
    stop: CancellationToken,
}

pub(super) struct StdioBridge {
    input: mpsc::Sender<Vec<u8>>,
    replies: PendingReplies,
    pub(super) events: broadcast::Sender<Value>,
    stop: CancellationToken,
    id: AtomicU64,
}

impl StdioProcess {
    pub(super) fn start(
        command: &str,
        shutdown: &CancellationToken,
        environment: Environment<'_>,
    ) -> io::Result<(Self, Arc<StdioBridge>)> {
        let (child, mut stdin, stdout) = spawn(command, environment)?;
        let (input, mut messages) = mpsc::channel::<Vec<u8>>(16);
        let bridge = Arc::new(StdioBridge {
            input,
            replies: Arc::default(),
            events: broadcast::channel(128).0,
            stop: shutdown.child_token(),
            id: AtomicU64::new(1),
        });
        let writer_stop = bridge.stop.clone();
        let writer = tokio::spawn(async move {
            let write = async {
                while let Some(message) = messages.recv().await {
                    stdin.write_all(&message).await?;
                }
                Ok::<(), io::Error>(())
            };
            tokio::select! {
                () = writer_stop.cancelled() => {},
                result = write => {
                    if let Err(error) = result {
                        tracing::debug!(%error, "stdio input closed");
                    }
                    writer_stop.cancel();
                }
            }
        });
        let reader_stop = bridge.stop.clone();
        let replies = bridge.replies.clone();
        let events = bridge.events.clone();
        let reader = tokio::spawn(async move {
            let read = async {
                let mut reader = BufReader::new(stdout);
                let mut line = Vec::new();
                loop {
                    if !read_line(&mut reader, &mut line).await? {
                        return Ok::<(), io::Error>(());
                    }
                    match serde_json::from_slice::<Value>(&line) {
                        Ok(Value::Array(messages)) => {
                            for message in messages {
                                deliver(message, &replies, &events);
                            }
                        }
                        Ok(message) => deliver(message, &replies, &events),
                        Err(_) => continue,
                    }
                }
            };
            tokio::select! {
                () = reader_stop.cancelled() => {},
                result = read => {
                    if let Err(error) = result {
                        tracing::debug!(%error, "stdio output closed");
                    }
                    reader_stop.cancel();
                }
            }
            replies.lock().expect("pending stdio replies").clear();
        });
        Ok((
            Self {
                child,
                tasks: [writer, reader],
                stop: bridge.stop.clone(),
            },
            bridge,
        ))
    }

    pub(super) async fn stop(mut self) {
        self.stop.cancel();
        let _ = self.child.kill().await;
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

pub(super) fn spawn(
    command: &str,
    environment: Environment<'_>,
) -> io::Result<(Child, ChildStdin, ChildStdout)> {
    let arguments = shell_words::split(command).map_err(io::Error::other)?;
    let (program, arguments) = arguments
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "stdio command is empty"))?;
    let mut child_command = Command::new(program);
    child_command
        .args(arguments)
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some((environment, values)) = environment {
        environment.apply(&mut child_command, values);
    }
    let mut child = child_command.spawn()?;
    let stdin = child.stdin.take().expect("piped child stdin");
    let stdout = child.stdout.take().expect("piped child stdout");
    Ok((child, stdin, stdout))
}

pub(super) async fn read_line(
    reader: &mut (impl AsyncBufRead + Unpin),
    line: &mut Vec<u8>,
) -> io::Result<bool> {
    line.clear();
    let bytes = reader
        .take((MAX_MESSAGE_BYTES + 1) as u64)
        .read_until(b'\n', line)
        .await?;
    if bytes > MAX_MESSAGE_BYTES {
        return Err(io::Error::other("stdio output line exceeds the size limit"));
    }
    Ok(bytes > 0)
}

impl StdioBridge {
    pub(super) async fn submit(&self, mut message: Value) -> io::Result<Option<StdioReply>> {
        let mut reply = None;
        if let Some(id) = message
            .as_object_mut()
            .and_then(|object| object.get_mut("id"))
        {
            let (send, receive) = oneshot::channel();
            let internal = self.id.fetch_add(1, Ordering::Relaxed);
            let mut replies = self.replies.lock().expect("pending stdio replies");
            if replies.len() >= MAX_PENDING {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "too many pending stdio requests",
                ));
            }
            replies.insert(internal, send);
            reply = Some(StdioReply {
                original: std::mem::replace(id, internal.into()),
                internal,
                receive,
                replies: self.replies.clone(),
            });
        }
        let mut bytes = serde_json::to_vec(&message).map_err(io::Error::other)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stdio message exceeds the size limit",
            ));
        }
        let closed = || io::Error::new(io::ErrorKind::BrokenPipe, "stdio process is closed");
        tokio::select! {
            () = self.stop.cancelled() => Err(closed()),
            result = self.input.send(bytes) => result.map(|()| reply).map_err(|_| closed()),
        }
    }
}

pub(super) struct StdioReply {
    original: Value,
    internal: u64,
    receive: oneshot::Receiver<Value>,
    replies: PendingReplies,
}

impl StdioReply {
    pub(super) async fn receive(mut self) -> Option<Value> {
        let mut reply = (&mut self.receive).await.ok()?;
        reply["id"] = std::mem::take(&mut self.original);
        Some(reply)
    }
}

impl Drop for StdioReply {
    fn drop(&mut self) {
        self.replies
            .lock()
            .expect("pending stdio replies")
            .remove(&self.internal);
    }
}

fn deliver(message: Value, replies: &PendingReplies, events: &broadcast::Sender<Value>) {
    if let Some(id) = message["id"].as_u64()
        && (message.get("result").is_some() || message.get("error").is_some())
    {
        if let Some(pending) = replies.lock().expect("pending stdio replies").remove(&id) {
            let _ = pending.send(message);
        }
    } else if message["method"].is_string() && message.get("id").is_none() {
        let _ = events.send(message);
    }
}
