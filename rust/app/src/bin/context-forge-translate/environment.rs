// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, HashSet},
    io,
    sync::Arc,
    time::Duration,
};

use axum::http::{HeaderMap, HeaderName};
use serde_json::{Value, json};
use tokio::{
    process::Command,
    sync::{mpsc, watch},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use super::stdio::{StdioBridge, StdioProcess};

const DEFAULT_MAX_HEADER_VALUE: usize = 4096;
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) type EnvironmentValues = BTreeMap<String, String>;

pub(super) struct DynamicEnvironment {
    command: String,
    mappings: Vec<(HeaderName, String)>,
    max_header_value: usize,
}

impl DynamicEnvironment {
    pub(super) fn parse(command: String, entries: &[String]) -> io::Result<Self> {
        let mut mappings = Vec::with_capacity(entries.len());
        let mut seen = HashSet::new();
        for entry in entries {
            let (header, name) = entry
                .split_once('=')
                .ok_or_else(|| invalid("Expected HEADER=ENV_VAR"))?;
            let header = header.trim();
            let name = name.trim();
            if !header
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
                || !header
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(invalid("Invalid environment mapping header name"));
            }
            if name.len() > 64
                || !name
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err(invalid("Invalid environment variable name"));
            }
            let header = HeaderName::from_bytes(header.as_bytes()).map_err(io::Error::other)?;
            if !seen.insert(header.clone()) {
                return Err(invalid("Duplicate header-to-environment mapping"));
            }
            mappings.push((header, name.to_owned()));
        }
        let max_header_value = std::env::var("MAX_HEADER_VALUE_LENGTH")
            .ok()
            .map(|value| {
                value
                    .parse::<usize>()
                    .ok()
                    .filter(|size| *size > 0)
                    .ok_or_else(|| invalid("MAX_HEADER_VALUE_LENGTH must be a positive integer"))
            })
            .transpose()?
            .unwrap_or(DEFAULT_MAX_HEADER_VALUE);
        Ok(Self {
            command,
            mappings,
            max_header_value,
        })
    }

    pub(super) fn values(&self, headers: &HeaderMap) -> EnvironmentValues {
        self.mappings
            .iter()
            .filter_map(|(header, name)| {
                let value = headers.get(header)?;
                let filtered: String = value
                    .as_bytes()
                    .iter()
                    .take(self.max_header_value)
                    .copied()
                    .filter(|byte| (b' '..=b'~').contains(byte))
                    .map(char::from)
                    .collect();
                (!filtered.is_empty()).then(|| (name.clone(), filtered))
            })
            .collect()
    }

    pub(super) fn apply(&self, command: &mut Command, values: &EnvironmentValues) {
        const SYSTEM_ENV: &[&str] = &[
            "PATH",
            "HOME",
            "TMPDIR",
            "TEMP",
            "TMP",
            "USER",
            "LOGNAME",
            "SHELL",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "PYTHONHOME",
            "PYTHONPATH",
        ];
        for (_, name) in &self.mappings {
            if !SYSTEM_ENV.contains(&name.as_str()) {
                command.env_remove(name);
            }
        }
        command.envs(values);
    }

    pub(super) fn start_session(
        self: &Arc<Self>,
        values: EnvironmentValues,
        close: CancellationToken,
        outgoing: mpsc::Sender<Value>,
    ) -> io::Result<EnvironmentConnection> {
        let (process, bridge) = self.start(&values, &close)?;
        let (active, reader) = watch::channel(bridge.clone());
        let (sender, incoming) = mpsc::channel(16);
        let environment = self.clone();
        tokio::spawn(async move {
            let session = EnvironmentSession {
                environment,
                active,
                process,
                bridge,
                values,
            };
            session.run(close, incoming, outgoing).await;
        });
        Ok(EnvironmentConnection {
            incoming: sender,
            active: reader,
        })
    }

    fn start(
        &self,
        values: &EnvironmentValues,
        close: &CancellationToken,
    ) -> io::Result<(StdioProcess, Arc<StdioBridge>)> {
        StdioProcess::start(&self.command, close, Some((self, values)))
    }
}

pub(super) struct EnvironmentRequest {
    pub(super) message: Value,
    pub(super) values: EnvironmentValues,
}

pub(super) struct EnvironmentConnection {
    pub(super) incoming: mpsc::Sender<EnvironmentRequest>,
    pub(super) active: watch::Receiver<Arc<StdioBridge>>,
}

struct EnvironmentSession {
    environment: Arc<DynamicEnvironment>,
    active: watch::Sender<Arc<StdioBridge>>,
    process: StdioProcess,
    bridge: Arc<StdioBridge>,
    values: EnvironmentValues,
}

impl EnvironmentSession {
    async fn run(
        mut self,
        close: CancellationToken,
        mut incoming: mpsc::Receiver<EnvironmentRequest>,
        outgoing: mpsc::Sender<Value>,
    ) {
        let send_replies = async {
            while let Some(request) = incoming.recv().await {
                let result = if !request.values.is_empty() && request.values != self.values {
                    self.replace_child(request.values, &close).await
                } else {
                    Ok(())
                };
                let id = request.message.get("id").cloned();
                let reply = match result {
                    Ok(()) => self.bridge.submit(request.message).await,
                    Err(error) => Err(error),
                };
                let message = match reply {
                    Ok(Some(reply)) => timeout(REPLY_TIMEOUT, reply.receive()).await.ok().flatten(),
                    Ok(None) => None,
                    Err(error) => {
                        tracing::debug!(%error, "could not forward scoped stdio request");
                        id.map(|id| json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"Stdio process unavailable"}}))
                    }
                };
                if let Some(message) = message
                    && outgoing.send(message).await.is_err()
                {
                    break;
                }
            }
        };
        tokio::select! {
            () = close.cancelled() => {},
            () = send_replies => {},
        }
        self.process.stop().await;
    }

    async fn replace_child(
        &mut self,
        values: EnvironmentValues,
        close: &CancellationToken,
    ) -> io::Result<()> {
        let (process, bridge) = self.environment.start(&values, close)?;
        let previous = std::mem::replace(&mut self.process, process);
        self.bridge = bridge.clone();
        self.values = values;
        self.active.send_replace(bridge);
        previous.stop().await;
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
