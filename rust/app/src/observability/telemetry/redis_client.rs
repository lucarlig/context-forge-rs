// SPDX-License-Identifier: Apache-2.0

use opentelemetry::{
    KeyValue,
    global::BoxedSpan,
    trace::{Span, SpanKind, Status},
};
use redis::{
    Arg, Client, Cmd, ConnectionAddr, ConnectionInfo, FromRedisValue, RedisResult,
    aio::ConnectionLike,
};
use serde::{Deserialize, Serialize};

use super::{ExportSpan, SemanticConventions, SettingsError};
use crate::observability::{bounded, current_trace};

#[derive(Clone, Copy, Deserialize, Serialize)]
pub(in crate::observability) struct RedisConventions {
    database: SemanticConventions,
    network: SemanticConventions,
}

impl RedisConventions {
    pub(super) fn from_env() -> Result<Self, SettingsError> {
        Ok(Self {
            database: SemanticConventions::from_env("database")?,
            network: SemanticConventions::from_env("http")?,
        })
    }
}

pub(crate) async fn query<T: FromRedisValue>(
    client: &Client,
    command: &Cmd,
    connection: &mut impl ConnectionLike,
) -> RedisResult<T> {
    let span = start(client.get_connection_info(), command);
    let result = command.query_async(connection).await;
    if let Some(mut span) = span {
        if result.is_err() {
            span.set_status(Status::error("Redis command failed"));
        }
        span.end();
    }
    result
}

fn start(connection: &ConnectionInfo, command: &Cmd) -> Option<BoxedSpan> {
    let trace = current_trace()?;
    let (parent, mode) = (trace.exported?, trace.redis_commands?);
    let (name, attributes) = describe(connection, command, mode);
    match parent.start_span(name, SpanKind::Client, attributes) {
        ExportSpan::Recording(span) => Some(span),
        ExportSpan::Unsampled(_) => None,
    }
}

fn describe(
    connection: &ConnectionInfo,
    command: &Cmd,
    mode: RedisConventions,
) -> (String, Vec<KeyValue>) {
    let mut args = command.args_iter();
    let count = args.len();
    let name = match args.next() {
        Some(Arg::Simple(name)) => std::str::from_utf8(name)
            .ok()
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= 64
                    && name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
            .unwrap_or("REDIS")
            .to_ascii_uppercase(),
        _ => "REDIS".to_owned(),
    };
    let placeholders = args.len();
    let limit = (1000 - name.len() - 3) / 2;
    let suffix = if placeholders > limit { "..." } else { "" };
    let query = format!("{name}{}{suffix}", " ?".repeat(placeholders.min(limit)));
    let mut attrs = vec![KeyValue::new(
        "db.redis.args_length",
        i64::try_from(count).unwrap_or(i64::MAX),
    )];
    if mode.database.legacy() {
        attrs.extend([
            KeyValue::new("db.system", "redis"),
            KeyValue::new("db.statement", query.clone()),
            KeyValue::new("db.redis.database_index", connection.redis_settings().db()),
        ]);
    }
    if mode.database.standard() {
        attrs.extend([
            KeyValue::new("db.system.name", "redis"),
            KeyValue::new("db.query.text", query),
        ]);
    }
    match connection.addr() {
        ConnectionAddr::Tcp(host, port) | ConnectionAddr::TcpTls { host, port, .. } => {
            if mode.network.legacy() {
                attrs.extend([
                    KeyValue::new("net.peer.name", bounded(host, 255)),
                    KeyValue::new("net.peer.port", i64::from(*port)),
                    KeyValue::new("net.transport", "ip_tcp"),
                ]);
            }
            if mode.network.standard() {
                attrs.extend([
                    KeyValue::new("server.address", bounded(host, 255)),
                    KeyValue::new("server.port", i64::from(*port)),
                    KeyValue::new("network.transport", "tcp"),
                ]);
            }
        }
        ConnectionAddr::Unix(_) => {
            if mode.network.legacy() {
                attrs.push(KeyValue::new("net.transport", "other"));
            }
            if mode.network.standard() {
                attrs.push(KeyValue::new("network.transport", "unix"));
            }
        }
        _ => {}
    }
    (name, attrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_placeholders_without_keys_scripts_or_redis_credentials() {
        let client = Client::open("redis://user:connection-private@localhost:6380/3").unwrap();
        let mut cmd = redis::cmd("EVAL");
        cmd.arg("script-private").arg(1).arg("key-private");
        let (name, attributes) = describe(
            client.get_connection_info(),
            &cmd,
            RedisConventions {
                database: SemanticConventions::Both,
                network: SemanticConventions::Both,
            },
        );
        assert_eq!(name, "EVAL");
        assert!(attributes.contains(&KeyValue::new("db.statement", "EVAL ? ? ?")));
        assert!(attributes.contains(&KeyValue::new("db.query.text", "EVAL ? ? ?")));
        assert!(attributes.contains(&KeyValue::new("db.redis.database_index", 3)));
        assert!(!format!("{attributes:?}").contains("-private"));
    }
}
