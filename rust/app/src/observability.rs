// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, net::SocketAddr, sync::Arc, time::Instant};

use axum::{
    Router,
    extract::{ConnectInfo, Request, State},
    http::{header, uri::Authority},
    middleware::{self, Next},
    response::Response,
};
use http_body::Body;
use jiff::Timestamp;
use regex::Regex;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    config::{flag, parse, value},
    database::Database,
};

pub(crate) mod background;
pub(crate) mod baggage;
pub(crate) mod framework;
mod operation;
pub(crate) mod query;
mod store;
pub(crate) mod telemetry;
pub(crate) use operation::{
    OperationSpan, Outcome, SpanResource, TraceContext, current_trace, with_trace,
};

pub(crate) fn safe_upstream_url(url: &url::Url) -> String {
    let mut url = url.clone();
    url.set_query(None);
    url.set_fragment(None);
    let _ = url.set_password(None);
    let _ = url.set_username("");
    bounded(url.as_str(), 2000)
}

const INCLUDE: &str = r#"["^/rpc/?$","^/sse$","^/message$","^/mcp(?:/|$)","^/servers/[^/]+/mcp/?$","^/servers/[^/]+/sse$","^/servers/[^/]+/message$","^/a2a(?:/|$)","^/v1/a2a(?:/|$)"]"#;
const EXCLUDE: &str = r#"["/health","/healthz","/ready","/metrics","/static/.*"]"#;
const SECRET_KEYS: &str = "password,secret,token,api_key,authorization,credential,auth_value,access_token,refresh_token,auth_token,client_secret,cookie,set-cookie,private_key,session_id,sessionid,session_token,secret_access_key,x-amz-security-token,x-amz-signature,x-amz-credential,code,assertion";

pub(crate) struct TraceLayer {
    database: Database,
    include: Vec<Regex>,
    exclude: Vec<Regex>,
    sample_rate: f64,
    redaction: QueryRedaction,
}

pub(crate) fn enabled() -> Result<bool, Box<dyn Error + Send + Sync>> {
    Ok(flag("OBSERVABILITY_ENABLED")?.unwrap_or(false))
}

impl TraceLayer {
    pub(crate) fn from_env(
        database: Database,
    ) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        if !enabled()? || !flag("OBSERVABILITY_TRACE_HTTP_REQUESTS")?.unwrap_or(true) {
            return Ok(None);
        }
        let sample_rate = parse("OBSERVABILITY_SAMPLE_RATE", 1.0)?;
        if !(0.0..=1.0).contains(&sample_rate) {
            return Err("invalid OBSERVABILITY_SAMPLE_RATE".into());
        }
        Ok(Some(Self {
            database,
            include: path_patterns("OBSERVABILITY_INCLUDE_PATHS", INCLUDE)?,
            exclude: path_patterns("OBSERVABILITY_EXCLUDE_PATHS", EXCLUDE)?,
            sample_rate,
            redaction: QueryRedaction::from_env()?,
        }))
    }

    pub(crate) fn apply(self: Arc<Self>, router: Router) -> Router {
        router.layer(middleware::from_fn_with_state(self, observe))
    }

    fn observes(&self, path: &str) -> bool {
        !matches!(
            path,
            "/health" | "/healthz" | "/ready" | "/metrics" | "/v1/metrics" | "/admin/events"
        ) && !path.starts_with("/static/")
            && !path.starts_with("/admin/observability/")
            && !self.exclude.iter().any(|pattern| pattern.is_match(path))
            && (self.include.is_empty()
                || self.include.iter().any(|pattern| pattern.is_match(path)))
    }
}

#[derive(Clone)]
struct QueryRedaction(Arc<std::collections::HashSet<String>>);

impl QueryRedaction {
    fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let custom = value("OTEL_REDACT_FIELDS", "")?;
        let keys = SECRET_KEYS
            .split(',')
            .chain(custom.split(','))
            .map(normalized_key)
            .filter(|key| !key.is_empty())
            .collect();
        Ok(Self(Arc::new(keys)))
    }

    fn sensitive_key(&self, key: &str) -> bool {
        self.0.contains(&normalized_key(key))
    }

    fn query(&self, raw: &str) -> String {
        let decoded = url::form_urlencoded::parse(raw.as_bytes());
        if !decoded.clone().any(|(key, _)| self.sensitive_key(&key)) {
            return raw.to_owned();
        }
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(decoded.map(|(key, value)| {
                let value = if self.sensitive_key(&key) {
                    "***".into()
                } else {
                    value
                };
                (key, value)
            }))
            .finish()
    }
}

fn path_patterns(name: &str, default: &str) -> Result<Vec<Regex>, Box<dyn Error + Send + Sync>> {
    let configured = value(name, default)?;
    let patterns: Vec<String> =
        serde_json::from_str(&configured).map_err(|_| format!("invalid {name}"))?;
    Ok(patterns
        .into_iter()
        .filter_map(|pattern| match Regex::new(&pattern) {
            Ok(pattern) => Some(pattern),
            Err(error) => {
                tracing::warn!(setting = name, %error, "Ignored invalid observability pattern");
                None
            }
        })
        .collect())
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

struct RequestTrace {
    id: String,
    span: String,
    started_at: Timestamp,
    started: Instant,
    name: String,
    method: String,
    url: String,
    agent: String,
    ip: Option<String>,
    attributes: Value,
    span_attrs: Value,
}

async fn observe(
    State(layer): State<Arc<TraceLayer>>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if layer.sample_rate == 0.0 || !layer.observes(path) {
        return next.run(request).await;
    }
    let generated = Uuid::new_v4();
    if layer.sample_rate < 1.0
        && (generated.as_u128() >> 64) as f64 / u64::MAX as f64 >= layer.sample_rate
    {
        return next.run(request).await;
    }
    let inherited = current_trace();
    let context = request
        .headers()
        .get("traceparent")
        .and_then(|value| traceparent(value.to_str().ok()?))
        .or_else(|| traceparent(&inherited.as_ref()?.exported.as_ref()?.traceparent));
    let query = request
        .uri()
        .query()
        .map(|query| bounded(&layer.redaction.query(query), 2000));
    let method = request.method().as_str();
    // The proxy middleware rewrites the request scheme for trusted forwarded traffic.
    let scheme = request.uri().scheme_str().unwrap_or("http");
    let host = request
        .uri()
        .authority()
        .cloned()
        .or_else(|| {
            request
                .headers()
                .get(header::HOST)?
                .to_str()
                .ok()?
                .parse::<Authority>()
                .ok()
        })
        .filter(|host| !host.as_str().contains('@'));
    let host = host.as_ref().map_or("localhost", Authority::as_str);
    let mut url = format!("{scheme}://{host}{path}");
    if let Some(query) = &query {
        url.push('?');
        url.push_str(query);
    }
    let url = bounded(&url, 767);
    let mut attributes = json!({"http.route":bounded(path, 2000),"http.query":query});
    if let Some((_, parent)) = &context {
        attributes["parent_span_id"] = json!(parent);
    }
    let mut trace = RequestTrace {
        id: context.map_or_else(|| generated.hyphenated().to_string(), |(id, _)| id),
        span: Uuid::new_v4().hyphenated().to_string(),
        started_at: Timestamp::now(),
        started: Instant::now(),
        name: bounded(&format!("{method} {path}"), 255),
        method: bounded(method, 10),
        agent: bounded(
            request
                .headers()
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .filter(|agent| !agent.is_empty())
                .unwrap_or("unknown"),
            500,
        ),
        ip: request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|peer| peer.0.ip().to_string()),
        span_attrs: json!({"http.method":method,"http.url":url}),
        url,
        attributes,
    };
    let owns = match layer.database.start_http_trace(&trace).await {
        Ok(owns) => owns,
        Err(error) => {
            tracing::warn!(%error, "Trace recording could not start");
            return next.run(request).await;
        }
    };
    let context = inherited
        .unwrap_or_default()
        .with_stored(trace.id.clone(), trace.span.clone());
    request.extensions_mut().insert(context.clone());
    let response = with_trace(Some(context), next.run(request)).await;
    let code = response.status().as_u16();
    let size = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            response
                .body()
                .size_hint()
                .exact()
                .map(|size| size.to_string())
        });
    trace.span_attrs["http.status_code"] = json!(code);
    trace.span_attrs["http.response_size"] = json!(size);
    let duration = trace.started.elapsed().as_secs_f64() * 1000.0;
    trace.attributes["response_time_ms"] = json!(duration);
    if let Err(error) = layer
        .database
        .finish_http_trace(&trace, owns, code, duration)
        .await
    {
        tracing::warn!(%error, "Trace recording could not finish");
    }
    response
}

fn bounded(text: &str, maximum: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .take(maximum)
        .collect()
}

fn traceparent(value: &str) -> Option<(String, String)> {
    let mut fields = value.split('-');
    if fields.next()? != "00" {
        return None;
    }
    let trace = fields.next()?;
    let parent = fields.next()?;
    let flags = fields.next()?;
    let hex = |value: &str, length: usize| {
        value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    if fields.next().is_some()
        || !hex(trace, 32)
        || !hex(parent, 16)
        || !hex(flags, 2)
        || trace.bytes().all(|byte| byte == b'0')
        || parent.bytes().all(|byte| byte == b'0')
    {
        return None;
    }
    Some((trace.to_ascii_lowercase(), parent.to_ascii_lowercase()))
}
