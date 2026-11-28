// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Cow,
    error::Error,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, MatchedPath, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Version, header},
    middleware::{self, Next},
    response::Response,
};
use http_body::{Body as HttpBody, Frame, SizeHint};
use opentelemetry::{
    Array, Context, InstrumentationScope, Key, KeyValue, Value as OtelValue,
    global::{self, BoxedSpan},
    propagation::{Extractor, TextMapPropagator},
    trace::{
        Span, SpanContext, SpanId, SpanKind, Status, TraceContextExt, TraceState, Tracer,
        TracerProvider,
    },
};
use opentelemetry_otlp::{
    Protocol, SpanExporter, WithExportConfig, WithHttpConfig, WithTonicConfig,
};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    propagation::TraceContextPropagator,
    trace::{
        BatchConfigBuilder, BatchSpanProcessor, SdkTracer, SdkTracerProvider, Span as SdkSpan,
        SpanData, SpanExporter as SdkSpanExporter, SpanProcessor,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tonic::{metadata::MetadataMap, transport::ClientTlsConfig};
use url::Url;
use uuid::Uuid;

use super::{QueryRedaction, TraceContext, baggage, bounded, framework, with_trace};
use crate::{
    config::{flag, parse, value},
    http_boundary::CorrelationId,
};

type SettingsError = Box<dyn Error + Send + Sync>;

pub(crate) mod client;
mod jaeger;
pub(super) mod langfuse;
pub(crate) mod redis_client;
pub(crate) mod sql_client;
mod zipkin;
use redis_client::RedisConventions;

#[derive(Clone, Copy, Deserialize, Serialize)]
pub(super) enum SemanticConventions {
    Legacy,
    Standard,
    Both,
}

impl SemanticConventions {
    fn from_env(signal: &str) -> Result<Self, SettingsError> {
        let modes = value("OTEL_SEMCONV_STABILITY_OPT_IN", "")?;
        let duplicate = format!("{signal}/dup");
        let selected = |name| modes.split(',').any(|mode| mode.trim() == name);
        Ok(if selected(duplicate.as_str()) {
            Self::Both
        } else if selected(signal) {
            Self::Standard
        } else {
            Self::Legacy
        })
    }

    fn legacy(self) -> bool {
        matches!(self, Self::Legacy | Self::Both)
    }

    fn standard(self) -> bool {
        matches!(self, Self::Standard | Self::Both)
    }
}

pub(crate) struct Telemetry {
    provider: SdkTracerProvider,
    tracer: SdkTracer,
    framework_tracer: SdkTracer,
    redaction: QueryRedaction,
    baggage: Option<baggage::Policy>,
    host: String,
    port: u16,
    http_clients: Option<SemanticConventions>,
    redis_commands: Option<RedisConventions>,
    sql_queries: Option<SemanticConventions>,
    system_traces: bool,
}

impl Telemetry {
    pub(crate) fn from_env(port: u16) -> Result<Option<Self>, SettingsError> {
        if !flag("OTEL_ENABLE_OBSERVABILITY")?.unwrap_or(false) {
            return Ok(None);
        }
        let exporter = value("OTEL_TRACES_EXPORTER", "otlp")?.to_ascii_lowercase();
        let endpoint = langfuse::configured_endpoint()?;
        let is_langfuse = langfuse::matches_endpoint(&endpoint);
        let builder = SdkTracerProvider::builder();
        let builder = match exporter.as_str() {
            "none" => return Ok(None),
            "jaeger" => {
                let Ok(exporter) = jaeger::Exporter::from_env() else {
                    tracing::warn!("Could not configure the Jaeger trace exporter");
                    return Ok(None);
                };
                builder.with_span_processor(batch_processor(exporter)?)
            }
            "zipkin" => {
                let Ok(exporter) = zipkin::Exporter::from_env() else {
                    tracing::warn!("Could not configure the Zipkin trace exporter");
                    return Ok(None);
                };
                builder.with_span_processor(batch_processor(exporter)?)
            }
            "otlp" => {
                if endpoint.is_empty() {
                    return Ok(None);
                }
                let configured_headers = value("OTEL_EXPORTER_OTLP_HEADERS", "")?;
                let authorization = is_langfuse
                    .then(|| langfuse::authorization(&configured_headers))
                    .transpose()?;
                let Ok(exporter) = otlp_exporter(&endpoint, &configured_headers, authorization)
                else {
                    tracing::warn!("Could not configure the OTLP trace exporter");
                    return Ok(None);
                };
                builder.with_span_processor(batch_processor(exporter)?)
            }
            _ => builder.with_simple_exporter(opentelemetry_stdout::SpanExporter::default()),
        };
        let environment = value("DEPLOYMENT_ENV", &value("ENVIRONMENT", "development")?)?;
        let mut attributes = vec![
            KeyValue::new("service.name", value("OTEL_SERVICE_NAME", SERVICE)?),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("deployment.environment", environment.clone()),
        ];
        attributes.extend(
            settings_pairs(&value("OTEL_RESOURCE_ATTRIBUTES", "")?)
                .map(|(key, value)| KeyValue::new(key.to_owned(), value.to_owned())),
        );
        let builder = if flag("OTEL_COPY_RESOURCE_ATTRS_TO_SPANS")?.unwrap_or(false) {
            builder.with_span_processor(ResourceSpanAttributes::default())
        } else {
            builder
        };
        let redaction = QueryRedaction::from_env()?;
        let baggage = match baggage::Policy::from_env(&redaction) {
            Ok(policy) => policy,
            Err(_) => {
                tracing::warn!("Could not configure OpenTelemetry baggage");
                None
            }
        };
        let builder = if baggage.is_some() {
            builder.with_span_processor(baggage::Processor)
        } else {
            builder
        };
        let provider = builder
            .with_resource(Resource::builder().with_attributes(attributes).build())
            .build();
        let tracer = provider.tracer_with_scope(scope());
        let framework_tracer = provider.tracer_with_scope(framework::scope());
        let host = value("HOST", "127.0.0.1")?;
        let http_clients = flag("OTEL_HTTPX_INSTRUMENTATION_ENABLED")?
            .unwrap_or(false)
            .then(|| SemanticConventions::from_env("http"))
            .transpose()?;
        let redis_commands = flag("OTEL_REDIS_INSTRUMENTATION_ENABLED")?
            .unwrap_or(false)
            .then(RedisConventions::from_env)
            .transpose()?;
        let sql_queries = flag("OTEL_SQLALCHEMY_INSTRUMENTATION_ENABLED")?
            .unwrap_or(false)
            .then(|| SemanticConventions::from_env("database"))
            .transpose()?;
        let system_traces = flag("OTEL_SYSTEM_TRACES_ENABLED")?.unwrap_or(false);
        langfuse::configure_policy(is_langfuse, environment, redaction.clone())?;
        global::set_tracer_provider(provider.clone());
        Ok(Some(Self {
            provider,
            tracer,
            framework_tracer,
            redaction,
            baggage,
            host,
            port,
            http_clients,
            redis_commands,
            sql_queries,
            system_traces,
        }))
    }

    pub(crate) fn apply(self: Arc<Self>, router: Router) -> Router {
        router.layer(middleware::from_fn_with_state(self, observe))
    }

    pub(crate) fn system_context(&self) -> Option<TraceContext> {
        self.system_traces.then(|| self.trace_context())
    }

    fn trace_context(&self) -> TraceContext {
        TraceContext {
            http_clients: self.http_clients,
            redis_commands: self.redis_commands,
            sql_queries: self.sql_queries,
            ..TraceContext::default()
        }
    }

    pub(crate) async fn shutdown(&self) {
        let provider = self.provider.clone();
        let shutdown = tokio::task::spawn_blocking(move || provider.shutdown()).await;
        if !matches!(shutdown, Ok(Ok(()))) {
            tracing::warn!("OpenTelemetry shutdown could not flush all spans");
        }
    }
}

#[derive(Debug, Default)]
struct ResourceSpanAttributes {
    attributes: Vec<KeyValue>,
}

impl SpanProcessor for ResourceSpanAttributes {
    fn set_resource(&mut self, resource: &Resource) {
        self.attributes = ["arize.project.name", "model_id"]
            .into_iter()
            .map(Key::from_static_str)
            .filter_map(|key| resource.get(&key).map(|value| KeyValue::new(key, value)))
            .collect();
    }

    fn on_start(&self, span: &mut SdkSpan, _: &Context) {
        span.set_attributes(self.attributes.iter().cloned());
    }

    fn on_end(&self, _: SpanData) {}

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
        Ok(())
    }
}

const SERVICE: &str = "mcp-gateway";

pub(super) fn scope() -> InstrumentationScope {
    InstrumentationScope::builder(SERVICE)
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url("https://opentelemetry.io/schemas/1.11.0")
        .build()
}

fn settings_pairs(input: &str) -> impl Iterator<Item = (&str, &str)> {
    input.split(',').filter_map(|item| {
        let (key, value) = item.split_once('=')?;
        let key = key.trim();
        (!key.is_empty()).then(|| (key, value.trim()))
    })
}

fn batch_processor(
    exporter: impl SdkSpanExporter + 'static,
) -> Result<BatchSpanProcessor, SettingsError> {
    let queue = parse("OTEL_BSP_MAX_QUEUE_SIZE", 2048)?;
    let batch = parse("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", 512)?;
    let delay = parse("OTEL_BSP_SCHEDULE_DELAY", 5000)?;
    if batch == 0 || queue == 0 || delay == 0 {
        return Err("OpenTelemetry batch sizes and delay must be positive".into());
    }
    Ok(BatchSpanProcessor::builder(exporter)
        .with_batch_config(
            BatchConfigBuilder::default()
                .with_max_queue_size(queue)
                .with_max_export_batch_size(batch)
                .with_scheduled_delay(Duration::from_millis(delay))
                .build(),
        )
        .build())
}

fn validate_collector_url(endpoint: &Url) -> Result<(), SettingsError> {
    if endpoint.host().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || !matches!(endpoint.scheme(), "http" | "https")
    {
        return Err("invalid telemetry collector endpoint".into());
    }
    Ok(())
}

fn collector_http_client(timeout: Duration) -> Result<reqwest::blocking::Client, SettingsError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = std::thread::Builder::new()
        .spawn(move || {
            reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(timeout)
                .build()
        })?
        .join()
        .map_err(|_| "could not create the telemetry HTTP client")??;
    Ok(client)
}

fn collector_service_name(resource: &Resource) -> Cow<'_, str> {
    resource
        .get_ref(&Key::from_static_str("service.name"))
        .map(OtelValue::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(Cow::Borrowed(SERVICE))
}

fn timestamp_micros(time: SystemTime) -> i64 {
    duration_micros(time.duration_since(UNIX_EPOCH).unwrap_or_default())
}

fn duration_micros(duration: Duration) -> i64 {
    i64::try_from((duration.as_nanos() + 500) / 1000).unwrap_or(i64::MAX)
}

fn collector_json_value(value: &OtelValue) -> Value {
    match value {
        OtelValue::Bool(value) => json!(value),
        OtelValue::I64(value) => json!(value),
        OtelValue::F64(value) => json!(value),
        OtelValue::Array(Array::Bool(values)) => json!(values),
        OtelValue::Array(Array::I64(values)) => json!(values),
        OtelValue::Array(Array::F64(values)) => json!(values),
        OtelValue::Array(Array::String(values)) => {
            json!(
                values
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<Vec<_>>()
            )
        }
        _ => json!(value.as_str()),
    }
}

fn otlp_exporter(
    raw_endpoint: &str,
    configured_headers: &str,
    authorization: Option<HeaderValue>,
) -> Result<SpanExporter, SettingsError> {
    let protocol = value("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")?.to_ascii_lowercase();
    let insecure = flag("OTEL_EXPORTER_OTLP_INSECURE")?;
    let raw_endpoint = raw_endpoint.trim();
    let mut endpoint = if !raw_endpoint.contains("://") && protocol == "grpc" {
        let scheme = if insecure == Some(false) {
            "https"
        } else {
            "http"
        };
        Url::parse(&format!("{scheme}://{raw_endpoint}"))?
    } else {
        Url::parse(raw_endpoint)?
    };
    validate_collector_url(&endpoint)?;
    let exporter = SpanExporter::builder();
    if protocol == "grpc" && authorization.is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        if insecure == Some(false) && endpoint.scheme() != "https" {
            return Err("secure OTLP gRPC requires an HTTPS endpoint".into());
        }
        let mut metadata = HeaderMap::new();
        for (name, value) in settings_pairs(configured_headers) {
            let mut value = HeaderValue::from_str(value)?;
            value.set_sensitive(true);
            metadata.insert(HeaderName::from_bytes(name.as_bytes())?, value);
        }
        let mut exporter = exporter
            .with_tonic()
            .with_endpoint(endpoint.as_str())
            .with_metadata(MetadataMap::from_headers(metadata));
        if endpoint.scheme() == "https" {
            exporter = exporter.with_tls_config(ClientTlsConfig::new().with_native_roots());
        }
        return exporter.build().map_err(Into::into);
    }
    if authorization.is_some() {
        langfuse::set_traces_path(&mut endpoint);
    } else if endpoint.port() == Some(4317) {
        let _ = endpoint.set_port(Some(4318));
        endpoint.set_path(&format!(
            "{}/v1/traces",
            endpoint.path().trim_end_matches('/')
        ));
    }
    let timeout = parse(
        "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
        parse("OTEL_EXPORTER_OTLP_TIMEOUT", 10_000)?,
    )?;
    let http = collector_http_client(Duration::from_millis(timeout))?;
    let headers = settings_pairs(configured_headers)
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    let exporter = exporter
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoint.as_str())
        .with_headers(headers);
    let exporter = match authorization {
        Some(authorization) => {
            exporter.with_http_client(langfuse::AuthenticatedClient::new(http, authorization))
        }
        None => exporter.with_http_client(http),
    };
    exporter.build().map_err(Into::into)
}

fn traces_path(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    matches!(
        path,
        "/rpc" | "/mcp" | "/mcp/sse" | "/mcp/message" | "/message" | "/sse" | "/a2a/invoke"
    ) || path.starts_with("/_internal/mcp/")
        || (path.starts_with("/servers/")
            && ["/mcp", "/message", "/sse"].iter().any(|suffix| path.ends_with(suffix)))
        || path.strip_prefix("/a2a/").is_some_and(|path| {
            matches!(path.split_once('/'), Some((id, "invoke" | "jsonrpc")) if !id.is_empty())
        })
}

struct Headers<'a>(&'a HeaderMap);

impl Extractor for Headers<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.to_str().ok()
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(HeaderName::as_str).collect()
    }
}

async fn observe(
    State(telemetry): State<Arc<Telemetry>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let gateway = traces_path(path);
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    let parent = TraceContextPropagator::new().extract(&Headers(request.headers()));
    let baggage = telemetry
        .baggage
        .as_ref()
        .and_then(|policy| policy.read(request.headers()));
    let remote = parent.span().span_context().clone();
    if remote.is_valid() && !remote.is_sampled() {
        return observe_request(
            request,
            next,
            ExportContext::child_context(&remote),
            None,
            baggage,
            &telemetry,
        )
        .await;
    }
    let parent = match &baggage {
        Some(baggage) => parent.with_value(baggage.clone()),
        None => parent,
    };
    let method = request.method().as_str();
    let path = bounded(path, 2000);
    let protocol = match request.version() {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "1.1",
    };
    let mut attributes = vec![
        KeyValue::new("http.request.method", method.to_owned()),
        KeyValue::new("url.path", path.clone()),
        KeyValue::new("network.protocol.version", protocol),
        KeyValue::new("server.address", bounded(&telemetry.host, 255)),
        KeyValue::new("server.port", i64::from(telemetry.port)),
    ];
    if let Some(ConnectInfo(client)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        attributes.push(KeyValue::new("client.address", client.ip().to_string()));
        attributes.push(KeyValue::new("client.port", i64::from(client.port())));
    }
    if let Some(query) = request.uri().query() {
        attributes.push(KeyValue::new(
            "url.query",
            bounded(&telemetry.redaction.query(query), 2000),
        ));
    }
    if let Some(correlation_id) = CorrelationId::current()
        && let Some(value) = correlation_id.as_str()
    {
        attributes.push(KeyValue::new("correlation_id", bounded(value, 64)));
    }
    let gateway_span = gateway.then(|| {
        let mut attributes = attributes.clone();
        attributes.push(KeyValue::new("http.route", path.clone()));
        if let Some(user_agent) = request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
        {
            attributes.push(KeyValue::new(
                "user_agent.original",
                bounded(user_agent, 500),
            ));
        }
        telemetry
            .tracer
            .span_builder(bounded(&format!("{method} {path}"), 255))
            .with_kind(SpanKind::Server)
            .with_attributes(attributes)
            .start_with_context(&telemetry.tracer, &parent)
    });
    let framework_span = {
        let name = if let Some(route) = route {
            attributes.push(KeyValue::new("http.route", bounded(route, 2000)));
            bounded(&format!("{method} {route}"), 255)
        } else {
            bounded(method, 255)
        };
        attributes.push(KeyValue::new(
            "url.scheme",
            crate::http_boundary::public_scheme(request.headers(), request.uri()),
        ));
        let framework_parent = match &gateway_span {
            Some(span) if !remote.is_valid() => {
                parent.with_remote_span_context(span.span_context().clone())
            }
            _ => parent.clone(),
        };
        telemetry
            .framework_tracer
            .span_builder(name)
            .with_kind(SpanKind::Server)
            .with_attributes(attributes)
            .start_with_context(&telemetry.framework_tracer, &framework_parent)
    };
    let root = gateway_span.as_ref().unwrap_or(&framework_span);
    let request_trace = Box::new(framework::RequestTrace {
        root: ExportContext::from_span(framework_span.span_context()),
        dispatch_started: SystemTime::now(),
        handler: None,
    });
    let response = observe_request(
        request,
        next,
        ExportContext::from_span(root.span_context()),
        Some(request_trace),
        baggage,
        &telemetry,
    )
    .await;
    let mut spans: Vec<_> = [
        (gateway_span, Status::Ok),
        (Some(framework_span), Status::Unset),
    ]
    .into_iter()
    .filter_map(|(span, success)| {
        let mut span = span.filter(Span::is_recording)?;
        let code = response.status();
        span.set_attribute(KeyValue::new(
            "http.response.status_code",
            i64::from(code.as_u16()),
        ));
        let status = if code.is_server_error() {
            Status::error("Gateway returned a server error")
        } else {
            success
        };
        Some((span, status))
    })
    .collect();
    if spans.is_empty() {
        return response;
    }
    let (parts, body) = response.into_parts();
    if body.is_end_stream() {
        finish_spans(&mut spans, false);
        return Response::from_parts(parts, body);
    }
    Response::from_parts(parts, Body::new(TracedBody { body, spans }))
}

async fn observe_request(
    mut request: Request,
    next: Next,
    exported: ExportContext,
    framework: Option<Box<framework::RequestTrace>>,
    baggage: Option<Arc<baggage::Baggage>>,
    telemetry: &Telemetry,
) -> Response {
    let context = TraceContext {
        exported: Some(exported),
        framework,
        baggage,
        ..telemetry.trace_context()
    };
    request.extensions_mut().insert(context.clone());
    with_trace(Some(context), next.run(request)).await
}

struct TracedBody {
    body: Body,
    spans: Vec<(SdkSpan, Status)>,
}

fn finish_spans(spans: &mut Vec<(SdkSpan, Status)>, failed: bool) {
    for (mut span, status) in spans.drain(..) {
        span.set_status(if failed {
            Status::error("Response body failed")
        } else {
            status
        });
        span.end();
    }
}

impl Drop for TracedBody {
    fn drop(&mut self) {
        finish_spans(&mut self.spans, false);
    }
}

impl HttpBody for TracedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let result = Pin::new(&mut self.body).poll_frame(cx);
        let failed = matches!(result, Poll::Ready(Some(Err(_))));
        if failed || self.body.is_end_stream() || matches!(result, Poll::Ready(None)) {
            finish_spans(&mut self.spans, failed);
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct ExportContext {
    pub(super) traceparent: String,
    tracestate: String,
}

impl ExportContext {
    pub(super) fn from_span(span: &SpanContext) -> Self {
        Self {
            traceparent: format!(
                "00-{}-{}-{:02x}",
                span.trace_id(),
                span.span_id(),
                span.trace_flags().to_u8()
            ),
            tracestate: span.trace_state().header(),
        }
    }

    fn child_context(parent: &SpanContext) -> Self {
        Self::from_span(&SpanContext::new(
            parent.trace_id(),
            SpanId::from_bytes((Uuid::new_v4().as_u128() as u64).to_be_bytes()),
            parent.trace_flags(),
            false,
            TraceState::default(),
        ))
    }

    pub(super) fn start_operation(&self, name: &'static str, attributes: &Value) -> ExportSpan {
        self.start_span(name, SpanKind::Internal, exported_attributes(attributes))
    }

    pub(super) fn start_span(
        &self,
        name: impl Into<Cow<'static, str>>,
        kind: SpanKind,
        attributes: impl IntoIterator<Item = KeyValue>,
    ) -> ExportSpan {
        let context = TraceContextPropagator::new().extract(self);
        let span = context.span();
        let parent = span.span_context();
        if !parent.is_sampled() {
            return ExportSpan::Unsampled(Self::child_context(parent));
        }
        let tracer = global::tracer_with_scope(scope());
        ExportSpan::Recording(
            tracer
                .span_builder(name)
                .with_kind(kind)
                .with_attributes(attributes)
                .start_with_context(&tracer, &context),
        )
    }

    pub(super) fn inject(&self, headers: &mut HeaderMap) {
        for name in ["traceparent", "tracestate"] {
            headers.remove(name);
        }
        if let Ok(value) = HeaderValue::from_str(&self.traceparent) {
            headers.insert("traceparent", value);
        }
        if !self.tracestate.is_empty()
            && let Ok(value) = HeaderValue::from_str(&self.tracestate)
        {
            headers.insert("tracestate", value);
        }
    }
}

pub(super) enum ExportSpan {
    Recording(BoxedSpan),
    Unsampled(ExportContext),
}

impl ExportSpan {
    pub(super) fn root(name: &'static str, attributes: impl IntoIterator<Item = KeyValue>) -> Self {
        let tracer = global::tracer_with_scope(scope());
        Self::Recording(
            tracer
                .span_builder(name)
                .with_attributes(attributes)
                .start_with_context(&tracer, &Context::new()),
        )
    }

    pub(super) fn context(&self) -> ExportContext {
        match self {
            Self::Recording(span) => ExportContext::from_span(span.span_context()),
            Self::Unsampled(context) => context.clone(),
        }
    }
}

impl Extractor for ExportContext {
    fn get(&self, key: &str) -> Option<&str> {
        match key {
            "traceparent" => Some(&self.traceparent),
            "tracestate" => Some(&self.tracestate),
            _ => None,
        }
    }

    fn keys(&self) -> Vec<&str> {
        vec!["traceparent", "tracestate"]
    }
}

pub(super) fn exported_attributes(attributes: &Value) -> impl Iterator<Item = KeyValue> {
    attributes.as_object().into_iter().flat_map(|fields| {
        fields.iter().filter_map(|(key, value)| {
            // The database keeps identity metadata in its administrator-only trace store.
            if matches!(key.as_str(), "user" | "user.email" | "tenant_id") {
                return None;
            }
            let value = match value {
                Value::String(text) => opentelemetry::Value::from(bounded(text, 2000)),
                Value::Bool(flag) => opentelemetry::Value::from(*flag),
                Value::Number(number) => number.as_i64()?.into(),
                _ => return None,
            };
            Some(KeyValue::new(key.clone(), value))
        })
    })
}
