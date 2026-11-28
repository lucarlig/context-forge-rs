// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

use opentelemetry::{
    KeyValue,
    trace::{Span, SpanKind, Status},
};
use reqwest::{Client, Method, Request, Response, Url, Version};
use serde::{Deserialize, Serialize};

use super::{ExportSpan, SettingsError};
use crate::{
    config::{flag, value},
    observability::{bounded, current_trace, with_trace},
};

#[derive(Clone, Copy, Deserialize, Serialize)]
pub(crate) enum HttpSemantics {
    Legacy,
    Standard,
    Both,
}

impl HttpSemantics {
    pub(super) fn from_env() -> Result<Option<Self>, SettingsError> {
        if !flag("OTEL_HTTPX_INSTRUMENTATION_ENABLED")?.unwrap_or(false) {
            return Ok(None);
        }
        let modes = value("OTEL_SEMCONV_STABILITY_OPT_IN", "")?;
        let one_of = |name| modes.split(',').any(|mode| mode.trim() == name);
        Ok(Some(if one_of("http/dup") {
            Self::Both
        } else if one_of("http") {
            Self::Standard
        } else {
            Self::Legacy
        }))
    }

    fn legacy(self) -> bool {
        matches!(self, Self::Legacy | Self::Both)
    }

    fn standard(self) -> bool {
        matches!(self, Self::Standard | Self::Both)
    }
}

pub(crate) struct HttpClientSpan(Option<Box<(ExportSpan, HttpSemantics)>>);

impl HttpClientSpan {
    pub(crate) fn start(request: &mut Request) -> Self {
        let Some(trace) = current_trace() else {
            return Self(None);
        };
        let Some(parent) = trace.exported else {
            return Self(None);
        };
        if let Some(mode) = trace.http_clients {
            let name = http_method(request.method());
            let span = parent.start_span(name, SpanKind::Client, request_attributes(request, mode));
            if !signature_owns_trace_headers(request.url()) {
                span.context().inject(request.headers_mut());
            }
            Self(Some(Box::new((span, mode))))
        } else {
            if trace.mcp_call && !signature_owns_trace_headers(request.url()) {
                parent.inject(request.headers_mut());
            }
            Self(None)
        }
    }

    pub(crate) async fn execute(
        mut self,
        client: &Client,
        request: Request,
    ) -> Result<Response, reqwest::Error> {
        let result = client.execute(request).await;
        if let Some(state) = self.0.take()
            && let (ExportSpan::Recording(mut span), mode) = *state
        {
            match &result {
                Ok(response) => record_response(&mut span, response, mode),
                Err(error) => {
                    span.set_status(Status::error("Upstream HTTP request failed"));
                    if mode.standard() {
                        let category = if error.is_timeout() {
                            "timeout"
                        } else if error.is_connect() {
                            "connect"
                        } else {
                            "transport"
                        };
                        span.set_attribute(KeyValue::new("error.type", category));
                    }
                }
            }
            span.end();
        }
        result
    }
}

impl Drop for HttpClientSpan {
    fn drop(&mut self) {
        if let Some(state) = self.0.take()
            && let (ExportSpan::Recording(mut span), mode) = *state
        {
            span.set_status(Status::error("Upstream HTTP request interrupted"));
            if mode.standard() {
                span.set_attribute(KeyValue::new("error.type", "interrupted"));
            }
            span.end();
        }
    }
}

pub(crate) async fn execute(
    client: &Client,
    mut request: Request,
) -> Result<Response, reqwest::Error> {
    HttpClientSpan::start(&mut request)
        .execute(client, request)
        .await
}

pub(crate) async fn mcp_call<T, E>(
    gateway_id: &str,
    endpoint: &str,
    transport: &'static str,
    tool: &str,
    operation: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let Some(mut context) = current_trace() else {
        return operation.await;
    };
    let Some(parent) = context.exported.take() else {
        return operation.await;
    };
    let mut attributes = vec![
        KeyValue::new("mcp.tool.name", bounded(tool, 255)),
        KeyValue::new("contextforge.gateway_id", bounded(gateway_id, 36)),
        KeyValue::new("contextforge.runtime", "rust"),
        KeyValue::new("contextforge.transport", transport.to_ascii_lowercase()),
        KeyValue::new("network.protocol.name", "mcp"),
    ];
    if let Ok(url) = Url::parse(endpoint) {
        attributes.push(KeyValue::new("url.path", bounded(url.path(), 2000)));
        attributes.push(KeyValue::new("url.full", safe_url(&url)));
        if let Some(host) = url.host_str() {
            attributes.push(KeyValue::new("server.address", bounded(host, 255)));
        }
        if let Some(port) = url.port() {
            attributes.push(KeyValue::new("server.port", i64::from(port)));
        }
    }
    let span = parent.start_span("mcp.client.call", SpanKind::Internal, attributes);
    context.exported = Some(span.context());
    context.mcp_call = true;
    let result = with_trace(Some(context), operation).await;
    if let ExportSpan::Recording(mut span) = span {
        span.set_status(if result.is_ok() {
            Status::Ok
        } else {
            Status::error("Upstream MCP call failed")
        });
        span.end();
    }
    result
}

fn signature_owns_trace_headers(url: &Url) -> bool {
    url.query_pairs().any(|(key, value)| {
        key.eq_ignore_ascii_case("x-amz-signedheaders")
            && value.split(';').any(|name| {
                ["traceparent", "tracestate", "baggage"]
                    .iter()
                    .any(|header| name.eq_ignore_ascii_case(header))
            })
    })
}

fn safe_url(url: &Url) -> String {
    let mut url = url.clone();
    url.set_query(None);
    url.set_fragment(None);
    let _ = url.set_password(None);
    let _ = url.set_username("");
    bounded(url.as_str(), 2000)
}

fn http_method(method: &Method) -> &'static str {
    match *method {
        Method::CONNECT => "CONNECT",
        Method::DELETE => "DELETE",
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::PATCH => "PATCH",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::TRACE => "TRACE",
        _ => "HTTP",
    }
}

fn request_attributes(request: &Request, mode: HttpSemantics) -> Vec<KeyValue> {
    let method = request.method().as_str();
    let url = safe_url(request.url());
    let mut attrs = Vec::new();
    if mode.legacy() {
        attrs.push(KeyValue::new("http.method", bounded(method, 64)));
        attrs.push(KeyValue::new("http.url", url.clone()));
    }
    if mode.standard() {
        let kind = http_method(request.method());
        attrs.push(KeyValue::new("url.full", url));
        attrs.push(KeyValue::new(
            "http.request.method",
            if kind == "HTTP" { "_OTHER" } else { kind },
        ));
        if kind == "HTTP" {
            attrs.push(KeyValue::new(
                "http.request.method_original",
                bounded(method, 64),
            ));
        }
        if let Some(host) = request.url().host_str() {
            attrs.push(KeyValue::new("server.address", bounded(host, 255)));
        }
        if let Some(port) = request.url().port_or_known_default() {
            attrs.push(KeyValue::new("server.port", i64::from(port)));
        }
    }
    attrs
}

fn record_response(span: &mut impl Span, response: &Response, mode: HttpSemantics) {
    let code = i64::from(response.status().as_u16());
    let failed = response.status().is_client_error() || response.status().is_server_error();
    if mode.legacy() {
        span.set_attribute(KeyValue::new("http.status_code", code));
    }
    if mode.standard() {
        span.set_attribute(KeyValue::new("http.response.status_code", code));
        let protocol = match response.version() {
            Version::HTTP_09 => "0.9",
            Version::HTTP_10 => "1.0",
            Version::HTTP_2 => "2",
            Version::HTTP_3 => "3",
            _ => "1.1",
        };
        span.set_attribute(KeyValue::new("network.protocol.version", protocol));
        if let Some(peer) = response.remote_addr() {
            span.set_attribute(KeyValue::new("network.peer.address", peer.ip().to_string()));
            span.set_attribute(KeyValue::new("network.peer.port", i64::from(peer.port())));
        }
        if failed {
            span.set_attribute(KeyValue::new("error.type", code.to_string()));
        }
    }
    if failed {
        span.set_status(Status::error("Upstream HTTP error"));
    }
}
