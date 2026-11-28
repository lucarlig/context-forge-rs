// SPDX-License-Identifier: Apache-2.0

use opentelemetry::{KeyValue, trace::Span as _};
use serde_json::{Value, json};
use url::Url;

use super::{TraceContext, bounded, current_trace, safe_upstream_url, scoped::ScopedSpan};
use crate::upstream::{UpstreamEndpoint, UpstreamError};

pub(super) const SESSION_ATTRIBUTE: &str = "gateway.upstream.session_id";

pub(crate) struct McpCallSpan {
    span: ScopedSpan,
    attributes: Value,
    session_hash: Option<String>,
}

impl McpCallSpan {
    pub(crate) fn start(
        gateway_id: &str,
        tool_id: Option<&str>,
        tool: &str,
        endpoint: UpstreamEndpoint<'_>,
    ) -> Option<Self> {
        current_trace()?.exported?;
        let url = Url::parse(endpoint.url).ok();
        let attributes = json!({
            "mcp.tool.name": bounded(tool, 255),
            "contextforge.tool.id": tool_id.map(|id| bounded(id, 36)),
            "contextforge.gateway_id": bounded(gateway_id, 36),
            "contextforge.runtime": "rust",
            "contextforge.transport": endpoint.transport.name().to_ascii_lowercase(),
            "network.protocol.name": "mcp",
            "url.path": url.as_ref().map(|url| bounded(url.path(), 2000)),
            "url.full": url.as_ref().map(safe_upstream_url),
            "server.address": url.as_ref().and_then(Url::host_str).map(|host| bounded(host, 255)),
            "server.port": url.as_ref().and_then(Url::port),
        });
        let span = ScopedSpan::start("mcp.client.call", || attributes.clone());
        Some(Self {
            span,
            attributes,
            session_hash: None,
        })
    }

    pub(crate) fn context(&self) -> Option<TraceContext> {
        let mut context = self.span.context()?;
        context.mcp_call = context.exported.clone();
        Some(context)
    }

    pub(crate) fn set_session(&mut self, hash: Option<String>) {
        self.session_hash = hash;
        add_session_attribute(&mut self.span, self.session_hash.as_deref());
    }

    pub(crate) fn request(&self) -> ScopedSpan {
        let mut span = ScopedSpan::start("mcp.client.request", || self.attributes.clone());
        add_session_attribute(&mut span, self.session_hash.as_deref());
        span
    }

    pub(crate) fn reply(&self, mut request: ScopedSpan, result: &Result<Value, UpstreamError>) {
        let failure = call_failure(result);
        let reply = result
            .as_ref()
            .ok()
            .filter(|value| value["resultType"] != "input_required");
        if let Some(span) = request.recording()
            && reply.is_some()
        {
            span.set_attribute(KeyValue::new(
                "upstream.response.success",
                failure.is_none(),
            ));
        }
        request.finish(failure);
        if reply.is_some() {
            let mut span = ScopedSpan::start("mcp.client.response", || {
                let mut attributes = self.attributes.clone();
                attributes["upstream.response.success"] = failure.is_none().into();
                attributes
            });
            add_session_attribute(&mut span, self.session_hash.as_deref());
            span.finish(failure);
        }
    }

    pub(crate) fn finish(mut self, result: &Result<Value, UpstreamError>) -> Option<String> {
        self.span.finish(call_failure(result));
        self.session_hash
    }
}

pub(crate) fn add_session_attribute(span: &mut ScopedSpan, hash: Option<&str>) {
    if let Some(hash) = hash
        && let Some(span) = span.recording()
    {
        span.set_attribute(KeyValue::new(SESSION_ATTRIBUTE, hash.to_owned()));
    }
}

fn call_failure(result: &Result<Value, UpstreamError>) -> Option<&'static str> {
    match result {
        Ok(value) if value["resultType"] == "input_required" => {
            Some("Upstream tool requires input")
        }
        Ok(value) if value["isError"] == true || value["is_error"] == true => {
            Some("Upstream tool returned an error")
        }
        Err(UpstreamError::Cancelled) => Some("Upstream MCP call cancelled"),
        Err(_) => Some("Upstream MCP call failed"),
        Ok(_) => None,
    }
}
