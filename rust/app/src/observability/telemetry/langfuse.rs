// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, sync::OnceLock};

use axum::http::{HeaderValue, header};
use base64::{Engine as _, prelude::BASE64_STANDARD};
use opentelemetry::{Array, KeyValue, trace::Span};
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use serde::Serialize;
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use super::{SettingsError, settings_pairs};
use crate::{
    access::Principal,
    auth::TeamVisibility,
    config::{flag, parse, value},
    observability::{QueryRedaction, bounded},
};

mod payload;

const INGESTION_PATH: &str = "/api/public/otel";
const INVALID_AUTHORIZATION: &str = "Langfuse OTLP endpoint requires valid Basic Authorization from OTEL_EXPORTER_OTLP_HEADERS, LANGFUSE_OTEL_AUTH, or the Langfuse project keys";

pub(super) fn configured_endpoint() -> Result<String, SettingsError> {
    let endpoint = value("LANGFUSE_OTEL_ENDPOINT", "")?;
    if endpoint.trim().is_empty() {
        value("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    } else {
        Ok(endpoint)
    }
}

pub(super) fn matches_endpoint(endpoint: &str) -> bool {
    Url::parse(endpoint.trim()).is_ok_and(|url| {
        let path = url.path().trim_end_matches('/');
        path.ends_with(INGESTION_PATH) || path.contains("/api/public/otel/")
    })
}

pub(super) fn set_traces_path(endpoint: &mut Url) {
    let path = endpoint.path().trim_end_matches('/');
    if path.ends_with(INGESTION_PATH) {
        endpoint.set_path(&format!("{path}/v1/traces"));
    }
}

pub(super) fn authorization(configured_headers: &str) -> Result<HeaderValue, SettingsError> {
    let authorization = settings_pairs(configured_headers)
        .filter(|(name, _)| name.eq_ignore_ascii_case(header::AUTHORIZATION.as_str()))
        .map(|(_, value)| value)
        .last()
        .filter(|value| !value.is_empty());
    if let Some(authorization) = authorization {
        let mut fields = authorization.split_ascii_whitespace();
        let scheme = fields.next().ok_or(INVALID_AUTHORIZATION)?;
        let encoded = fields.next().ok_or(INVALID_AUTHORIZATION)?;
        if !scheme.eq_ignore_ascii_case("basic") || fields.next().is_some() {
            return Err(INVALID_AUTHORIZATION.into());
        }
        return basic_header(encoded);
    }

    let encoded = Zeroizing::new(value("LANGFUSE_OTEL_AUTH", "")?);
    if !encoded.trim().is_empty() {
        return basic_header(encoded.trim());
    }
    let public_key = Zeroizing::new(value("LANGFUSE_PUBLIC_KEY", "")?);
    let secret_key = Zeroizing::new(value("LANGFUSE_SECRET_KEY", "")?);
    if public_key.trim().is_empty()
        || public_key.trim().contains(':')
        || secret_key.trim().is_empty()
    {
        return Err(INVALID_AUTHORIZATION.into());
    }
    let credentials = Zeroizing::new(format!("{}:{}", public_key.trim(), secret_key.trim()));
    let encoded = Zeroizing::new(BASE64_STANDARD.encode(credentials.as_bytes()));
    basic_header(&encoded)
}

fn basic_header(encoded: &str) -> Result<HeaderValue, SettingsError> {
    let credentials = Zeroizing::new(
        BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| INVALID_AUTHORIZATION)?,
    );
    let valid = std::str::from_utf8(&credentials)
        .ok()
        .and_then(|text| text.split_once(':'))
        .is_some_and(|(public_key, secret_key)| !public_key.is_empty() && !secret_key.is_empty());
    if !valid {
        return Err(INVALID_AUTHORIZATION.into());
    }
    let authorization = Zeroizing::new(format!("Basic {encoded}"));
    let mut header = HeaderValue::from_str(&authorization).map_err(|_| INVALID_AUTHORIZATION)?;
    header.set_sensitive(true);
    Ok(header)
}

#[derive(Debug)]
pub(super) struct AuthenticatedClient {
    client: reqwest::blocking::Client,
    authorization: HeaderValue,
}

impl AuthenticatedClient {
    pub(super) fn new(client: reqwest::blocking::Client, authorization: HeaderValue) -> Self {
        Self {
            client,
            authorization,
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for AuthenticatedClient {
    async fn send_bytes(&self, mut request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        // The SDK also applies signal-specific environment headers before dispatch.
        request
            .headers_mut()
            .insert(header::AUTHORIZATION, self.authorization.clone());
        request
            .headers_mut()
            .entry("x-langfuse-ingestion-version")
            .or_insert(HeaderValue::from_static("4"));
        self.client.send_bytes(request).await
    }
}

static POLICY: OnceLock<OperationPolicy> = OnceLock::new();

pub(super) fn configure_policy(
    langfuse: bool,
    environment: String,
    redaction: QueryRedaction,
) -> Result<(), SettingsError> {
    let labels = flag("OTEL_EMIT_LANGFUSE_ATTRIBUTES")?.unwrap_or(langfuse);
    let identity = flag("OTEL_CAPTURE_IDENTITY_ATTRIBUTES")?.unwrap_or(labels);
    if labels || identity {
        let capture = |setting| -> Result<HashSet<String>, SettingsError> {
            Ok(value(setting, "")?
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect())
        };
        let maximum = parse("OTEL_MAX_TRACE_PAYLOAD_SIZE", 32_768)?;
        if maximum < 256 {
            return Err("OTEL_MAX_TRACE_PAYLOAD_SIZE must be at least 256".into());
        }
        let _ = POLICY.set(OperationPolicy {
            labels,
            identity,
            environment: bounded(&environment, 255),
            inputs: capture("OTEL_CAPTURE_INPUT_SPANS")?,
            outputs: capture("OTEL_CAPTURE_OUTPUT_SPANS")?,
            maximum,
            redaction,
        });
    }
    Ok(())
}

pub(in crate::observability) fn policy() -> Option<&'static OperationPolicy> {
    POLICY.get()
}

pub(in crate::observability) struct OperationPolicy {
    labels: bool,
    identity: bool,
    environment: String,
    inputs: HashSet<String>,
    outputs: HashSet<String>,
    maximum: usize,
    redaction: QueryRedaction,
}

impl OperationPolicy {
    pub(in crate::observability) fn label(
        &self,
        name: &'static str,
        metadata: &Value,
        span: &mut impl Span,
    ) {
        if !self.labels {
            return;
        }
        let display = match name {
            "tool.invoke" => Some(("Tool", "tool.name")),
            "prompt.render" => Some(("Prompt", "prompt.id")),
            "resource.read" => Some(("Resource", "resource.uri")),
            "a2a.invoke" => Some(("A2A", "a2a.agent.name")),
            _ => None,
        };
        let label = display
            .and_then(|(prefix, key)| Some(format!("{prefix}: {}", metadata[key].as_str()?)))
            .unwrap_or_else(|| name.to_owned());
        span.set_attributes([
            KeyValue::new("langfuse.environment", self.environment.clone()),
            KeyValue::new(
                "langfuse.trace.name",
                bounded(&self.redaction.text(&label), 512),
            ),
            KeyValue::new("langfuse.observation.level", "DEFAULT"),
        ]);
        self.tag(span, None, None);
    }

    pub(in crate::observability) fn identify(&self, principal: &Principal, span: &mut impl Span) {
        span.set_attribute(KeyValue::new("auth.method", "jwt"));
        let (scope, primary) = match &principal.visibility {
            TeamVisibility::Admin => ("admin".to_owned(), Some("admin")),
            TeamVisibility::Public => ("public".to_owned(), Some("public")),
            TeamVisibility::Teams(teams) => (teams.join(","), teams.first().map(String::as_str)),
        };
        if self.identity {
            let email = bounded(&principal.email, 255);
            span.set_attributes([
                KeyValue::new("user.email", email.clone()),
                KeyValue::new("user.is_admin", principal.is_admin()),
                KeyValue::new("team.scope", bounded(&scope, 512)),
            ]);
            if self.labels {
                span.set_attribute(KeyValue::new("langfuse.user.id", email));
            }
        }
        if self.labels {
            self.tag(span, Some("jwt"), primary.filter(|_| self.identity));
        }
    }

    fn tag(&self, span: &mut impl Span, auth: Option<&str>, team: Option<&str>) {
        let mut tags = Vec::new();
        if let Some(team) = team {
            tags.push(format!("team:{}", bounded(team, 255)).into());
        }
        if let Some(method) = auth {
            tags.push(format!("auth:{method}").into());
        }
        if !self.environment.is_empty() {
            tags.push(format!("env:{}", self.environment).into());
        }
        if !tags.is_empty() {
            span.set_attribute(KeyValue::new(
                "langfuse.trace.tags",
                opentelemetry::Value::Array(Array::String(tags)),
            ));
        }
    }

    pub(in crate::observability) fn failure(&self, span: &mut impl Span) {
        if self.labels {
            span.set_attribute(KeyValue::new("langfuse.observation.level", "ERROR"));
        }
    }

    pub(in crate::observability) fn capture<T: Serialize + ?Sized>(
        &self,
        name: &str,
        input: bool,
        value: &T,
        span: &mut impl Span,
    ) {
        let allowed = if input { &self.inputs } else { &self.outputs };
        if self.labels
            && allowed.contains(name)
            && let Some(payload) = self.redaction.serialize_payload(value, self.maximum)
        {
            let key = if input {
                "langfuse.observation.input"
            } else {
                "langfuse.observation.output"
            };
            span.set_attribute(KeyValue::new(key, payload));
        }
    }
}
