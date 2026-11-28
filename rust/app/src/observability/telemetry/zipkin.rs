// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use opentelemetry::{
    Array, Key, Value,
    trace::{Event, SpanId, SpanKind, Status},
};
use opentelemetry_sdk::{
    Resource,
    error::{OTelSdkError, OTelSdkResult},
    trace::{SpanData, SpanExporter},
};
use serde::Serialize;
use serde_json::json;
use url::Url;

use super::{SERVICE, SettingsError, collector_http_client, validate_collector_url};
use crate::config::{parse, value};

const DEFAULT_ENDPOINT: &str = "http://localhost:9411/api/v2/spans";

pub(super) struct Exporter {
    endpoint: Url,
    timeout: Duration,
    client: reqwest::blocking::Client,
    resource: Resource,
}

impl fmt::Debug for Exporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZipkinExporter")
            .finish_non_exhaustive()
    }
}

impl Exporter {
    pub(super) fn from_env() -> Result<Self, SettingsError> {
        let configured = value("OTEL_EXPORTER_ZIPKIN_ENDPOINT", DEFAULT_ENDPOINT)?;
        let endpoint = Url::parse(if configured.trim().is_empty() {
            DEFAULT_ENDPOINT
        } else {
            configured.trim()
        })?;
        validate_collector_url(&endpoint)?;
        let timeout = Duration::from_secs(parse("OTEL_EXPORTER_ZIPKIN_TIMEOUT", 10)?);
        if timeout.is_zero() {
            return Err("OTEL_EXPORTER_ZIPKIN_TIMEOUT must be positive".into());
        }
        Ok(Self {
            endpoint,
            timeout,
            client: collector_http_client(timeout)?,
            resource: Resource::builder_empty().build(),
        })
    }
}

impl SpanExporter for Exporter {
    fn set_resource(&mut self, resource: &Resource) {
        self.resource = resource.clone();
    }

    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        if batch.is_empty() {
            return Ok(());
        }
        let service = self
            .resource
            .get_ref(&Key::from_static_str("service.name"))
            .map(Value::as_str)
            .filter(|name| !name.is_empty());
        let spans: Vec<_> = batch
            .iter()
            .map(|span| {
                ZipkinSpan::new(span, &self.resource, service.as_deref().unwrap_or(SERVICE))
            })
            .collect();
        let body = serde_json::to_vec(&spans)
            .map_err(|_| OTelSdkError::InternalFailure("Could not encode Zipkin spans".into()))?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    OTelSdkError::Timeout(self.timeout)
                } else {
                    OTelSdkError::InternalFailure("Zipkin collector request failed".into())
                }
            })?;
        match response.status().as_u16() {
            200 | 202 => Ok(()),
            status => Err(OTelSdkError::InternalFailure(format!(
                "Zipkin collector returned HTTP {status}"
            ))),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ZipkinSpan<'a> {
    trace_id: String,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'static str>,
    timestamp: i64,
    duration: i64,
    local_endpoint: Endpoint<'a>,
    tags: BTreeMap<&'a str, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    annotations: Vec<Annotation>,
}

impl<'a> ZipkinSpan<'a> {
    fn new(span: &'a SpanData, resource: &'a Resource, service_name: &'a str) -> Self {
        let mut tags: BTreeMap<_, _> = span
            .attributes
            .iter()
            .map(|attribute| (&attribute.key, &attribute.value))
            .chain(resource.iter())
            .map(|(key, value)| (key.as_str(), tag_value(value)))
            .collect();
        let scope = &span.instrumentation_scope;
        for key in ["otel.library.name", "otel.scope.name"] {
            tags.insert(key, scope.name().to_owned());
        }
        if let Some(version) = scope.version() {
            for key in ["otel.library.version", "otel.scope.version"] {
                tags.insert(key, version.to_owned());
            }
        }
        tags.remove("error");
        tags.remove("otel.status_code");
        match &span.status {
            Status::Unset => {}
            Status::Ok => {
                tags.insert("otel.status_code", "OK".into());
            }
            Status::Error { description } => {
                tags.insert("otel.status_code", "ERROR".into());
                tags.insert("error", description.to_string());
            }
        }
        for (key, count) in [
            (
                "otel.dropped_attributes_count",
                span.dropped_attributes_count,
            ),
            ("otel.dropped_events_count", span.events.dropped_count),
            ("otel.dropped_links_count", span.links.dropped_count),
        ] {
            if count != 0 {
                tags.insert(key, count.to_string());
            }
        }

        Self {
            trace_id: span.span_context.trace_id().to_string(),
            id: span.span_context.span_id().to_string(),
            parent_id: (span.parent_span_id != SpanId::INVALID)
                .then(|| span.parent_span_id.to_string()),
            name: span.name.as_ref(),
            kind: match span.span_kind {
                SpanKind::Client => Some("CLIENT"),
                SpanKind::Server => Some("SERVER"),
                SpanKind::Producer => Some("PRODUCER"),
                SpanKind::Consumer => Some("CONSUMER"),
                SpanKind::Internal => None,
            },
            timestamp: timestamp(span.start_time),
            duration: micros(
                span.end_time
                    .duration_since(span.start_time)
                    .unwrap_or_default(),
            )
            .max(1),
            local_endpoint: Endpoint { service_name },
            tags,
            annotations: span.events.iter().map(Annotation::from).collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Endpoint<'a> {
    service_name: &'a str,
}

#[derive(Serialize)]
struct Annotation {
    timestamp: i64,
    value: String,
}

impl From<&Event> for Annotation {
    fn from(event: &Event) -> Self {
        let attributes: BTreeMap<_, _> = event
            .attributes
            .iter()
            .map(|attribute| (attribute.key.as_str(), json_value(&attribute.value)))
            .collect();
        Self {
            timestamp: timestamp(event.timestamp),
            value: json!({(event.name.as_ref()): attributes}).to_string(),
        }
    }
}

fn timestamp(time: SystemTime) -> i64 {
    micros(time.duration_since(UNIX_EPOCH).unwrap_or_default())
}

fn micros(duration: Duration) -> i64 {
    i64::try_from((duration.as_nanos() + 500) / 1000).unwrap_or(i64::MAX)
}

fn tag_value(value: &Value) -> String {
    match value {
        Value::Array(Array::Bool(values)) => string_list(values),
        Value::Array(Array::I64(values)) => string_list(values),
        Value::Array(Array::F64(values)) => string_list(values),
        Value::Array(Array::String(values)) => string_list(values),
        _ => value.as_str().into_owned(),
    }
}

fn string_list(values: &[impl ToString]) -> String {
    json!(values.iter().map(ToString::to_string).collect::<Vec<_>>()).to_string()
}

fn json_value(value: &Value) -> serde_json::Value {
    match value {
        Value::Bool(value) => json!(value),
        Value::I64(value) => json!(value),
        Value::F64(value) => json!(value),
        Value::Array(Array::Bool(values)) => json!(values),
        Value::Array(Array::I64(values)) => json!(values),
        Value::Array(Array::F64(values)) => json!(values),
        Value::Array(Array::String(values)) => json!(
            values
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>()
        ),
        _ => json!(value.as_str()),
    }
}
