// SPDX-License-Identifier: Apache-2.0

use std::{fmt, time::Duration};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use opentelemetry::{
    KeyValue, Value,
    trace::{Event, Link, SpanContext, SpanKind, Status},
};
use opentelemetry_sdk::{
    Resource,
    error::{OTelSdkError, OTelSdkResult},
    trace::{SpanData, SpanExporter},
};
use reqwest::header::{self, HeaderValue};
use thrift::{
    ProtocolErrorKind, new_protocol_error,
    protocol::{
        TBinaryOutputProtocol, TFieldIdentifier, TListIdentifier, TOutputProtocol,
        TStructIdentifier, TType,
    },
};
use url::Url;
use zeroize::Zeroizing;

use super::{
    SettingsError, collector_http_client, collector_json_value, collector_service_name,
    duration_micros, timestamp_micros, validate_collector_url,
};
use crate::{
    config::{parse, value},
    environment,
};

const DEFAULT_ENDPOINT: &str = "http://localhost:14268/api/traces";

pub(super) struct Exporter {
    endpoint: Url,
    timeout: Duration,
    authorization: Option<HeaderValue>,
    client: reqwest::blocking::Client,
    resource: Resource,
}

impl fmt::Debug for Exporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JaegerExporter")
            .finish_non_exhaustive()
    }
}

impl Exporter {
    pub(super) fn from_env() -> Result<Self, SettingsError> {
        let configured = value("OTEL_EXPORTER_JAEGER_ENDPOINT", DEFAULT_ENDPOINT)?;
        let endpoint = Url::parse(if configured.trim().is_empty() {
            DEFAULT_ENDPOINT
        } else {
            configured.trim()
        })?;
        validate_collector_url(&endpoint)?;
        let timeout = Duration::from_secs(parse("OTEL_EXPORTER_JAEGER_TIMEOUT", 10)?);
        if timeout.is_zero() {
            return Err("OTEL_EXPORTER_JAEGER_TIMEOUT must be positive".into());
        }
        Ok(Self {
            endpoint,
            timeout,
            authorization: collector_authorization()?,
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
        let body = encode_batch(&batch, &self.resource)
            .map_err(|_| OTelSdkError::InternalFailure("Could not encode Jaeger spans".into()))?;
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header(header::CONTENT_TYPE, "application/x-thrift")
            .body(body);
        if let Some(authorization) = &self.authorization {
            request = request.header(header::AUTHORIZATION, authorization.clone());
        }
        let response = request.send().map_err(|error| {
            if error.is_timeout() {
                OTelSdkError::Timeout(self.timeout)
            } else {
                OTelSdkError::InternalFailure("Jaeger collector request failed".into())
            }
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(OTelSdkError::InternalFailure(format!(
                "Jaeger collector returned HTTP {}",
                status.as_u16()
            )));
        }
        Ok(())
    }
}

fn collector_authorization() -> Result<Option<HeaderValue>, SettingsError> {
    const USER: &str = "OTEL_EXPORTER_JAEGER_USER";
    const PASSWORD: &str = "OTEL_EXPORTER_JAEGER_PASSWORD";
    if environment::var_os(USER).is_none() || environment::var_os(PASSWORD).is_none() {
        return Ok(None);
    }
    let username = value(USER, "")?;
    let password = Zeroizing::new(value(PASSWORD, "")?);
    let credentials = Zeroizing::new(format!("{username}:{}", password.as_str()));
    let encoded = Zeroizing::new(BASE64_STANDARD.encode(credentials.as_bytes()));
    let basic = Zeroizing::new(format!("Basic {}", encoded.as_str()));
    let mut authorization = HeaderValue::from_str(&basic)?;
    authorization.set_sensitive(true);
    Ok(Some(authorization))
}

// The field IDs and types follow jaeger.thrift. HTTP accepts a Batch struct directly.
fn encode_batch(spans: &[SpanData], resource: &Resource) -> thrift::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut out = TBinaryOutputProtocol::new(&mut buffer, true);
    let service = collector_service_name(resource);
    structure(&mut out, "Batch", |out| {
        field(out, 1, TType::Struct, |out| {
            structure(out, "Process", |out| {
                field(out, 1, TType::String, |out| out.write_string(&service))
            })
        })?;
        list(out, 2, spans, |out, span| write_span(out, span, resource))
    })?;
    out.flush()?;
    Ok(buffer)
}

fn write_span(
    out: &mut impl TOutputProtocol,
    span: &SpanData,
    resource: &Resource,
) -> thrift::Result<()> {
    let (high, low, id) = span_ids(&span.span_context);
    let parent = i64::from_be_bytes(span.parent_span_id.to_bytes());
    let flags = i32::from(span.span_context.is_sampled());
    let start = timestamp_micros(span.start_time);
    let duration = duration_micros(
        span.end_time
            .duration_since(span.start_time)
            .unwrap_or_default(),
    );
    let tags = span_tags(span, resource);
    structure(out, "Span", |out| {
        field(out, 1, TType::I64, |out| out.write_i64(low))?;
        field(out, 2, TType::I64, |out| out.write_i64(high))?;
        field(out, 3, TType::I64, |out| out.write_i64(id))?;
        field(out, 4, TType::I64, |out| out.write_i64(parent))?;
        field(out, 5, TType::String, |out| out.write_string(&span.name))?;
        if !span.links.is_empty() {
            list(out, 6, &span.links, write_reference)?;
        }
        field(out, 7, TType::I32, |out| out.write_i32(flags))?;
        field(out, 8, TType::I64, |out| out.write_i64(start))?;
        field(out, 9, TType::I64, |out| out.write_i64(duration))?;
        list(out, 10, &tags, write_tag)?;
        if !span.events.is_empty() {
            list(out, 11, &span.events, write_log)?;
        }
        Ok(())
    })
}

fn span_ids(context: &SpanContext) -> (i64, i64, i64) {
    let trace = context.trace_id().to_bytes();
    let (high, low) = trace.split_at(8);
    (
        i64::from_be_bytes(high.try_into().unwrap()),
        i64::from_be_bytes(low.try_into().unwrap()),
        i64::from_be_bytes(context.span_id().to_bytes()),
    )
}

fn write_reference(out: &mut impl TOutputProtocol, link: &Link) -> thrift::Result<()> {
    let (high, low, id) = span_ids(&link.span_context);
    structure(out, "SpanRef", |out| {
        field(out, 1, TType::I32, |out| out.write_i32(1))?;
        field(out, 2, TType::I64, |out| out.write_i64(low))?;
        field(out, 3, TType::I64, |out| out.write_i64(high))?;
        field(out, 4, TType::I64, |out| out.write_i64(id))
    })
}

fn write_log(out: &mut impl TOutputProtocol, event: &Event) -> thrift::Result<()> {
    let mut tags = event.attributes.clone();
    if event.dropped_attributes_count != 0 {
        tags.push(KeyValue::new(
            "otel.dropped_attributes_count",
            i64::from(event.dropped_attributes_count),
        ));
    }
    tags.push(KeyValue::new("message", event.name.clone()));
    structure(out, "Log", |out| {
        field(out, 1, TType::I64, |out| {
            out.write_i64(timestamp_micros(event.timestamp))
        })?;
        list(out, 2, &tags, write_tag)
    })
}

fn span_tags(span: &SpanData, resource: &Resource) -> Vec<KeyValue> {
    let mut tags = span.attributes.clone();
    tags.extend(
        resource
            .iter()
            .map(|(key, value)| KeyValue::new(key.clone(), value.clone())),
    );
    match &span.status {
        Status::Unset => {}
        Status::Ok => tags.push(KeyValue::new("otel.status_code", "OK")),
        Status::Error { description } => tags.extend([
            KeyValue::new("otel.status_code", "ERROR"),
            KeyValue::new("otel.status_description", description.clone()),
            KeyValue::new("error", true),
        ]),
    }
    let kind = match span.span_kind {
        SpanKind::Client => "client",
        SpanKind::Server => "server",
        SpanKind::Producer => "producer",
        SpanKind::Consumer => "consumer",
        SpanKind::Internal => "internal",
    };
    tags.push(KeyValue::new("span.kind", kind));
    let scope = &span.instrumentation_scope;
    for key in ["otel.library.name", "otel.scope.name"] {
        tags.push(KeyValue::new(key, scope.name().to_owned()));
    }
    if let Some(version) = scope.version() {
        for key in ["otel.library.version", "otel.scope.version"] {
            tags.push(KeyValue::new(key, version.to_owned()));
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
            tags.push(KeyValue::new(key, i64::from(count)));
        }
    }
    tags
}

fn write_tag(out: &mut impl TOutputProtocol, attribute: &KeyValue) -> thrift::Result<()> {
    structure(out, "Tag", |out| {
        field(out, 1, TType::String, |out| {
            out.write_string(attribute.key.as_str())
        })?;
        let tag_type = match attribute.value {
            Value::F64(_) => 1,
            Value::Bool(_) => 2,
            Value::I64(_) => 3,
            _ => 0,
        };
        field(out, 2, TType::I32, |out| out.write_i32(tag_type))?;
        match &attribute.value {
            Value::F64(value) => field(out, 4, TType::Double, |out| out.write_double(*value)),
            Value::Bool(value) => field(out, 5, TType::Bool, |out| out.write_bool(*value)),
            Value::I64(value) => field(out, 6, TType::I64, |out| out.write_i64(*value)),
            Value::Array(_) => field(out, 3, TType::String, |out| {
                out.write_string(&collector_json_value(&attribute.value).to_string())
            }),
            value => field(out, 3, TType::String, |out| {
                out.write_string(&value.as_str())
            }),
        }
    })
}

fn structure<P: TOutputProtocol>(
    out: &mut P,
    name: &str,
    write: impl FnOnce(&mut P) -> thrift::Result<()>,
) -> thrift::Result<()> {
    out.write_struct_begin(&TStructIdentifier::new(name))?;
    write(out)?;
    out.write_field_stop()?;
    out.write_struct_end()
}

fn field<P: TOutputProtocol>(
    out: &mut P,
    id: i16,
    kind: TType,
    write: impl FnOnce(&mut P) -> thrift::Result<()>,
) -> thrift::Result<()> {
    out.write_field_begin(&TFieldIdentifier {
        name: None,
        field_type: kind,
        id: Some(id),
    })?;
    write(out)?;
    out.write_field_end()
}

fn list<P: TOutputProtocol, T>(
    out: &mut P,
    id: i16,
    values: &[T],
    mut write: impl FnMut(&mut P, &T) -> thrift::Result<()>,
) -> thrift::Result<()> {
    let size = i32::try_from(values.len())
        .map_err(|_| new_protocol_error(ProtocolErrorKind::SizeLimit, "Jaeger list too large"))?;
    field(out, id, TType::List, |out| {
        out.write_list_begin(&TListIdentifier::new(TType::Struct, size))?;
        for value in values {
            write(out, value)?;
        }
        out.write_list_end()
    })
}
