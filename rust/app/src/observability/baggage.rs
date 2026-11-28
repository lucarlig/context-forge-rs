// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, sync::Arc, time::Duration};

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use indexmap::IndexMap;
use opentelemetry::{Context, KeyValue, trace::Span as _};
use opentelemetry_sdk::{
    error::OTelSdkResult,
    trace::{Span, SpanData, SpanProcessor},
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};

use super::{QueryRedaction, operation::current_baggage};
use crate::config::{flag, parse, value};

pub(crate) const HEADER: &str = "baggage";
const ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
type SettingsError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Deserialize)]
struct MappingSetting {
    header_name: String,
    baggage_key: String,
}

pub(super) struct Policy {
    mappings: Vec<(HeaderName, String)>,
    keys: HashSet<String>,
    forward: bool,
    max_bytes: usize,
    max_value_length: usize,
    log_rejected: bool,
    log_sanitization: bool,
}

#[derive(Deserialize, Serialize)]
pub(super) struct Baggage {
    entries: Vec<(String, String)>,
    forward: bool,
}

impl Policy {
    pub(super) fn from_env(redaction: &QueryRedaction) -> Result<Option<Self>, SettingsError> {
        if !flag("OTEL_BAGGAGE_ENABLED")?.unwrap_or(false) {
            return Ok(None);
        }
        let max_items = parse("OTEL_BAGGAGE_MAX_ITEMS", 32)?;
        let max_bytes = parse("OTEL_BAGGAGE_MAX_SIZE_BYTES", 8192)?;
        let max_value_length = parse::<usize>("MAX_HEADER_VALUE_LENGTH", 4096)?;
        if !(1..=64).contains(&max_items)
            || !(1024..=16384).contains(&max_bytes)
            || max_value_length == 0
        {
            return Err("invalid OpenTelemetry baggage limits".into());
        }
        let mappings: Vec<MappingSetting> =
            serde_json::from_str(&value("OTEL_BAGGAGE_HEADER_MAPPINGS", "[]")?)?;
        if mappings.len() > max_items {
            return Err("too many OpenTelemetry baggage mappings".into());
        }
        let mut normalized = Vec::with_capacity(mappings.len());
        let mut headers = HashSet::new();
        let mut keys = HashSet::new();
        for mapping in mappings {
            if !valid_name(&mapping.header_name, &[])
                || mapping.baggage_key.len() > 256
                || !valid_name(&mapping.baggage_key, b"._")
            {
                return Err("invalid OpenTelemetry baggage mapping".into());
            }
            let header = HeaderName::from_bytes(mapping.header_name.as_bytes())?;
            if blocked_header(&header, redaction) || sensitive_key(&mapping.baggage_key, redaction)
            {
                return Err("credential or propagation headers cannot be mapped to baggage".into());
            }
            if !headers.insert(header.clone()) || !keys.insert(mapping.baggage_key.clone()) {
                return Err("duplicate OpenTelemetry baggage mapping".into());
            }
            normalized.push((header, mapping.baggage_key));
        }
        if normalized.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            mappings: normalized,
            keys,
            forward: flag("OTEL_BAGGAGE_PROPAGATE_TO_EXTERNAL")?.unwrap_or(false),
            max_bytes,
            max_value_length: max_value_length.min(max_bytes),
            log_rejected: flag("OTEL_BAGGAGE_LOG_REJECTED")?.unwrap_or(true),
            log_sanitization: flag("OTEL_BAGGAGE_LOG_SANITIZATION")?.unwrap_or(true),
        }))
    }

    pub(super) fn read(&self, headers: &HeaderMap) -> Option<Arc<Baggage>> {
        let mut rejected = 0;
        let mut incoming = self.incoming(headers, &mut rejected);
        let mapped = self
            .mappings
            .iter()
            .filter_map(|(header, key)| {
                let value = headers.get_all(header).iter().next_back()?.to_str().ok()?;
                let value = self.sanitize(value)?;
                incoming.shift_remove(key.as_str());
                Some((key.as_str(), value))
            })
            .collect::<Vec<_>>();
        let mut encoded_bytes = 0;
        let mut entries = Vec::new();
        for (key, value) in mapped.into_iter().chain(incoming) {
            let size = key.len()
                + 1
                + encoded(&value).to_string().len()
                + usize::from(!entries.is_empty());
            if encoded_bytes + size > self.max_bytes {
                rejected += 1;
                continue;
            }
            entries.push((key.to_owned(), value));
            encoded_bytes += size;
        }
        if self.log_rejected && rejected > 0 {
            tracing::debug!(
                rejected,
                "Dropped incoming baggage outside the configured policy"
            );
        }
        (!entries.is_empty()).then(|| {
            Arc::new(Baggage {
                entries,
                forward: self.forward,
            })
        })
    }

    fn incoming<'a>(
        &'a self,
        headers: &HeaderMap,
        rejected: &mut usize,
    ) -> IndexMap<&'a str, String> {
        let fields = headers.get_all(HEADER);
        let mut length = 0;
        let mut incoming = IndexMap::new();
        for field in &fields {
            length += field.as_bytes().len() + usize::from(length != 0);
            if length > self.max_bytes {
                *rejected += 1;
                break;
            }
            let Ok(raw) = field.to_str() else {
                *rejected += 1;
                continue;
            };
            for member in raw.split(',') {
                let Some((key, value)) = member
                    .split(';')
                    .next()
                    .and_then(|member| member.split_once('='))
                else {
                    *rejected += 1;
                    continue;
                };
                let Some(key) = self.keys.get(key.trim()) else {
                    *rejected += 1;
                    continue;
                };
                let value = value.trim();
                if !valid_wire_value(value) {
                    *rejected += 1;
                    continue;
                }
                let decoded = percent_decode_str(value).decode_utf8_lossy();
                if let Some(value) = self.sanitize(&decoded) {
                    incoming.insert(key.as_str(), value);
                } else {
                    *rejected += 1;
                }
            }
        }
        incoming
    }

    fn sanitize(&self, raw: &str) -> Option<String> {
        if credential_value(raw) {
            return None;
        }
        let value: String = raw
            .chars()
            .take(self.max_value_length)
            .filter(|character| matches!(character, ' '..='~'))
            .collect();
        if self.log_sanitization && value != raw {
            tracing::debug!("Sanitized a baggage value");
        }
        (!value.trim().is_empty() && !credential_value(&value)).then_some(value)
    }
}

fn credential_value(value: &str) -> bool {
    let mut words = value.split_ascii_whitespace();
    words.next().is_some_and(|word| {
        word.eq_ignore_ascii_case("basic") || word.eq_ignore_ascii_case("bearer")
    }) && words.next().is_some()
}

fn valid_name(text: &str, extra: &[u8]) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || extra.contains(&byte))
}

fn sensitive_key(key: &str, redaction: &QueryRedaction) -> bool {
    redaction.sensitive_key(key)
        || key
            .rsplit_once('.')
            .is_some_and(|(_, name)| redaction.sensitive_key(name))
}

fn blocked_header(header: &HeaderName, redaction: &QueryRedaction) -> bool {
    let name = header.as_str();
    crate::forward_headers::sensitive(header)
        || sensitive_key(name, redaction)
        || name
            .strip_prefix("x-")
            .is_some_and(|base| sensitive_key(base, redaction))
        || matches!(
            name,
            HEADER
                | "traceparent"
                | "tracestate"
                | "proxy-authorization"
                | "mcp-session-id"
                | "x-mcp-session-id"
                | "x-vault-tokens"
                | "x-upstream-authorization"
        )
}

fn valid_wire_value(value: &str) -> bool {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                if !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                    || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                {
                    return false;
                }
            }
            b'!' | b'#'..=b'+' | b'-'..=b':' | b'<'..=b'[' | b']'..=b'~' => {}
            _ => return false,
        }
    }
    true
}

fn encoded(value: &str) -> percent_encoding::PercentEncode<'_> {
    utf8_percent_encode(value, ENCODE)
}

pub(super) fn inject(headers: &mut HeaderMap, baggage: Option<&Baggage>) {
    headers.remove(HEADER);
    if let Some(baggage) = baggage.filter(|baggage| baggage.forward) {
        let wire = baggage
            .entries
            .iter()
            .map(|(key, value)| format!("{key}={}", encoded(value)))
            .collect::<Vec<_>>()
            .join(",");
        if !wire.is_empty()
            && let Ok(mut value) = HeaderValue::from_str(&wire)
        {
            value.set_sensitive(true);
            headers.insert(HEADER, value);
        }
    }
}

#[derive(Debug)]
pub(super) struct Processor;

impl SpanProcessor for Processor {
    fn on_start(&self, span: &mut Span, parent: &Context) {
        if let Some(baggage) = parent
            .get::<Arc<Baggage>>()
            .cloned()
            .or_else(current_baggage)
        {
            span.set_attributes(
                baggage
                    .entries
                    .iter()
                    .map(|(key, value)| KeyValue::new(format!("baggage.{key}"), value.clone())),
            );
        }
    }

    fn on_end(&self, _: SpanData) {}

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_encoded_baggage_and_requires_forwarding() {
        let mut policy = Policy {
            mappings: vec![
                (HeaderName::from_static("x-fixture-zone"), "zone".into()),
                (HeaderName::from_static("x-fixture-region"), "region".into()),
            ],
            keys: ["zone".into(), "region".into()].into(),
            forward: false,
            max_bytes: 1024,
            max_value_length: 1024,
            log_rejected: false,
            log_sanitization: false,
        };
        let mut headers = HeaderMap::new();
        headers.append(HEADER, HeaderValue::from_static("region=invalid%QQ"));
        headers.append(
            HEADER,
            HeaderValue::from_static("region=west+east;meta=yes"),
        );
        headers.insert(
            "x-fixture-zone",
            HeaderValue::from_str(&format!("a{}z", " ".repeat(340))).unwrap(),
        );
        let local = policy.read(&headers).unwrap();
        assert_eq!(
            local.entries,
            [("region".to_owned(), "west+east".to_owned())]
        );
        let mut outgoing = headers.clone();
        inject(&mut outgoing, Some(&local));
        assert!(!outgoing.contains_key(HEADER));

        policy.forward = true;
        let outbound = policy.read(&headers).unwrap();
        inject(&mut outgoing, Some(&outbound));
        assert_eq!(outgoing[HEADER], "region=west%2Beast");
        assert!(outgoing[HEADER].is_sensitive());

        let oversized = format!("region={}", "x".repeat(1024));
        headers.insert(HEADER, HeaderValue::from_str(&oversized).unwrap());
        assert!(policy.read(&headers).is_none());
    }
}
