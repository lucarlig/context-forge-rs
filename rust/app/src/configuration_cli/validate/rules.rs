// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use axum::http::HeaderName;
use serde_json::Value;
use url::Url;

use crate::{gateway::CIMD_DOCUMENT_PATH, http_boundary::ProxyHeaders};

use super::{Issue, ResultKind, Values};

pub(super) fn is_http_url(raw: &str) -> bool {
    Url::parse(raw).is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
}

pub(super) fn incompatible(message: &str) -> ResultKind {
    ResultKind::Invalid(vec![Issue::value("", message)])
}

pub(super) fn fields(values: &Values<'_>, issues: &mut Vec<Issue>) {
    for (field, value) in values.explicit.as_object().into_iter().flatten() {
        let issue = value
            .as_str()
            .and_then(|text| text_issue(field, text))
            .or_else(|| value.as_array().and_then(|list| list_issue(field, list)))
            .or_else(|| {
                (field == "max_header_value_length" && value.as_f64().is_some_and(|n| n <= 0.0))
                    .then_some("MAX_HEADER_VALUE_LENGTH must be positive")
            });
        if let Some(message) = issue {
            issues.push(Issue::value(field, message));
        }
    }
}

fn text_issue(field: &str, raw: &str) -> Option<&'static str> {
    match field {
        "auth_header_name"
            if !raw.trim().is_empty() && raw.trim().parse::<HeaderName>().is_err() =>
        {
            Some("AUTH_HEADER_NAME must be a valid HTTP header token")
        }
        "forwarded_allow_ips" if ProxyHeaders::parse(raw).is_err() => {
            Some("FORWARDED_ALLOW_IPS must contain valid IP addresses or CIDR networks")
        }
        "oauth_redirect_allowed_origin" if !exact_https_origin(raw) => {
            Some("OAUTH_REDIRECT_ALLOWED_ORIGIN must be an exact HTTPS origin")
        }
        "cimd_client_metadata_url" if !raw.is_empty() && !cimd_url(raw) => Some(
            "CIMD_CLIENT_METADATA_URL must end with /oauth/client-metadata.json and have no query or fragment",
        ),
        "ui_base_url"
            if Url::parse(raw).is_ok_and(|url| {
                !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some_and(|query| !query.is_empty())
                    || url.fragment().is_some_and(|fragment| !fragment.is_empty())
            }) =>
        {
            Some("UI_BASE_URL must omit credentials, queries, and fragments")
        }
        "ratelimiter_redis_url"
            if !raw.trim().is_empty()
                && !raw.trim().starts_with("redis://")
                && !raw.trim().starts_with("rediss://") =>
        {
            Some("RATELIMITER_REDIS_URL must start with redis:// or rediss://")
        }
        _ => None,
    }
}

fn list_issue(field: &str, list: &[Value]) -> Option<&'static str> {
    let strings = list.iter().filter_map(Value::as_str);
    match field {
        "root_allowed_schemes"
            if strings.clone().any(|scheme| {
                !matches!(
                    scheme.to_ascii_lowercase().as_str(),
                    "http" | "https" | "ws" | "wss"
                )
            }) =>
        {
            Some("ROOT_ALLOWED_SCHEMES must contain HTTP or WebSocket schemes")
        }
        "root_allowed_file_prefixes"
            if strings.clone().any(|prefix| !valid_file_prefix(prefix)) =>
        {
            Some("ROOT_ALLOWED_FILE_PREFIXES must contain absolute POSIX paths without traversal")
        }
        "uaid_allowed_domains" if strings.clone().any(|domain| !valid_uaid_domain(domain)) => {
            Some("UAID_ALLOWED_DOMAINS must contain public host names only")
        }
        _ => None,
    }
}

fn exact_https_origin(raw: &str) -> bool {
    let Some((_, target)) = raw.split_once("://") else {
        return false;
    };
    let target = target.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = target.split_once('/').unwrap_or((target, ""));
    !authority.ends_with(':')
        && !authority.contains('@')
        && !raw.contains('\\')
        && path.is_empty()
        && Url::parse(raw).is_ok_and(|url| {
            url.scheme() == "https"
                && url.has_host()
                && url.query().is_none_or(str::is_empty)
                && url.fragment().is_none_or(str::is_empty)
        })
}

fn cimd_url(raw: &str) -> bool {
    let (path, fragment) = raw.split_once('#').unwrap_or((raw, ""));
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    query.is_empty() && fragment.is_empty() && path.ends_with(CIMD_DOCUMENT_PATH)
}

fn valid_file_prefix(raw: &str) -> bool {
    raw.starts_with('/')
        && !raw
            .bytes()
            .any(|ch| ch.is_ascii_control() || matches!(ch, b'\\' | b'?' | b'#'))
        && !raw
            .strip_prefix("//")
            .is_some_and(|address| !address.is_empty() && !address.starts_with('/'))
        && !raw.split('/').any(|component| component == "..")
}

fn valid_uaid_domain(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    let host = if lower.starts_with('[') {
        lower
            .split_once("]:")
            .map_or(lower.as_str(), |(host, _)| &lower[..=host.len()])
    } else if lower.bytes().filter(|&ch| ch == b':').count() == 1 {
        lower
            .split_once(':')
            .map_or(lower.as_str(), |(host, _)| host)
    } else {
        lower.as_str()
    };
    let private_172 = lower
        .strip_prefix("172.")
        .and_then(|number| number.split_once('.'))
        .is_some_and(|(number, _)| {
            number.len() == 2
                && number
                    .parse::<u8>()
                    .is_ok_and(|octet| (16..=31).contains(&octet))
        });
    !matches!(
        host,
        "localhost" | "127.0.0.1" | "::1" | "[::1]" | "0.0.0.0" | "[::0]"
    ) && !host.starts_with("169.254.")
        && !lower.starts_with("10.")
        && !lower.starts_with("192.168.")
        && !private_172
        && !raw.contains([' ', '\t', '\n'])
}

pub(super) fn collection(field: &str, property: &Value, raw: &str) -> serde_json::Result<Value> {
    let mut value = match field {
        "allowed_origins" | "mcp_allowed_origins" | "mcp_allowed_hosts" => origin_values(raw),
        "identity_sensitive_attributes" => Value::from(raw),
        "sso_issuers" => serde_json::from_str(raw).unwrap_or_else(|_| Value::from(raw)),
        "default_passthrough_headers"
        | "mcpgateway_ui_hide_header_items"
        | "mcpgateway_ui_hide_header_items_admin"
        | "mcpgateway_ui_hide_sections"
        | "mcpgateway_ui_hide_sections_admin"
        | "sso_auto_admin_domains"
        | "sso_entra_admin_groups"
        | "sso_generic_admin_groups"
        | "sso_github_admin_orgs"
        | "sso_google_admin_domains"
        | "sso_trusted_domains" => list_or_csv(raw),
        _ => serde_json::from_str(raw)?,
    };
    match field {
        "siem_destinations" => {
            if let Value::String(raw) = &value {
                value = serde_json::from_str(raw)
                    .or_else(|_| serde_saphyr::from_str(raw))
                    .unwrap_or_default();
            }
            let list = match value {
                Value::Array(list) => list,
                _ => value
                    .get_mut("destinations")
                    .map(Value::take)
                    .or_else(|| {
                        value
                            .pointer_mut("/siem_export/destinations")
                            .map(Value::take)
                    })
                    .and_then(|items| match items {
                        Value::Array(items) => Some(items),
                        _ => None,
                    })
                    .unwrap_or_default(),
            };
            value = Value::Array(list.into_iter().filter(Value::is_object).collect());
        }
        "allowed_roots"
        | "insecure_queryparam_auth_allowed_hosts"
        | "root_allowed_schemes"
        | "root_allowed_file_prefixes"
        | "tool_description_forbidden_patterns"
        | "sso_issuers" => {
            if let Some(raw) = value.as_str() {
                value = list_or_csv(raw);
            }
        }
        _ => {}
    }
    if property["uniqueItems"] == true
        && let Some(items) = value.as_array_mut()
    {
        let mut present = HashSet::new();
        items.retain(|item| present.insert(item.clone()));
    }
    Ok(value)
}

fn list_or_csv(raw: &str) -> Value {
    if let Ok(Value::Array(items)) = serde_json::from_str(raw) {
        return Value::Array(items);
    }
    Value::Array(
        raw.split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(Value::from)
            .collect(),
    )
}

fn origin_values(raw: &str) -> Value {
    let raw = raw.trim();
    let raw = ['\'', '"']
        .into_iter()
        .find_map(|quote| raw.strip_prefix(quote)?.strip_suffix(quote))
        .unwrap_or(raw);
    match serde_json::from_str(raw) {
        Ok(Value::Object(object)) => Value::Array(
            object
                .into_iter()
                .map(|(key, _)| Value::from(key))
                .collect(),
        ),
        Ok(Value::String(string)) => Value::Array(
            string
                .chars()
                .map(|ch| Value::String(ch.to_string()))
                .collect(),
        ),
        Ok(value) => value,
        Err(_) => list_or_csv(raw),
    }
}
