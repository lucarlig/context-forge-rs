// SPDX-License-Identifier: Apache-2.0

use std::sync::LazyLock;

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use regex::Regex;

use crate::{
    config::{HeaderForwarding, HeaderSource},
    database::Database,
    gateway::GATEWAY_ID_HEADER,
};

const EXPLICIT_AUTH: &str = "x-upstream-authorization";

impl HeaderForwarding {
    pub(crate) fn needs_config(&self, headers: &HeaderMap) -> bool {
        self.enabled || headers.contains_key(EXPLICIT_AUTH)
    }

    pub(crate) async fn apply(
        &self,
        database: &Database,
        outgoing: &mut HeaderMap,
        incoming: &HeaderMap,
        gateway_headers: Option<&str>,
        managed_auth: bool,
    ) -> Result<(), sqlx::Error> {
        if !managed_auth
            && !outgoing.contains_key(header::AUTHORIZATION)
            && !nominated_hop_header(incoming, EXPLICIT_AUTH)
            && let Some(value) = sanitized(incoming, EXPLICIT_AUTH, self.max_value_length)
        {
            outgoing.insert(header::AUTHORIZATION, value);
        }
        if !self.enabled {
            return Ok(());
        }
        let mut allowed = if let Some(raw) = gateway_headers.filter(|raw| raw.trim() != "null") {
            parse_config(raw)?
        } else if matches!(self.source, HeaderSource::Environment) {
            self.defaults.iter().cloned().collect()
        } else {
            let database = database.global_passthrough_headers().await?;
            let database = database.as_deref().filter(|raw| raw.trim() != "null");
            match (database, &self.source) {
                (Some(raw), HeaderSource::Merge) => {
                    let mut allowed: Vec<_> = self.defaults.iter().cloned().collect();
                    allowed.extend(parse_config(raw)?);
                    allowed
                }
                (Some(raw), _) => parse_config(raw)?,
                (None, _) => self.defaults.iter().cloned().collect(),
            }
        };
        allowed.sort_unstable_by_key(|name| name.to_ascii_lowercase());
        allowed.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        for name in allowed {
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            if blocked(&name, incoming)
                || !self.sensitive && sensitive(&name)
                || managed_auth && name == header::AUTHORIZATION
                || !self.overwrite && outgoing.contains_key(&name)
            {
                continue;
            }
            if let Some(value) = sanitized(incoming, name.as_str(), self.max_value_length) {
                outgoing.insert(name, value);
            }
        }
        Ok(())
    }
}

fn parse_config(raw: &str) -> Result<Vec<String>, sqlx::Error> {
    serde_json::from_str(raw)
        .map_err(|_| sqlx::Error::Protocol("invalid passthrough header configuration".into()))
}

fn blocked(name: &HeaderName, incoming: &HeaderMap) -> bool {
    let name = name.as_str();
    name.starts_with("mcp-")
        || hop_header_name(name)
        || name.starts_with("x-forwarded-user")
        || matches!(
            name,
            "accept"
                | "content-type"
                | "content-length"
                | "host"
                | "expect"
                | EXPLICIT_AUTH
                | GATEWAY_ID_HEADER
        )
        || nominated_hop_header(incoming, name)
}

pub(crate) fn hop_header_name(name: &str) -> bool {
    name.starts_with("proxy-")
        || matches!(
            name,
            "connection" | "keep-alive" | "te" | "trailer" | "transfer-encoding" | "upgrade"
        )
}

pub(crate) fn nominated_hop_header(incoming: &HeaderMap, name: &str) -> bool {
    incoming
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|listed| listed.trim().eq_ignore_ascii_case(name))
}

fn sensitive(name: &HeaderName) -> bool {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
        r"^(?:authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-(?:auth|api|access|refresh|client|bearer|session|security)[-_]?(?:token|secret|key)|x-amz-(?:security-token|signature|credential))$"
    ).expect("valid sensitive-header expression")
    });
    PATTERN.is_match(name.as_str())
}

fn sanitized(incoming: &HeaderMap, name: &str, max_length: usize) -> Option<HeaderValue> {
    let mut values = incoming.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let printable: Vec<_> = value
        .as_bytes()
        .iter()
        .take(max_length)
        .copied()
        .filter(|byte| (b' '..=b'~').contains(byte))
        .collect();
    if printable.is_empty() {
        return None;
    }
    let mut value = HeaderValue::from_bytes(&printable).ok()?;
    value.set_sensitive(true);
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forwards_allowed_values_without_replacing_managed_authorization() {
        let database =
            Database::Sqlite(sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap());
        let mut incoming = HeaderMap::new();
        for (name, value) in [
            ("x-tenant-id", "tenant-fixture"),
            ("x-api-key", "caller-api-key"),
            ("x-upstream-authorization", "Bearer caller-upstream"),
            ("authorization", "Bearer gateway-token"),
            ("host", "gateway.example.test"),
            ("connection", "X-Hop"),
            ("x-hop", "connection-only"),
        ] {
            incoming.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        let mut outgoing = HeaderMap::new();
        outgoing.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer stored-upstream"),
        );
        let mut policy = HeaderForwarding {
            enabled: true,
            overwrite: true,
            ..HeaderForwarding::default()
        };
        let configured = Some(r#"["X-Tenant-ID","Authorization","X-Api-Key","Host","X-Hop"]"#);
        policy
            .apply(&database, &mut outgoing, &incoming, configured, true)
            .await
            .unwrap();
        assert_eq!(outgoing[header::AUTHORIZATION], "Bearer stored-upstream");
        assert_eq!(outgoing["x-tenant-id"], "tenant-fixture");
        assert_eq!(outgoing.len(), 2);

        policy.sensitive = true;
        policy
            .apply(&database, &mut outgoing, &incoming, configured, true)
            .await
            .unwrap();
        assert_eq!(outgoing[header::AUTHORIZATION], "Bearer stored-upstream");
        assert_eq!(outgoing["x-api-key"], "caller-api-key");
        assert_eq!(outgoing.len(), 3);

        outgoing.clear();
        HeaderForwarding::default()
            .apply(&database, &mut outgoing, &incoming, None, false)
            .await
            .unwrap();
        assert_eq!(outgoing[header::AUTHORIZATION], "Bearer caller-upstream");
        assert_eq!(outgoing.len(), 1);
    }
}
