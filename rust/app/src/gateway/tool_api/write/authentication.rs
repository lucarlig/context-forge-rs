// SPDX-License-Identifier: Apache-2.0

use std::sync::LazyLock;

use serde_json::Map;

use super::*;
use crate::sigv4::SigV4Config;

pub(super) fn apply(
    service: &GatewayService,
    tool: &mut ToolRecord,
    nested: Option<Map<String, Value>>,
    mut fields: Map<String, Value>,
) -> Result<(), CatalogApiError> {
    let nested = nested.unwrap_or_default();
    let mut input = Map::new();
    for (name, camel, nested_name) in [
        ("auth_type", "authType", "auth_type"),
        ("auth_username", "authUsername", "username"),
        ("auth_password", "authPassword", "password"),
        ("auth_token", "authToken", "token"),
        ("auth_header_key", "authHeaderKey", "auth_header_key"),
        ("auth_header_value", "authHeaderValue", "auth_header_value"),
        ("auth_headers", "authHeaders", "authHeaders"),
        ("sigv4_config", "sigv4Config", "sigv4_config"),
    ] {
        let value = fields
            .remove(name)
            .or_else(|| fields.remove(camel))
            .or_else(|| {
                nested
                    .get(nested_name)
                    .or_else(|| nested.get(camel))
                    .cloned()
            });
        if let Some(value) = value.filter(|value| !value.is_null()) {
            input.insert(name.into(), value);
        }
    }
    if input.is_empty() && nested.is_empty() {
        return Ok(());
    }
    let kind = input
        .get("auth_type")
        .and_then(Value::as_str)
        .or(tool.auth_type.as_deref())
        .ok_or_else(|| invalid("Tool auth_type is required"))?
        .trim()
        .to_ascii_lowercase();
    if matches!(kind.as_str(), "" | "none") {
        tool.auth_type = None;
        tool.auth_value = None;
        tool.sigv4_config = None;
        return Ok(());
    }
    if !matches!(kind.as_str(), "basic" | "bearer" | "authheaders" | "sigv4") {
        return Err(invalid("Unsupported tool authentication type"));
    }
    let cipher = service.credential_cipher.as_ref().ok_or_else(|| {
        CatalogApiError::detail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Tool credential encryption unavailable",
        )
    })?;
    let same_kind = tool.auth_type.as_deref() == Some(kind.as_str());
    if kind == "sigv4" {
        let config = input.remove("sigv4_config");
        if let Some(config) = config {
            let mut config: SigV4Config = serde_json::from_value(config)
                .map_err(|_| invalid("Invalid SigV4 configuration"))?;
            config
                .resolve_masks(cipher, tool.sigv4_config.as_deref().filter(|_| same_kind))
                .map_err(|_| invalid("Invalid SigV4 configuration"))?;
            let (_, stored, _) = config
                .prepare(cipher)
                .map_err(|_| invalid("Invalid SigV4 configuration"))?;
            tool.sigv4_config = Some(stored);
        } else if tool.gateway_id.is_none() && (!same_kind || tool.sigv4_config.is_none()) {
            return Err(invalid("SigV4 requires credentials or a gateway"));
        }
        tool.auth_type = Some(kind);
        tool.auth_value = None;
        return Ok(());
    }
    if input.contains_key("sigv4_config") {
        return Err(invalid("sigv4_config requires auth_type 'sigv4'"));
    }
    if let Some(encoded) = nested
        .get("auth_value")
        .or_else(|| nested.get("authValue"))
        .and_then(Value::as_str)
        && !encoded.is_empty()
        && encoded != MASK
        && input.len() == 1
    {
        decode_stored_auth(cipher, encoded)
            .map_err(|_| invalid("Invalid stored tool credentials"))?;
        tool.auth_value = Some(encoded.to_owned());
        tool.auth_type = Some(kind);
        tool.sigv4_config = None;
        return Ok(());
    }
    let previous = if same_kind {
        tool.auth_value
            .as_deref()
            .map(|stored| decode_stored_auth(cipher, stored))
            .transpose()
            .map_err(|_| invalid("Stored tool credentials could not be loaded"))?
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    let value = |key: &str| {
        previous
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    };
    let authorization = value("authorization");
    if kind == "basic" {
        if let Some(encoded) = authorization.and_then(|value| value.strip_prefix("Basic "))
            && let Ok(decoded) = BASE64_STANDARD.decode(encoded).map(Zeroizing::new)
            && let Ok(decoded) = std::str::from_utf8(&decoded)
            && let Some((user, password)) = decoded.split_once(':')
        {
            retain_mask(&mut input, "auth_username", Some(user))?;
            retain_mask(&mut input, "auth_password", Some(password))?;
        } else {
            retain_mask(&mut input, "auth_username", None)?;
            retain_mask(&mut input, "auth_password", None)?;
        }
    } else if kind == "bearer" {
        retain_mask(
            &mut input,
            "auth_token",
            authorization.and_then(|value| value.strip_prefix("Bearer ")),
        )?;
    } else if let Some(values) = input.get_mut("auth_headers").and_then(Value::as_array_mut) {
        for header in values {
            let options = header
                .as_object_mut()
                .ok_or_else(|| invalid("Invalid tool auth headers"))?;
            let name = options
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Invalid tool auth headers"))?;
            let previous = value(name);
            retain_mask(options, "value", previous)?;
        }
    } else if let Some(key) = input.get("auth_header_key").and_then(Value::as_str) {
        let previous = value(key);
        retain_mask(&mut input, "auth_header_value", previous)?;
    } else if !previous.is_empty() {
        input.insert(
            "auth_headers".into(),
            json!(
                previous
                    .iter()
                    .map(|(key, value)| json!({"key":key,"value":value}))
                    .collect::<Vec<_>>()
            ),
        );
    }
    input.insert("auth_type".into(), kind.clone().into());
    let auth: AuthInput = serde_json::from_value(Value::Object(input))
        .map_err(|_| invalid("Invalid tool authentication"))?;
    let prepared = auth
        .prepare(Some(cipher), None, tool.url.as_deref().unwrap_or_default())
        .map_err(|_| invalid("Invalid tool authentication"))?
        .ok_or_else(|| invalid("Invalid tool authentication"))?;
    tool.auth_value = prepared
        .encoded_headers
        .as_deref()
        .and_then(|json| serde_json::from_str::<String>(json).ok());
    tool.auth_type = Some(kind);
    tool.sigv4_config = None;
    Ok(())
}

fn retain_mask(
    map: &mut Map<String, Value>,
    key: &str,
    previous: Option<&str>,
) -> Result<(), CatalogApiError> {
    if map
        .get(key)
        .is_none_or(|value| value.as_str() == Some(MASK))
    {
        let value = previous.ok_or_else(|| invalid("Masked credential has no stored value"))?;
        map.insert(key.to_owned(), value.into());
    }
    Ok(())
}

pub(super) fn prepare_headers(
    service: &GatewayService,
    tool: &ToolRecord,
    headers: BTreeMap<String, String>,
) -> Result<String, CatalogApiError> {
    let previous = json_value(tool.headers.as_deref());
    let mut updated = Map::new();
    let mut names = HashSet::new();
    for (name, value) in headers {
        if HeaderName::from_bytes(name.as_bytes()).is_err()
            || axum::http::HeaderValue::from_str(&value).is_err()
            || !names.insert(name.to_ascii_lowercase())
        {
            return Err(invalid("Invalid tool headers"));
        }
        let encoded = if value == MASK {
            previous
                .as_object()
                .and_then(|fields| {
                    fields
                        .iter()
                        .find(|(key, _)| key.eq_ignore_ascii_case(&name))
                        .map(|(_, value)| value.clone())
                })
                .ok_or_else(|| invalid("Masked header has no stored value"))?
        } else if protected_header(&name) {
            let cipher = service.credential_cipher.as_ref().ok_or_else(|| {
                CatalogApiError::detail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Tool credential encryption unavailable",
                )
            })?;
            let encoded = cipher
                .seal(&json!({"data":value}))
                .map_err(|_| invalid("Tool header encryption failed"))?;
            json!({(SECRET_HEADER):encoded})
        } else {
            value.into()
        };
        updated.insert(name, encoded);
    }
    Ok(Value::Object(updated).to_string())
}

pub(super) fn protected_header(name: &str) -> bool {
    static SENSITIVE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)^(?:x-)?(?:auth|api|access|refresh|client|bearer|session|security)[-_]?(?:token|secret|key)$")
            .expect("valid credential header pattern")
    });
    let normalized = name.to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "host"
            | "transfer-encoding"
            | "content-length"
            | "connection"
            | "upgrade"
            | "content-type"
    ) || SENSITIVE.is_match(name)
}
