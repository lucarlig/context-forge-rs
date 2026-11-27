// SPDX-License-Identifier: Apache-2.0

use base64::{Engine, prelude::BASE64_STANDARD};

use super::*;
use crate::gateway::{GatewayRegistrationSource, RegisterGateway, register_gateway};

pub(super) async fn import_gateway(
    service: &GatewayService,
    scope: &ImportScope<'_>,
    mut data: Map<String, Value>,
) -> Result<Outcome, CatalogApiError> {
    let name = data
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned();
    let slug = slugify(&name);
    if name.len() > 255 || slug.is_empty() {
        return Err(invalid("Invalid gateway name"));
    }

    let visibility = access::catalog_scope(Some(scope.principal));
    let matches: Vec<_> = service
        .database
        .gateway_records(&slug)
        .await?
        .into_iter()
        .filter(|record| {
            record.slug == slug
                && visibility.visible(
                    &record.visibility,
                    record.team_id.as_deref(),
                    record.owner_email.as_deref(),
                )
        })
        .collect();
    let owned = matches
        .iter()
        .filter(|record| scope.owns(record.owner_email.as_deref()));
    let mut previous = owned.take(2).collect::<Vec<_>>();
    let mut rename = None;
    let existing = if matches.is_empty() {
        None
    } else {
        match scope.strategy {
            Strategy::Skip => return Ok(Outcome::Skipped),
            Strategy::Fail => return Err(name_conflict(&name)),
            Strategy::Rename => {
                let suffix = format!("_imported_{}", Timestamp::now().as_second());
                let limit = name.floor_char_boundary((255 - suffix.len()).min(name.len()));
                let renamed = format!("{}{suffix}", &name[..limit]);
                data.insert("name".into(), renamed.clone().into());
                rename = Some(renamed);
                None
            }
            Strategy::Update if previous.len() == 1 => previous.pop().cloned(),
            Strategy::Update if previous.is_empty() => {
                return Err(CatalogApiError::detail(
                    StatusCode::FORBIDDEN,
                    format!("Permission denied: cannot update gateway {name}"),
                ));
            }
            Strategy::Update => return Err(name_conflict(&name)),
        }
    };

    let mut fields = gateway_fields(service, scope, data)?;
    if let Some(existing) = existing {
        let update = serde_json::from_value(Value::Object(fields))
            .map_err(|_| invalid("Invalid imported gateway"))?;
        crate::gateway::management::import_update(service, scope, existing, update).await?;
        return Ok(Outcome::Updated);
    }

    if let Some(Value::Array(tags)) = fields.remove("tags") {
        let tags = tags
            .iter()
            .map(|tag| tag["label"].as_str().unwrap_or_default())
            .collect::<Vec<_>>();
        fields.insert("tags".into(), json!(tags));
    }
    let input: RegisterGateway = serde_json::from_value(Value::Object(fields))
        .map_err(|_| invalid("Invalid imported gateway"))?;
    register_gateway(
        service,
        scope.principal,
        input,
        GatewayRegistrationSource::Import(scope),
    )
    .await
    .map_err(|error| CatalogApiError::detail(error.status, error.message))?;
    Ok(rename.map_or(Outcome::Created, Outcome::Renamed))
}

fn gateway_fields(
    service: &GatewayService,
    scope: &ImportScope<'_>,
    mut data: Map<String, Value>,
) -> Result<Map<String, Value>, CatalogApiError> {
    if data
        .get("tool_validation_policy")
        .is_some_and(|value| match value {
            Value::Null => false,
            Value::String(policy) => !policy.trim().is_empty(),
            _ => true,
        })
    {
        return Err(invalid(
            "Gateway tool validation policies cannot yet be imported",
        ));
    }
    if !data.get("url").is_some_and(Value::is_string) {
        return Err(invalid("Invalid gateway URL"));
    }
    let auth = auth_fields(service, scope, &data)?;
    let tags = data.remove("tags");
    data.retain(|key, _| {
        matches!(
            key.as_str(),
            "name" | "url" | "description" | "transport" | "passthrough_headers"
        )
    });
    match tags {
        Some(Value::Array(tags)) => {
            data.insert(
                "tags".into(),
                super::super::catalog_api::normalized_tags(tags)?,
            );
        }
        None | Some(Value::Null) => {}
        Some(_) => return Err(invalid("Invalid catalog tag")),
    }
    data.extend(auth);
    Ok(data)
}

fn auth_fields(
    service: &GatewayService,
    scope: &ImportScope<'_>,
    data: &Map<String, Value>,
) -> Result<Map<String, Value>, CatalogApiError> {
    let auth_value = data.get("auth_value").filter(|value| !value.is_null());
    let auth_query = data
        .get("auth_query_params")
        .filter(|value| !value.is_null());
    let kind = match data.get("auth_type") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.as_str()),
        _ => return Err(invalid_credentials()),
    };
    let mut fields = Map::new();
    if matches!(kind, None | Some("" | "none")) && auth_value.is_none() && auth_query.is_none() {
        return Ok(fields);
    }
    let kind = kind.ok_or_else(invalid_credentials)?;
    let decode = |value: &Value| {
        open_archive(
            service,
            scope,
            value.as_str().ok_or_else(invalid_credentials)?,
        )
    };
    match kind {
        "basic" | "bearer" if auth_query.is_none() => {
            let headers = decode(auth_value.ok_or_else(invalid_credentials)?)?;
            if headers.len() != 1 {
                return Err(invalid_credentials());
            }
            let header = headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.as_str())
                .ok_or_else(invalid_credentials)?;
            if kind == "basic" {
                let encoded = header
                    .strip_prefix("Basic ")
                    .ok_or_else(invalid_credentials)?;
                let bytes = BASE64_STANDARD
                    .decode(encoded)
                    .map(Zeroizing::new)
                    .map_err(|_| invalid_credentials())?;
                let text = std::str::from_utf8(&bytes).map_err(|_| invalid_credentials())?;
                let (user, password) = text.split_once(':').ok_or_else(invalid_credentials)?;
                fields.insert("auth_username".into(), user.into());
                fields.insert("auth_password".into(), password.into());
            } else {
                let token = header
                    .strip_prefix("Bearer ")
                    .ok_or_else(invalid_credentials)?;
                fields.insert("auth_token".into(), token.into());
            }
        }
        "authheaders" if auth_query.is_none() => {
            let headers = decode(auth_value.ok_or_else(invalid_credentials)?)?;
            let values: Vec<_> = headers
                .iter()
                .map(|(key, value)| json!({"key":key,"value":value}))
                .collect();
            fields.insert("auth_headers".into(), json!(values));
        }
        "query_param" if auth_value.is_none() => {
            let query = auth_query
                .and_then(Value::as_object)
                .ok_or_else(invalid_credentials)?;
            if query.len() != 1 {
                return Err(invalid_credentials());
            }
            let (key, value) = query.iter().next().ok_or_else(invalid_credentials)?;
            let decoded = decode(value)?;
            let value = decoded.get(key).ok_or_else(invalid_credentials)?;
            fields.insert("auth_query_param_key".into(), key.clone().into());
            fields.insert("auth_query_param_value".into(), value.clone().into());
        }
        _ => return Err(invalid_credentials()),
    }
    fields.insert("auth_type".into(), kind.into());
    Ok(fields)
}

fn open_archive(
    service: &GatewayService,
    scope: &ImportScope<'_>,
    stored: &str,
) -> Result<BTreeMap<String, String>, CatalogApiError> {
    let cipher = service
        .credential_cipher
        .as_ref()
        .ok_or_else(|| invalid("Gateway credential encryption unavailable"))?;
    cipher
        .open(stored)
        .or_else(|error| match scope.rekey {
            Some(source) => CredentialCipher::new(source).open(stored),
            None => Err(error),
        })
        .map_err(|_| invalid_credentials())
}

fn name_conflict(name: &str) -> CatalogApiError {
    CatalogApiError::detail(
        StatusCode::CONFLICT,
        format!(
            "Failed to process gateways: Failed to process gateway {name}: Gateway name conflict: {name}"
        ),
    )
}

fn invalid_credentials() -> CatalogApiError {
    invalid("Invalid imported gateway credentials")
}

fn invalid(message: &str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}
