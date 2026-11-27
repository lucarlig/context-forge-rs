// SPDX-License-Identifier: Apache-2.0

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    catalog::slugify,
    credentials::{CredentialCipher, decode_header_values},
    gateway_records::{GatewayList, GatewayRecord},
};

use super::*;

const MASKED: &str = "*****";

#[derive(Deserialize)]
pub(super) struct ListParameters {
    include_inactive: Option<String>,
    include_pagination: Option<String>,
    visibility: Option<String>,
    team_id: Option<String>,
    cursor: Option<String>,
    limit: Option<i64>,
}

pub(super) async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ListParameters>,
) -> Result<Json<Value>, ManagementError> {
    check_read(&service, &principal).await?;
    let include_inactive = flag(query.include_inactive.as_deref())?;
    let paginate = flag(query.include_pagination.as_deref())?;
    let visibility = query.visibility.as_deref();
    if visibility.is_some_and(|value| !matches!(value, "public" | "team" | "private")) {
        return Err(ManagementError::Invalid("Invalid gateway visibility"));
    }
    let team = query.team_id.as_deref();
    if let (TeamVisibility::Teams(allowed), Some(team)) = (&principal.visibility, team)
        && !allowed.iter().any(|id| id == team)
    {
        return Err(ManagementError::Denied);
    }
    let page_size = match query.limit {
        Some(0) => None,
        Some(limit) if limit > 0 => {
            Some(limit.min(i64::from(service.management_max_page_size)) as u32)
        }
        Some(_) => return Err(ManagementError::Invalid("Invalid gateway page limit")),
        None => Some(service.management_page_size),
    };
    let filters = json!([visibility, team, include_inactive]).to_string();
    let fingerprint = list_fingerprint("gateways.list", Some(&principal), Some(&filters));
    let position = query
        .cursor
        .as_deref()
        .and_then(|cursor| service.pagination.decode(cursor, &fingerprint).ok())
        .and_then(|cursor| serde_json::from_str::<(String, String)>(&cursor.after_id).ok());
    let mut records = service
        .database
        .listed_gateways(
            access::catalog_scope(Some(&principal)),
            GatewayList {
                include_inactive,
                visibility,
                team,
                after: position
                    .as_ref()
                    .map(|(date, id)| (date.as_str(), id.as_str())),
                limit: page_size.map_or(i64::MAX, |size| i64::from(size) + 1),
            },
        )
        .await?;
    let mut next = None;
    if let Some(page_size) = page_size
        && records.len() > page_size as usize
    {
        records.truncate(page_size as usize);
        if let Some(last) = records.last()
            && paginate
        {
            let position = serde_json::to_string(&(&last.created_at, &last.id))
                .map_err(|_| ManagementError::Internal)?;
            next = Some(
                service
                    .pagination
                    .encode(
                        position,
                        fingerprint,
                        Timestamp::now()
                            .as_second()
                            .saturating_add(service.pagination.ttl),
                    )
                    .map_err(|_| ManagementError::Internal)?,
            );
        }
    }
    let gateways = records
        .iter()
        .map(|record| response(record, service.credential_cipher.as_ref()))
        .collect::<Vec<_>>();
    Ok(Json(if paginate {
        json!({"gateways":gateways,"nextCursor":next})
    } else {
        json!(gateways)
    }))
}

pub(super) async fn detail(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(key): Path<String>,
) -> Result<Json<Value>, ManagementError> {
    check_read(&service, &principal).await?;
    let record = lookup(&service, &principal, key).await?;
    Ok(Json(response(&record, service.credential_cipher.as_ref())))
}

pub(super) async fn impact_preview(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(key): Path<String>,
) -> Result<Json<Value>, ManagementError> {
    check_read(&service, &principal).await?;
    let record = lookup(&service, &principal, key).await?;
    let servers = service
        .database
        .gateway_impact(&record.id, access::catalog_scope(Some(&principal)))
        .await?;
    Ok(Json(
        json!({"gatewayId":record.id,"mcpServerId":record.id,"servers":servers}),
    ))
}

pub(super) async fn delete(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(key): Path<String>,
) -> Result<Json<Value>, ManagementError> {
    let record = manageable(
        &service,
        &principal,
        key,
        "gateways.delete",
        "Only the owner can delete this gateway",
    )
    .await?;
    if !service.database.delete_gateway(&record).await? {
        return Err(ManagementError::ConcurrentChange);
    }
    service.subscriptions.removed(
        &record.id,
        &record.visibility,
        record.team_id.as_deref(),
        record.owner_email.as_deref(),
    );
    Ok(Json(
        json!({"status":"success","message":format!("Gateway {} deleted", record.id)}),
    ))
}

async fn manageable(
    service: &GatewayService,
    principal: &Principal,
    key: String,
    permission: &str,
    ownership_error: &'static str,
) -> Result<GatewayRecord, ManagementError> {
    if !service
        .access
        .allows(principal, permission, RoleContext::AnyTeam, true)
        .await?
    {
        return Err(ManagementError::Denied);
    }
    let record = lookup(service, principal, key.clone()).await?;
    if record.id != key {
        return Err(ManagementError::NotFound(key));
    }
    let team = record.team_id.as_deref();
    let context = team.map_or(RoleContext::AnyTeam, RoleContext::Team);
    if !service
        .access
        .allows(principal, permission, context, true)
        .await?
    {
        return Err(ManagementError::Denied);
    }
    let owned = record.owner_email.as_deref() == Some(principal.email.as_str())
        || principal.is_global_admin();
    let team_owned = if !owned
        && record.visibility == "team"
        && let Some(team) = team
    {
        service.database.team_owner(&principal.email, team).await?
    } else {
        false
    };
    if !owned && !team_owned {
        return Err(ManagementError::Ownership(ownership_error));
    }
    Ok(record)
}

async fn lookup(
    service: &GatewayService,
    principal: &Principal,
    key: String,
) -> Result<GatewayRecord, ManagementError> {
    let records = service.database.gateway_records(&key).await?;
    let scope = access::catalog_scope(Some(principal));
    let exact = records.iter().any(|record| record.id == key);
    let mut visible = records.into_iter().filter(|record| {
        scope.visible(
            &record.visibility,
            record.team_id.as_deref(),
            record.owner_email.as_deref(),
        )
    });
    match (visible.next(), visible.next()) {
        (Some(record), None) => Ok(record),
        (Some(_), Some(_)) => Err(ManagementError::Conflict(key)),
        _ if exact && principal.visibility != TeamVisibility::Admin => Err(ManagementError::Denied),
        _ => Err(ManagementError::NotFound(key)),
    }
}

async fn check_read(
    service: &GatewayService,
    principal: &Principal,
) -> Result<(), ManagementError> {
    if !service
        .access
        .allows(principal, "gateways.read", RoleContext::AnyTeam, true)
        .await?
    {
        return Err(ManagementError::Denied);
    }
    Ok(())
}

fn flag(value: Option<&str>) -> Result<bool, ManagementError> {
    match value.map(str::to_ascii_lowercase).as_deref() {
        None | Some("false" | "f" | "no" | "n" | "off" | "0") => Ok(false),
        Some("true" | "t" | "yes" | "y" | "on" | "1") => Ok(true),
        _ => Err(ManagementError::Invalid("Invalid gateway query flag")),
    }
}

fn response(record: &GatewayRecord, cipher: Option<&CredentialCipher>) -> Value {
    let mut response = json!(record);
    for key in [
        "createdAt",
        "updatedAt",
        "lastSeen",
        "nextRetryAt",
        "lifecycleClaimedAt",
        "lifecycleClaimExpiresAt",
        "lastRefreshAt",
    ] {
        if let Some(value) = response[key].as_str() {
            response[key] = value.replacen(' ', "T", 1).into();
        }
    }
    response["capabilities"] = json_value(Some(&record.capabilities));
    response["passthroughHeaders"] = json_value(record.passthrough_headers.as_deref());
    response["identityPropagation"] = json_value(record.identity_propagation.as_deref());
    let tags = json_value(Some(&record.tags));
    response["tags"] = json!(
        tags.as_array()
            .into_iter()
            .flatten()
            .map(|tag| {
                if let Some(label) = tag.as_str() {
                    json!({"id":slugify(label),"label":label})
                } else {
                    tag.clone()
                }
            })
            .collect::<Vec<_>>()
    );
    if record.signing_algorithm.is_none() {
        response["signingAlgorithm"] = "ed25519".into();
    }
    response["clientKey"] = json!(record.has_client_key.then_some(MASKED));
    response["skippedTools"] = json!([]);
    response["authValue"] = json!(
        record
            .auth_value
            .as_deref()
            .filter(|raw| !matches!(raw.trim(), "" | "null" | "\"\"" | "{}"))
            .map(|_| MASKED)
    );
    let mut oauth = json_value(record.oauth_config.as_deref());
    if !oauth.is_object() {
        oauth = Value::Null;
    }
    mask_fields(
        &mut oauth,
        &[
            "client_secret",
            "password",
            "refresh_token",
            "access_token",
            "id_token",
            "token",
            "secret",
            "private_key",
        ],
    );
    response["registrationMethod"] = oauth["registration_method"].clone();
    response["oauthConfig"] = oauth;
    let mut sigv4 = json_value(record.sigv4_config.as_deref());
    if !sigv4.is_object() {
        sigv4 = Value::Null;
    }
    mask_fields(&mut sigv4, &["secret_access_key", "session_token"]);
    response["sigv4Config"] = sigv4;
    for key in [
        "authUsername",
        "authPassword",
        "authToken",
        "authHeaderKey",
        "authHeaderValue",
        "authHeaders",
        "authHeadersUnmasked",
        "authTokenUnmasked",
        "authPasswordUnmasked",
        "authHeaderValueUnmasked",
        "authQueryParamKey",
        "authQueryParamValueMasked",
    ] {
        response[key] = Value::Null;
    }
    let query = json_value(record.auth_query_params.as_deref());
    if let Some((key, _)) = query.as_object().and_then(|query| query.iter().next()) {
        response["authQueryParamKey"] = key.as_str().into();
        response["authQueryParamValueMasked"] = MASKED.into();
    }
    if let Some(stored) = &record.auth_value
        && let Ok(headers) = decode_header_values(cipher, stored)
    {
        let authorization = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str());
        match record.auth_type.as_deref() {
            Some("basic") => {
                if let Some(encoded) = authorization.and_then(|value| value.strip_prefix("Basic "))
                    && let Ok(decoded) = BASE64_STANDARD.decode(encoded).map(Zeroizing::new)
                    && let Ok(value) = std::str::from_utf8(&decoded)
                    && let Some((user, _)) = value.split_once(':')
                {
                    response["authUsername"] = user.into();
                    response["authPassword"] = MASKED.into();
                }
            }
            Some("bearer") if authorization.is_some() => response["authToken"] = MASKED.into(),
            Some("authheaders") => {
                if let Some(first) = headers.keys().next() {
                    response["authHeaderKey"] = first.as_str().into();
                    response["authHeaderValue"] = MASKED.into();
                    response["authHeaders"] = json!(
                        headers
                            .keys()
                            .map(|key| json!({"key":key,"value":MASKED}))
                            .collect::<Vec<_>>()
                    );
                }
            }
            _ => {}
        }
    }
    response
}

fn json_value(value: Option<&str>) -> Value {
    value
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or(Value::Null)
}

fn mask_fields(value: &mut Value, sensitive: &[&str]) {
    match value {
        Value::Object(fields) => {
            for (key, item) in fields {
                if sensitive.iter().any(|name| key.eq_ignore_ascii_case(name)) {
                    if !item.is_null() {
                        *item = MASKED.into();
                    }
                } else {
                    mask_fields(item, sensitive);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                mask_fields(item, sensitive);
            }
        }
        _ => {}
    }
}

pub(super) enum ManagementError {
    Invalid(&'static str),
    Denied,
    Ownership(&'static str),
    NotFound(String),
    Conflict(String),
    ConcurrentChange,
    Internal,
}

impl From<sqlx::Error> for ManagementError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "gateway management query failed");
        Self::Internal
    }
}

impl IntoResponse for ManagementError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::Invalid(message) => (StatusCode::UNPROCESSABLE_ENTITY, message.to_owned()),
            Self::Denied => (StatusCode::FORBIDDEN, "Access denied".to_owned()),
            Self::Ownership(message) => (StatusCode::FORBIDDEN, message.to_owned()),
            Self::NotFound(key) => (StatusCode::NOT_FOUND, format!("Gateway not found: {key}")),
            Self::Conflict(key) => (
                StatusCode::CONFLICT,
                format!("Multiple gateways match: {key}"),
            ),
            Self::ConcurrentChange => (
                StatusCode::CONFLICT,
                "Gateway changed during request".to_owned(),
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_owned(),
            ),
        };
        (status, Json(json!({"detail":detail}))).into_response()
    }
}
