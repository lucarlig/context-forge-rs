// SPDX-License-Identifier: Apache-2.0

mod flow;
mod storage;
mod token_access;

pub(super) use token_access::{TokenTarget, authorization_header};

use std::collections::BTreeSet;

use axum::extract::{OriginalUri, Path, Query};
use jiff::Timestamp;
use serde_json::Map;

use super::{catalog_api::CatalogApiError, *};

const MAX_STATUS_GATEWAYS: usize = 100;

pub struct GatewayOAuthSettings {
    pub(crate) redirect_uri: String,
    pub(crate) callback_path: String,
    pub(crate) browser_origin: String,
    pub(crate) secure_cookies: bool,
    pub(crate) token_retrieval: bool,
    pub(crate) refresh_threshold: i64,
}

impl Default for GatewayOAuthSettings {
    fn default() -> Self {
        Self {
            redirect_uri: "http://localhost:4444/oauth/callback".to_owned(),
            callback_path: "/oauth/callback".to_owned(),
            browser_origin: "http://localhost:4444".to_owned(),
            secure_cookies: true,
            token_retrieval: false,
            refresh_threshold: 600,
        }
    }
}

pub(super) fn router() -> Router<Arc<GatewayService>> {
    Router::new()
        .route("/oauth/status", get(status_batch))
        .route("/oauth/status/{id}", get(status))
        .route("/oauth/authorize/{id}", get(flow::authorize))
        .route("/oauth/token/{id}", get(token_access::token))
        .route("/oauth/fetch-tools/{id}", post(fetch_tools))
}

pub(super) fn callback_router() -> Router<Arc<GatewayService>> {
    Router::new().route("/oauth/callback", get(flow::callback))
}

async fn fetch_tools(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match visible_gateway(&service, &principal, &id).await {
        Ok(gateway) if gateway.oauth_config.is_some() => {}
        Ok(_) => {
            return CatalogApiError::detail(StatusCode::BAD_REQUEST, "Failed to fetch tools")
                .into_response();
        }
        Err(error) => return error.into_response(),
    }
    let response = super::management::refresh(
        State(service.clone()),
        Extension(principal),
        Path(id.clone()),
        Query(super::management::RefreshParameters::default()),
        headers,
    )
    .await;
    match response {
        Ok(Json(value)) if value["success"] == true => {
            let count = match service.database.gateway_records(&id).await {
                Ok(rows) => match rows.into_iter().find(|row| row.id == id) {
                    Some(row) => row.tool_count,
                    None => {
                        return CatalogApiError::detail(StatusCode::NOT_FOUND, "Gateway not found")
                            .into_response();
                    }
                },
                Err(error) => return CatalogApiError::from(error).into_response(),
            };
            Json(json!({"success":true,"message":format!("Successfully fetched and created {count} tools")})).into_response()
        }
        Ok(_) => CatalogApiError::detail(StatusCode::BAD_REQUEST, "Failed to fetch tools")
            .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn status(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    check_read(&service, &principal).await?;
    let gateway = visible_gateway(&service, &principal, &id).await?;
    let mut payload = status_payload(&gateway);
    if payload["grant_type"] == "authorization_code" {
        attach_status(&service, &principal, &mut payload, &id).await;
    }
    Ok(Json(payload))
}

async fn status_batch(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, CatalogApiError> {
    check_read(&service, &principal).await?;
    let mut ids = BTreeSet::new();
    for (name, value) in url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()) {
        if name == "gateway_ids" {
            ids.insert(value.into_owned());
            if ids.len() > MAX_STATUS_GATEWAYS {
                return Err(CatalogApiError::detail(
                    StatusCode::BAD_REQUEST,
                    format!("Too many gateway_ids requested (max {MAX_STATUS_GATEWAYS})"),
                ));
            }
        }
    }
    if ids.is_empty() {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "gateway_ids is required",
        ));
    }
    let ids: Vec<String> = ids.into_iter().collect();
    let gateways = service.database.oauth_gateways(&ids).await?;
    let mut results = Map::new();
    let mut token_ids = Vec::new();
    for gateway in gateways
        .into_iter()
        .filter(|gateway| gateway.visible(&principal))
    {
        let payload = status_payload(&gateway);
        if payload["grant_type"] == "authorization_code" {
            token_ids.push(gateway.id.clone());
        }
        results.insert(gateway.id, payload);
    }
    if token_ids.is_empty() {
        return Ok(Json(Value::Object(results)));
    }
    let rows = tokio::time::timeout(
        Duration::from_secs(15),
        service
            .database
            .oauth_statuses(&principal.email, &token_ids),
    )
    .await;
    let now = Timestamp::now();
    for id in token_ids {
        let status = match &rows {
            Ok(Ok(rows)) => rows
                .get(&id)
                .map_or_else(missing_token, |token| token.metadata(now)),
            _ => unknown_token(),
        };
        if let Some(payload) = results.get_mut(&id) {
            payload["user_token_status"] = status;
        }
    }
    Ok(Json(Value::Object(results)))
}

async fn attach_status(
    service: &GatewayService,
    principal: &Principal,
    payload: &mut Value,
    id: &str,
) {
    let result = service
        .database
        .oauth_statuses(&principal.email, &[id.to_owned()])
        .await;
    payload["user_token_status"] = match result {
        Ok(tokens) => tokens
            .get(id)
            .map_or_else(missing_token, |token| token.metadata(Timestamp::now())),
        Err(_) => unknown_token(),
    };
}

async fn visible_gateway(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
) -> Result<storage::OAuthGateway, CatalogApiError> {
    let mut matches = service.database.oauth_gateways(&[id.to_owned()]).await?;
    let gateway = matches
        .pop()
        .ok_or_else(|| CatalogApiError::detail(StatusCode::NOT_FOUND, "Gateway not found"))?;
    if !gateway.visible(principal) {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "You don't have access to this gateway",
        ));
    }
    Ok(gateway)
}

async fn check_read(
    service: &GatewayService,
    principal: &Principal,
) -> Result<(), CatalogApiError> {
    if !service
        .access
        .allows(principal, "gateways.read", RoleContext::AnyTeam, true)
        .await?
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    Ok(())
}

fn status_payload(gateway: &storage::OAuthGateway) -> Value {
    let config = gateway
        .oauth_config
        .as_deref()
        .and_then(|encoded| serde_json::from_str::<Value>(encoded).ok())
        .filter(|config| config.as_object().is_some_and(|object| !object.is_empty()));
    let Some(config) = config else {
        return json!({"oauth_enabled":false,"message":"Gateway is not configured for OAuth"});
    };
    let grant = config["grant_type"].as_str();
    let mut payload = json!({
        "oauth_enabled":true,"grant_type":config["grant_type"],"client_id":config["client_id"],
        "scopes":config.get("scopes").cloned().unwrap_or_else(||json!([])),
    });
    payload["message"] = if grant == Some("authorization_code") {
        payload["authorization_url"] = config["authorization_url"].clone();
        payload["redirect_uri"] = config["redirect_uri"].clone();
        "Gateway configured for Authorization Code flow".into()
    } else {
        format!("Gateway configured for {} flow", grant.unwrap_or("None")).into()
    };
    payload
}

fn missing_token() -> Value {
    json!({"status":"missing","authorized":false})
}

fn unknown_token() -> Value {
    json!({"status":"unknown","authorized":false})
}

fn parse_time(text: &str) -> Option<Timestamp> {
    let iso = text.replacen(' ', "T", 1);
    iso.parse().or_else(|_| format!("{iso}Z").parse()).ok()
}

pub(super) fn requires_user(encoded: &str) -> bool {
    serde_json::from_str::<Value>(encoded)
        .ok()
        .is_some_and(|value| value["grant_type"] == "authorization_code")
}

fn resource_origin(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .map(|url| url.origin().ascii_serialization())
}
