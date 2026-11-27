// SPDX-License-Identifier: Apache-2.0

use axum::http::{HeaderValue, Uri, uri::Authority};

use super::*;

const WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";
const INVALID_PATH: &str = "Invalid resource path format. Expected: /.well-known/oauth-protected-resource/servers/{server_id}/mcp";

pub(in crate::gateway) fn router() -> Router<Arc<GatewayService>> {
    Router::new()
        .route(WELL_KNOWN_PATH, get(deprecated_query))
        .route(
            "/.well-known/oauth-protected-resource/{*path}",
            get(protected_resource),
        )
        .route(
            "/servers/{id}/.well-known/oauth-protected-resource",
            get(deprecated_path),
        )
}

async fn protected_resource(
    State(service): State<Arc<GatewayService>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, CatalogApiError> {
    if !service.well_known_enabled {
        return Err(not_found("Not found"));
    }
    let mut segments = path.trim_matches('/').split('/');
    if segments.next() != Some("servers") {
        return Err(not_found(INVALID_PATH));
    }
    let Some(id) = segments.next() else {
        return Err(not_found(INVALID_PATH));
    };
    if !matches!(id.len(), 32 | 36) || Uuid::parse_str(id).is_err() {
        return Err(not_found("Invalid server_id format. Must be a valid UUID."));
    }
    if segments.next().is_some_and(|suffix| suffix != "mcp") || segments.next().is_some() {
        return Err(not_found(INVALID_PATH));
    }
    let record = service
        .database
        .managed_server(id)
        .await?
        .filter(|server| server.enabled && server.visibility == "public")
        .ok_or_else(|| not_found("Server not found"))?;
    if !record.oauth_enabled {
        return Err(not_found(format!("OAuth not enabled for server: {id}")));
    }
    if !record.oauth_config_approved
        || record
            .oauth_config_generation
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err(not_found(format!(
            "OAuth configuration requires administrator approval for server: {id}"
        )));
    }
    let config = record
        .oauth_config
        .as_deref()
        .and_then(|config| serde_json::from_str::<Value>(config).ok())
        .filter(|config| config.as_object().is_some_and(|fields| !fields.is_empty()))
        .ok_or_else(|| not_found(format!("OAuth not configured for server: {id}")))?;
    let issuers = oauth_issuers(&config, service.allow_http_oauth_loopback);
    if issuers.is_empty() {
        return Err(not_found(format!(
            "OAuth authorization_server not configured for server: {id}"
        )));
    }
    let base = request_base(&service.virtual_server_base, &headers, &uri);
    let mut result = json!({
        "resource":format!("{base}/servers/{id}/mcp"),
        "authorization_servers":issuers,
        "bearer_methods_supported":["header"],
    });
    if let Some(scopes) = ["scopes_supported", "scopes"]
        .into_iter()
        .filter_map(|key| config.get(key))
        .find(|scopes| scopes.as_array().is_some_and(|scopes| !scopes.is_empty()))
    {
        result["scopes_supported"] = scopes.clone();
    }
    let mut response = Json(result).into_response();
    let cache = format!("public, max-age={}", service.well_known_max_age);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&cache).expect("valid cache lifetime"),
    );
    Ok(response)
}

async fn deprecated_query(State(service): State<Arc<GatewayService>>) -> CatalogApiError {
    if !service.well_known_enabled {
        return not_found("Not found");
    }
    not_found(
        "This endpoint is deprecated and non-compliant with RFC 9728. Use the path-based endpoint: /.well-known/oauth-protected-resource/servers/{server_id}/mcp",
    )
}

async fn deprecated_path(
    State(service): State<Arc<GatewayService>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, CatalogApiError> {
    if !service.well_known_enabled {
        return Err(not_found("Not found"));
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(not_found("Server not found"));
    }
    let target = HeaderValue::from_str(&resource_metadata_url(
        &service.virtual_server_base,
        &headers,
        &uri,
        &id,
    ))
    .map_err(|_| CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid server URL"))?;
    let mut response = (
        StatusCode::MOVED_PERMANENTLY,
        Json(json!({"detail":"Moved Permanently"})),
    )
        .into_response();
    response.headers_mut().insert(header::LOCATION, target);
    Ok(response)
}

pub(crate) fn resource_metadata_url(
    base: &str,
    headers: &HeaderMap,
    uri: &Uri,
    server: &str,
) -> String {
    let base = request_base(base, headers, uri);
    format!("{base}{WELL_KNOWN_PATH}/servers/{server}/mcp")
}

fn request_base(configured_base: &str, headers: &HeaderMap, uri: &Uri) -> String {
    let authority = headers
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
        .and_then(|host| host.parse::<Authority>().ok());
    let Some(authority) = authority
        .as_ref()
        .or_else(|| uri.authority())
        .filter(|host| !host.as_str().contains('@'))
    else {
        return configured_base.to_owned();
    };
    let scheme = crate::http_boundary::public_scheme(headers, uri);
    let configured = reqwest::Url::parse(configured_base).ok();
    let prefix = configured
        .as_ref()
        .map_or("", |config| config.path().trim_end_matches('/'));
    format!("{scheme}://{authority}{prefix}")
}

pub(crate) fn oauth_issuers(config: &Value, allow_http_loopback: bool) -> Vec<&str> {
    let single = config.get("authorization_server").into_iter();
    let multiple = config
        .get("authorization_servers")
        .and_then(Value::as_array)
        .filter(|issuers| {
            issuers
                .iter()
                .any(|value| value.as_str().is_some_and(|text| !text.trim().is_empty()))
        });
    let values: Box<dyn Iterator<Item = &Value>> = match multiple {
        Some(issuers) => Box::new(issuers.iter()),
        None => Box::new(single),
    };
    values
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|issuer| {
            let Ok(url) = reqwest::Url::parse(issuer) else {
                return false;
            };
            if url.host().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return false;
            }
            match url.scheme() {
                "https" => true,
                "http" if allow_http_loopback => url.host_str().is_some_and(|host| {
                    let host = host.trim_end_matches('.').trim_matches(['[', ']']);
                    matches!(host, "localhost" | "localhost.localdomain")
                        || host
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|address| address.is_loopback())
                }),
                _ => false,
            }
        })
        .collect()
}

fn not_found(message: impl Into<String>) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::NOT_FOUND, message)
}
