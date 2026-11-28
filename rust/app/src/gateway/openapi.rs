// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde_json::Map;
use tokio::{
    sync::{Mutex, OnceCell},
    time::{Instant, timeout},
};

use super::{catalog_api::*, *};
use crate::upstream::read_bounded_body;

const MAX_SPEC_BYTES: usize = 10 * 1024 * 1024;
const MAX_URL_CHARS: usize = 2048;
const CACHE_CAPACITY: usize = 64;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const DOCUMENT_TTL: Duration = Duration::from_secs(60);
const FAILURE_TTL: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
pub(super) struct GenerateRequest {
    url: String,
    #[serde(default = "default_method")]
    request_type: String,
    #[serde(default)]
    openapi_url: String,
}

fn default_method() -> String {
    "GET".into()
}

pub(super) async fn generate_schemas(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<GenerateRequest>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "tools.create", false).await?;
    let tool_url = request.url.trim();
    validate_url_length(tool_url, "Tool URL")
        .map_err(|message| failure(StatusCode::BAD_REQUEST, message))?;
    service
        .upstream
        .check_pinned_endpoint(tool_url)
        .await
        .map_err(|error| {
            failure(
                StatusCode::BAD_REQUEST,
                url_error("Tool URL", tool_url, &error),
            )
        })?;

    let (origin, path) = origin_and_path(tool_url);
    let spec_url = if request.openapi_url.is_empty() {
        format!("{origin}/openapi.json")
    } else {
        request.openapi_url
    };
    let body = service
        .openapi
        .load(&service.upstream, &spec_url)
        .await
        .map_err(FetchError::into_api)?;
    let spec: Value = serde_json::from_slice(&body).map_err(|_| FetchError::NotJson.into_api())?;
    let (input, output) = extract_schemas(&spec, path, &request.request_type)?;
    Ok(Json(json!({
        "message": "Schemas generated successfully from OpenAPI spec",
        "success": true,
        "input_schema": input,
        "output_schema": output,
        "spec_url": spec_url
    })))
}

fn origin_and_path(raw: &str) -> (&str, &str) {
    let authority_start = raw.find("://").expect("validated HTTP URL") + 3;
    let authority_end = raw[authority_start..]
        .find(['/', '?'])
        .map_or(raw.len(), |index| authority_start + index);
    let (origin, remainder) = raw.split_at(authority_end);
    let path = remainder.split('?').next().unwrap_or_default();
    (origin, path)
}

fn extract_schemas<'a>(
    spec: &'a Value,
    path: &str,
    method: &str,
) -> Result<(Option<&'a Value>, Option<&'a Value>), CatalogApiError> {
    let spec = spec.as_object().ok_or_else(unexpected_spec)?;
    let methods = match spec.get("paths") {
        Some(paths) => paths.as_object().ok_or_else(unexpected_spec)?.get(path),
        None => None,
    }
    .ok_or_else(|| {
        failure(
            StatusCode::NOT_FOUND,
            format!("\"Path '{path}' not found in OpenAPI spec\""),
        )
    })?
    .as_object()
    .ok_or_else(unexpected_spec)?;
    let method = method.to_lowercase();
    let operation = methods
        .get(&method)
        .ok_or_else(|| {
            failure(
                StatusCode::NOT_FOUND,
                format!("\"Method '{method}' not found for path '{path}'\""),
            )
        })?
        .as_object()
        .ok_or_else(unexpected_spec)?;
    let components = spec
        .get("components")
        .map(|value| value.as_object().ok_or_else(unexpected_spec))
        .transpose()?
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object);
    let input = operation
        .get("requestBody")
        .and_then(|body| body.pointer("/content/application~1json/schema"));
    let output = operation
        .get("responses")
        .and_then(|responses| responses.get("200").or_else(|| responses.get("201")))
        .and_then(|response| response.pointer("/content/application~1json/schema"));
    Ok((
        resolve_schema(input, components)?,
        resolve_schema(output, components)?,
    ))
}

fn resolve_schema<'a>(
    schema: Option<&'a Value>,
    components: Option<&'a Map<String, Value>>,
) -> Result<Option<&'a Value>, CatalogApiError> {
    let Some(reference) = schema.and_then(|schema| schema.get("$ref")) else {
        return Ok(schema);
    };
    let reference = reference.as_str().ok_or_else(unexpected_spec)?;
    if !reference.starts_with("#/components/schemas/") {
        return Ok(None);
    }
    let name = reference.rsplit('/').next().unwrap_or_default();
    Ok(components.and_then(|components| components.get(name)))
}

fn failure(status: StatusCode, message: impl Into<String>) -> CatalogApiError {
    CatalogApiError(status, json!({"message": message.into(), "success": false}))
}

fn unexpected_spec() -> CatalogApiError {
    failure(
        StatusCode::INTERNAL_SERVER_ERROR,
        "An unexpected error occurred while processing the OpenAPI spec",
    )
}

fn validate_url_length(url: &str, field: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    if url.chars().count() > MAX_URL_CHARS {
        return Err(format!("{field} exceeds maximum length of {MAX_URL_CHARS}"));
    }
    Ok(())
}

fn url_error(field: &str, url: &str, error: &UpstreamError) -> String {
    match error {
        UpstreamError::BlockedDestination => format!("{field} blocked by URL policy"),
        UpstreamError::Resolve => format!("{field} hostname could not be resolved"),
        UpstreamError::Timeout => format!("{field} URL validation timed out"),
        _ if !url.split_once("://").is_some_and(|(scheme, _)| {
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        }) =>
        {
            format!("{field} must start with one of: http://, https://, ws://, wss://")
        }
        _ => format!("{field} is not a valid URL"),
    }
}

#[derive(Clone)]
enum FetchError {
    Policy(String),
    NotJson,
    TooLarge(Option<u64>),
    Http(u16),
    Transport,
}

impl FetchError {
    fn into_api(self) -> CatalogApiError {
        match self {
            Self::Policy(message) => failure(
                StatusCode::BAD_REQUEST,
                format!("Security validation failed: {message}"),
            ),
            Self::NotJson => failure(
                StatusCode::BAD_REQUEST,
                "Security validation failed: Response is not valid JSON. Ensure the URL points to a JSON OpenAPI specification.",
            ),
            Self::TooLarge(length) => {
                let detail = length.map_or_else(
                    || format!(">{MAX_SPEC_BYTES} bytes"),
                    |length| format!("{length} bytes, max {MAX_SPEC_BYTES}"),
                );
                failure(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Security validation failed: OpenAPI spec response too large ({detail})"
                    ),
                )
            }
            Self::Http(status) => failure(
                StatusCode::BAD_GATEWAY,
                format!("OpenAPI spec server returned HTTP {status}"),
            ),
            Self::Transport => failure(
                StatusCode::BAD_GATEWAY,
                "Failed to fetch OpenAPI spec from the provided URL",
            ),
        }
    }
}

type Document = Result<Arc<Vec<u8>>, FetchError>;

#[derive(Default)]
pub(super) struct Documents {
    entries: Mutex<HashMap<String, Entry>>,
}

struct Entry {
    last_access: Instant,
    document: Arc<OnceCell<Downloaded>>,
}

struct Downloaded {
    result: Document,
    expires_at: Instant,
}

impl Documents {
    async fn load(&self, upstream: &UpstreamClient, url: &str) -> Document {
        validate_url_length(url, "OpenAPI spec URL").map_err(FetchError::Policy)?;
        let cell = {
            let mut entries = self.entries.lock().await;
            let now = Instant::now();
            entries.retain(|_, entry| match entry.document.get() {
                Some(download) => download.expires_at > now,
                None => Arc::strong_count(&entry.document) > 1,
            });
            if let Some(entry) = entries.get_mut(url) {
                entry.last_access = now;
                Arc::clone(&entry.document)
            } else {
                if entries.len() >= CACHE_CAPACITY {
                    let expired = entries
                        .iter()
                        .filter(|(_, entry)| entry.document.get().is_some())
                        .min_by_key(|(_, entry)| entry.last_access)
                        .map(|(key, _)| key.clone())
                        .ok_or(FetchError::Transport)?;
                    entries.remove(&expired);
                }
                let document = Arc::new(OnceCell::new());
                entries.insert(
                    url.to_owned(),
                    Entry {
                        last_access: now,
                        document: Arc::clone(&document),
                    },
                );
                document
            }
        };
        let download = cell
            .get_or_init(|| async {
                let result = timeout(FETCH_TIMEOUT, fetch(upstream, url))
                    .await
                    .unwrap_or(Err(FetchError::Transport));
                let ttl = if result.is_ok() {
                    DOCUMENT_TTL
                } else {
                    FAILURE_TTL
                };
                Downloaded {
                    result,
                    expires_at: Instant::now() + ttl,
                }
            })
            .await;
        download.result.clone()
    }
}

async fn fetch(upstream: &UpstreamClient, endpoint: &str) -> Document {
    let (client, url) = upstream
        .pinned_client(endpoint, None)
        .await
        .map_err(|error| FetchError::Policy(url_error("OpenAPI spec URL", endpoint, &error)))?;
    let request = client.get(url).build().map_err(|_| FetchError::Transport)?;
    let response = crate::observability::telemetry::client::execute(&client, request)
        .await
        .map_err(|_| FetchError::Transport)?;
    if !response.status().is_success() {
        return Err(FetchError::Http(response.status().as_u16()));
    }
    if let Some(length) = response.content_length()
        && length > MAX_SPEC_BYTES as u64
    {
        return Err(FetchError::TooLarge(Some(length)));
    }
    let body = read_bounded_body(response, MAX_SPEC_BYTES)
        .await
        .map_err(|error| match error {
            UpstreamError::LimitExceeded => FetchError::TooLarge(None),
            _ => FetchError::Transport,
        })?;
    serde_json::from_slice::<serde::de::IgnoredAny>(&body).map_err(|_| FetchError::NotJson)?;
    Ok(Arc::new(body))
}
