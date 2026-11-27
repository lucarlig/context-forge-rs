// SPDX-License-Identifier: Apache-2.0

use axum::extract::{DefaultBodyLimit, Path, Query};
use rmcp::model::{ReadResourceRequest, ReadResourceRequestParams};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::catalog::{ResourceContentRecord, ResourceFilters, ResourceRecord};

mod write;
pub use write::ResourceLimits;

pub(super) fn router(max_resource_bytes: usize) -> Router<Arc<GatewayService>> {
    let mut routes = Router::new();
    for base in ["/resources", "/v1/resources"] {
        routes = routes
            .route(base, get(list).post(write::create))
            .route(&format!("{base}/"), get(list).post(write::create))
            .route(&format!("{base}/templates/list"), get(templates))
            .route(&format!("{base}/test/{{*uri}}"), get(test_uri))
            .route(&format!("{base}/{{id}}/info"), get(info))
            .route(
                &format!("{base}/{{id}}"),
                get(read).put(write::update).delete(write::delete),
            )
            .route(&format!("{base}/{{id}}/state"), post(write::set_state))
            .route(&format!("{base}/{{id}}/toggle"), post(write::set_state));
    }
    routes.layer(DefaultBodyLimit::max(
        max_resource_bytes.saturating_mul(6).saturating_add(65536),
    ))
}

#[derive(Default, Deserialize)]
struct ResourceQuery {
    include_inactive: Option<String>,
    include_pagination: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
    tags: Option<String>,
    visibility: Option<String>,
    team_id: Option<String>,
    gateway_id: Option<String>,
    mcp_server_id: Option<String>,
}

impl ResourceQuery {
    fn gateway_filter(&self) -> Result<Option<&str>, ResourceError> {
        let gateway = self.gateway_id.as_deref();
        let alias = self.mcp_server_id.as_deref();
        if gateway
            .zip(alias)
            .is_some_and(|(gateway, alias)| gateway != alias)
        {
            return Err(ResourceError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "gateway_id and mcp_server_id conflict",
            ));
        }
        Ok(gateway.or(alias))
    }

    fn tags(&self) -> Vec<String> {
        let mut tags = self
            .tags
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        tags.sort_unstable();
        tags.dedup();
        tags
    }
}

async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<Value>, ResourceError> {
    require_resources(&service, &principal, "resources.read", true).await?;
    let include_inactive = flag(query.include_inactive.as_deref())?;
    let include_pagination = flag(query.include_pagination.as_deref())?;
    let gateway = query.gateway_filter()?;
    let team = query.team_id.as_deref();
    if let (TeamVisibility::Teams(allowed), Some(team)) = (&principal.visibility, team)
        && !allowed.iter().any(|id| id == team)
    {
        return Err(ResourceError(
            StatusCode::FORBIDDEN,
            json!({
                "message":"Access issue: This API token does not have the required permissions for this team."
            }),
        ));
    }
    let tags = query.tags();
    let limit = match query.limit {
        Some(0) => None,
        Some(limit) if limit > 0 => Some(limit.min(i64::from(service.management_max_page_size))),
        Some(_) => {
            return Err(ResourceError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid limit",
            ));
        }
        None => Some(i64::from(service.management_page_size)),
    };
    let fingerprint = Sha256::digest(
        json!([
            list_fingerprint("rest/resources", Some(&principal), None),
            include_inactive,
            &tags,
            team,
            gateway,
            &query.visibility,
        ])
        .to_string()
        .as_bytes(),
    )
    .into();
    let cursor = query
        .cursor
        .as_deref()
        .and_then(|value| service.pagination.decode(value, &fingerprint).ok())
        .and_then(|cursor| serde_json::from_str::<(String, String)>(&cursor.after_id).ok());
    let mut rows = service
        .database
        .managed_resources(
            access::catalog_scope(Some(&principal)),
            ResourceFilters {
                templates: false,
                include_inactive,
                visibility: query.visibility.as_deref(),
                team,
                gateway,
                after: cursor
                    .as_ref()
                    .map(|(created, id)| (created.as_str(), id.as_str())),
                limit: limit.map_or(i64::MAX, |limit| limit + 1),
                tags: &tags,
            },
        )
        .await?;
    let mut next_cursor = None;
    if let Some(limit) = limit
        && rows.len() as i64 > limit
    {
        rows.truncate(limit as usize);
        if include_pagination && let Some(last) = rows.last() {
            let position = json!([last.created_at, last.id]).to_string();
            let expires = Timestamp::now()
                .as_second()
                .saturating_add(service.pagination.ttl);
            next_cursor = Some(
                service
                    .pagination
                    .encode(position, fingerprint, expires)
                    .map_err(|_| ResourceError::unavailable())?,
            );
        }
    }
    let resources = rows
        .iter()
        .map(|resource| metadata(resource, true))
        .collect::<Vec<_>>();
    Ok(Json(if include_pagination {
        json!({"resources":resources,"nextCursor":next_cursor})
    } else {
        json!(resources)
    }))
}

async fn templates(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<Value>, ResourceError> {
    require_resources(&service, &principal, "resources.read", true).await?;
    let tags = query.tags();
    let records = service
        .database
        .managed_resources(
            access::catalog_scope(Some(&principal)),
            ResourceFilters {
                templates: true,
                include_inactive: flag(query.include_inactive.as_deref())?,
                visibility: query.visibility.as_deref(),
                team: None,
                gateway: None,
                after: None,
                limit: i64::MAX,
                tags: &tags,
            },
        )
        .await?;
    let templates = records.into_iter().map(|resource| json!({
        "_meta":null,"annotations":null,"id":resource.id,"name":resource.name,
        "uriTemplate":resource.uri_template,"description":resource.description,"mimeType":resource.mime_type,
    })).collect::<Vec<_>>();
    Ok(Json(
        json!({"_meta":{},"next_cursor":null,"resource_templates":templates}),
    ))
}

async fn info(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<Value>, ResourceError> {
    require_resources(&service, &principal, "resources.read", true).await?;
    let resource = find_visible(
        &service,
        &principal,
        &id,
        flag(query.include_inactive.as_deref())?,
    )
    .await?;
    Ok(Json(metadata(&resource, true)))
}

async fn read(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ResourceError> {
    require_resources(&service, &principal, "resources.read", true).await?;
    let record = service
        .database
        .resource_content_by_id(access::catalog_scope(Some(&principal)), &id)
        .await?
        .ok_or_else(|| ResourceError::missing(&id))?;
    let uri = record.uri.clone();
    Ok(Json(
        resource_content(&service, &principal, record, uri, &headers, false).await?,
    ))
}

async fn test_uri(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(uri): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ResourceError> {
    require_resources(&service, &principal, "resources.read", false).await?;
    let record = service
        .database
        .resource_content(access::catalog_scope(Some(&principal)), None, &uri)
        .await?
        .ok_or_else(|| ResourceError::missing(&uri))?;
    let content = resource_content(&service, &principal, record, uri, &headers, true).await?;
    Ok(Json(json!({"content":content})))
}

async fn resource_content(
    service: &GatewayService,
    principal: &Principal,
    mut record: ResourceContentRecord,
    uri: String,
    headers: &HeaderMap,
    aliases: bool,
) -> Result<Value, ResourceError> {
    let id = record.id.clone();
    let mime = record.mime.clone();
    let contents = if let Some(gateway) = record.gateway.take() {
        let cancellation = CancellationToken::new();
        let reply = service
            .request_content(
                &gateway,
                ReadResourceRequest::new(ReadResourceRequestParams::new(uri.clone())).into(),
                Some(principal),
                ToolContext {
                    cancellation: &cancellation,
                    progress: None,
                    notifications: None,
                    client_capabilities: None,
                    request_headers: Some(headers),
                },
                None,
                None,
            )
            .await
            .map_err(|error| ResourceError::detail(StatusCode::BAD_REQUEST, error.message))?;
        reply
            .get("contents")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .cloned()
            .ok_or_else(|| {
                ResourceError::detail(
                    StatusCode::BAD_REQUEST,
                    "Upstream returned no resource content",
                )
            })?
    } else {
        json!(content::local_resource(record, uri.clone()))
    };
    let mut envelope = json!({"type":"resource","id":id,"uri":uri,"text":contents["text"],"blob":contents["blob"]});
    let mime = contents
        .get("mimeType")
        .cloned()
        .unwrap_or_else(|| json!(mime));
    if aliases {
        envelope["mimeType"] = mime;
        envelope["_meta"] = contents["_meta"].clone();
    } else {
        envelope["mime_type"] = mime;
        if !contents["_meta"].is_null() {
            envelope["meta"] = contents["_meta"].clone();
        }
    }
    Ok(envelope)
}

async fn require_resources(
    service: &GatewayService,
    principal: &Principal,
    permission: &str,
    bypass: bool,
) -> Result<(), ResourceError> {
    if !service
        .access
        .allows(principal, permission, RoleContext::AnyTeam, bypass)
        .await?
    {
        return Err(ResourceError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    Ok(())
}

async fn find_visible(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
    inactive: bool,
) -> Result<ResourceRecord, ResourceError> {
    let record = service
        .database
        .managed_resource(id)
        .await?
        .filter(|record| {
            access::catalog_scope(Some(principal)).visible(
                &record.visibility,
                record.team_id.as_deref(),
                record.owner_email.as_deref(),
            )
        })
        .ok_or_else(|| ResourceError::missing(id))?;
    if !record.enabled && !inactive {
        return Err(ResourceError::detail(
            StatusCode::NOT_FOUND,
            format!("Resource '{id}' exists but is inactive"),
        ));
    }
    Ok(record)
}

fn flag(input: Option<&str>) -> Result<bool, ResourceError> {
    match input.map(str::to_ascii_lowercase).as_deref() {
        None | Some("0" | "false" | "f" | "off" | "n" | "no") => Ok(false),
        Some("1" | "true" | "t" | "on" | "y" | "yes") => Ok(true),
        _ => Err(ResourceError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid boolean query parameter",
        )),
    }
}

fn metadata(record: &ResourceRecord, aliases: bool) -> Value {
    let mut response = json!(record);
    response["created_at"] = record.created_at.replacen(' ', "T", 1).into();
    response["updated_at"] = record.updated_at.replacen(' ', "T", 1).into();
    response["mcp_server_id"] = json!(record.gateway_id);
    let tags = serde_json::from_str::<Vec<Value>>(&record.tags).unwrap_or_default();
    response["tags"] = json!(
        tags.iter()
            .filter_map(|tag| tag
                .as_str()
                .or_else(|| tag["label"].as_str())
                .or_else(|| tag["name"].as_str()))
            .collect::<Vec<_>>()
    );
    response["extension_metadata"] = record
        .extension_metadata
        .as_deref()
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or(Value::Null);
    response["annotations"] = Value::Null;
    response["metrics"] = Value::Null;
    if !aliases {
        response["meta"] = Value::Null;
        return response;
    }
    let Value::Object(response) = response else {
        unreachable!()
    };
    let mut aliased: serde_json::Map<_, _> = response
        .into_iter()
        .map(|(key, value)| {
            let mut pieces = key.split('_');
            let mut camel = pieces.next().unwrap_or_default().to_owned();
            for piece in pieces {
                let mut characters = piece.chars();
                if let Some(first) = characters.next() {
                    camel.extend(first.to_uppercase());
                    camel.push_str(characters.as_str());
                }
            }
            (camel, value)
        })
        .collect();
    aliased.insert("_meta".to_owned(), Value::Null);
    Value::Object(aliased)
}

struct ResourceError(StatusCode, Value);

impl ResourceError {
    fn detail(status: StatusCode, detail: impl Into<String>) -> Self {
        Self(status, json!({"detail":detail.into()}))
    }

    fn missing(id: &str) -> Self {
        Self::detail(StatusCode::NOT_FOUND, format!("Resource not found: {id}"))
    }

    fn unavailable() -> Self {
        Self::detail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Resource service unavailable",
        )
    }
}

impl From<sqlx::Error> for ResourceError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "resource registry query failed");
        Self::unavailable()
    }
}

impl IntoResponse for ResourceError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}
