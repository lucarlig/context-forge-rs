// SPDX-License-Identifier: Apache-2.0

use axum::extract::{DefaultBodyLimit, Path, Query};
use rmcp::model::{ReadResourceRequest, ReadResourceRequestParams};
use tokio_util::sync::CancellationToken;

use super::{
    catalog_api::{
        CatalogApiError as ResourceError, CatalogListQuery, CatalogPage, alias_metadata, flag,
        http_server_id, require_catalog_permission,
    },
    *,
};
use crate::catalog::{CatalogEntryFilters, ResourceContentRecord, ResourceRecord};

mod events;
mod write;
pub(crate) use events::ResourceEvents;
pub use write::ResourceLimits;
pub(super) use write::import_resource;

pub(super) fn router(max_resource_bytes: usize) -> Router<Arc<GatewayService>> {
    let mut routes = Router::new();
    for base in ["/resources", "/v1/resources"] {
        routes = routes
            .route(base, get(list).post(write::create))
            .route(&format!("{base}/"), get(list).post(write::create))
            .route(&format!("{base}/templates/list"), get(templates))
            .route(&format!("{base}/subscribe"), post(events::subscribe))
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

async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<CatalogListQuery>,
) -> Result<Json<Value>, ResourceError> {
    require_catalog_permission(&service, &principal, "resources.read", true).await?;
    let page = CatalogPage::prepare(&service, &principal, &query, "rest/resources")?;
    let rows = service
        .database
        .managed_resources(
            access::catalog_scope(Some(&principal)),
            page.filters(),
            false,
        )
        .await?;
    Ok(Json(page.envelope(
        &service,
        rows,
        "resources",
        |row| (&row.created_at, &row.id),
        |row| metadata(row, true),
    )?))
}

async fn templates(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<CatalogListQuery>,
) -> Result<Json<Value>, ResourceError> {
    require_catalog_permission(&service, &principal, "resources.read", true).await?;
    let tags = query.tags();
    let records = service
        .database
        .managed_resources(
            access::catalog_scope(Some(&principal)),
            CatalogEntryFilters {
                include_inactive: flag(query.include_inactive.as_deref())?,
                visibility: query.visibility.as_deref(),
                team: None,
                gateway: None,
                after: None,
                limit: i64::MAX,
                tags: &tags,
            },
            true,
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
    Query(query): Query<CatalogListQuery>,
) -> Result<Json<Value>, ResourceError> {
    require_catalog_permission(&service, &principal, "resources.read", true).await?;
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
    require_catalog_permission(&service, &principal, "resources.read", true).await?;
    let server = headers
        .get("x-server-id")
        .map(http_server_id)
        .transpose()?
        .filter(|value| !value.is_empty());
    let record = service
        .database
        .resource_content_by_id(access::catalog_scope(Some(&principal)), server, &id)
        .await?
        .ok_or_else(|| missing_resource(&id))?;
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
    require_catalog_permission(&service, &principal, "resources.read", false).await?;
    let record = service
        .database
        .resource_content(access::catalog_scope(Some(&principal)), None, &uri)
        .await?
        .ok_or_else(|| missing_resource(&uri))?;
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
        .ok_or_else(|| missing_resource(id))?;
    if !record.enabled && !inactive {
        return Err(ResourceError::detail(
            StatusCode::NOT_FOUND,
            format!("Resource '{id}' exists but is inactive"),
        ));
    }
    Ok(record)
}

pub(super) fn metadata(record: &ResourceRecord, aliases: bool) -> Value {
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
    alias_metadata(response)
}

fn missing_resource(id: &str) -> ResourceError {
    ResourceError::detail(StatusCode::NOT_FOUND, format!("Resource not found: {id}"))
}
