// SPDX-License-Identifier: Apache-2.0

use axum::extract::{Path, Query};

use super::{catalog_api::*, *};
use crate::catalog::{ExecutionMetrics, MetricEntity, ServerLinks, ServerRecord};

mod handshake;
pub(super) use handshake::HandshakeProbe;
mod oauth;
mod write;
pub(super) use oauth::router as well_known_router;
pub(crate) use oauth::{oauth_issuers, resource_metadata_url};
pub(super) use write::{
    change_state, create_record, editable, import_server, remove, update_record,
};

pub(super) fn router() -> Router<Arc<GatewayService>> {
    let mut routes = Router::new();
    for base in ["/servers", "/v1/servers", "/v1/virtual-servers"] {
        routes = routes
            .route(base, get(list).post(write::create))
            .route(&format!("{base}/"), get(list).post(write::create))
            .route(
                &format!("{base}/{{id}}"),
                get(detail).put(write::update).delete(write::delete),
            )
            .route(&format!("{base}/{{id}}/state"), post(write::set_state))
            .route(&format!("{base}/{{id}}/toggle"), post(write::set_state))
            .route(
                &format!("{base}/{{id}}/oauth/approve"),
                post(write::approve),
            )
            .route(
                &format!("{base}/{{id}}/test-handshake"),
                post(handshake::test),
            )
            .route(&format!("{base}/{{id}}/{{kind}}"), get(associated));
    }
    routes
}

async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(mut query): Query<CatalogListQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "servers.read", true).await?;
    query.gateway_id = None;
    query.mcp_server_id = None;
    let page = CatalogPage::prepare(&service, &principal, &query, "rest/servers")?;
    let scope = access::catalog_scope(Some(&principal));
    let rows = service
        .database
        .managed_servers(scope, page.filters())
        .await?;
    let ids = rows
        .iter()
        .map(|server| server.id.as_str())
        .collect::<Vec<_>>();
    let links = service.database.managed_server_links(&ids, scope).await?;
    let default = ServerLinks::default();
    let mut response = page.envelope(
        &service,
        rows,
        "servers",
        |row| (&row.created_at, &row.id),
        |server| metadata(&service, server, links.get(&server.id).unwrap_or(&default)),
    )?;
    if flag(query.include_metrics.as_deref())? {
        let rows = if response.is_array() {
            &mut response
        } else {
            &mut response["servers"]
        };
        if let Some(rows) = rows.as_array_mut() {
            include_metrics(&service, MetricEntity::Server, rows).await?;
        }
    }
    Ok(Json(response))
}

async fn detail(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "servers.read", true).await?;
    let server = find_visible(&service, &principal, &id).await?;
    Ok(Json(with_links(&service, &principal, &server).await?))
}

#[derive(Deserialize)]
struct AssociatedQuery {
    include_inactive: Option<String>,
    include_metrics: Option<String>,
}

async fn associated(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path((id, kind)): Path<(String, String)>,
    Query(query): Query<AssociatedQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    if !matches!(kind.as_str(), "tools" | "resources" | "prompts") {
        return Err(CatalogApiError::detail(StatusCode::NOT_FOUND, "Not Found"));
    }
    require_catalog_permission(&service, &principal, "servers.read", true).await?;
    let server = find_visible(&service, &principal, &id).await?;
    let inactive = flag(query.include_inactive.as_deref())?;
    let scope = access::catalog_scope(Some(&principal));
    let (entity, mut rows) = match kind.as_str() {
        "tools" => {
            let tools = service
                .database
                .managed_server_tools(scope, &server.id, inactive)
                .await?;
            let mut entries = Vec::with_capacity(tools.len());
            for tool in tools {
                let owner = if scope.can_own()
                    && tool.visibility == "team"
                    && !tool_api::can_view_headers(&principal, &tool, false)
                    && let Some(team) = tool.team_id.as_deref()
                {
                    service.database.team_owner(&principal.email, team).await?
                } else {
                    false
                };
                let headers = tool_api::can_view_headers(&principal, &tool, owner);
                entries.push(tool_api::metadata(&service, &tool, true, false, headers));
            }
            (MetricEntity::Tool, entries)
        }
        "resources" => (
            MetricEntity::Resource,
            service
                .database
                .managed_server_resources(scope, &server.id, inactive)
                .await?
                .iter()
                .map(|row| resource_api::metadata(row, true))
                .collect(),
        ),
        "prompts" => (
            MetricEntity::Prompt,
            service
                .database
                .managed_server_prompts(scope, &server.id, inactive)
                .await?
                .iter()
                .map(|row| prompt_api::metadata(row, true))
                .collect(),
        ),
        _ => unreachable!("server association validated"),
    };
    if flag(query.include_metrics.as_deref())? {
        include_metrics(&service, entity, &mut rows).await?;
    }
    Ok(Json(Value::Array(rows)))
}

async fn include_metrics(
    service: &GatewayService,
    entity: MetricEntity,
    rows: &mut [Value],
) -> Result<(), CatalogApiError> {
    let ids = rows
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect::<Vec<_>>();
    let metrics = service.database.execution_metrics(entity, &ids).await?;
    let empty = ExecutionMetrics::default();
    for row in rows {
        let result = row["id"]
            .as_str()
            .and_then(|id| metrics.get(id))
            .unwrap_or(&empty)
            .json();
        if matches!(entity, MetricEntity::Tool) {
            row["executionCount"] = result["totalExecutions"].clone();
        }
        row["metrics"] = result;
    }
    Ok(())
}

async fn find_visible(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
) -> Result<ServerRecord, CatalogApiError> {
    let scope = access::catalog_scope(Some(principal));
    let server = service
        .database
        .managed_server(id)
        .await?
        .ok_or_else(|| missing(id))?;
    if !server.is_visible(scope) {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    Ok(server)
}

pub(super) async fn with_links(
    service: &GatewayService,
    principal: &Principal,
    server: &ServerRecord,
) -> Result<Value, CatalogApiError> {
    let scope = access::catalog_scope(Some(principal));
    let links = service
        .database
        .managed_server_links(&[&server.id], scope)
        .await?
        .remove(&server.id)
        .unwrap_or_default();
    Ok(metadata(service, server, &links))
}

pub(super) fn metadata(
    service: &GatewayService,
    server: &ServerRecord,
    links: &ServerLinks,
) -> Value {
    let mut response = json!(server);
    response["created_at"] = server.created_at.replacen(' ', "T", 1).into();
    response["updated_at"] = server.updated_at.replacen(' ', "T", 1).into();
    response["url"] = format!("{}/servers/{}/mcp", service.virtual_server_base, server.id).into();
    response["associated_tools"] =
        json!(links.tools.iter().map(|(_, name)| name).collect::<Vec<_>>());
    response["associated_tool_ids"] =
        json!(links.tools.iter().map(|(id, _)| id).collect::<Vec<_>>());
    response["associated_resources"] = json!(links.resources);
    response["associated_prompts"] = json!(links.prompts);
    response["associated_a2a_agents"] = json!(links.agents);
    response["interfaces"] = json!(
        links
            .interfaces
            .iter()
            .map(|interface| {
                let mut response = json!(interface);
                response["created_at"] = interface.created_at.replacen(' ', "T", 1).into();
                response["updated_at"] = interface.updated_at.replacen(' ', "T", 1).into();
                response["config"] = interface
                    .config
                    .as_deref()
                    .and_then(|encoded| serde_json::from_str(encoded).ok())
                    .unwrap_or_default();
                response
            })
            .collect::<Vec<_>>()
    );
    response["metrics"] = Value::Null;
    response["tags"] = serde_json::from_str(&server.tags).unwrap_or_else(|_| json!([]));
    let mut oauth = server
        .oauth_config
        .as_deref()
        .and_then(|encoded| serde_json::from_str(encoded).ok())
        .unwrap_or_default();
    mask_oauth_fields(&mut oauth);
    response["oauth_config"] = oauth;
    camelcase_fields(response)
}

pub(super) fn mask_oauth_fields(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                if is_oauth_secret(name) && !value.is_null() && value.as_str() != Some("") {
                    *value = "*****".into();
                } else {
                    mask_oauth_fields(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(mask_oauth_fields),
        _ => {}
    }
}

fn is_oauth_secret(name: &str) -> bool {
    [
        "client_secret",
        "private_key",
        "refresh_token",
        "access_token",
        "password",
        "token",
        "id_token",
        "secret",
    ]
    .into_iter()
    .any(|key| name.eq_ignore_ascii_case(key))
}

fn missing(id: &str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::NOT_FOUND, format!("Server not found: {id}"))
}
