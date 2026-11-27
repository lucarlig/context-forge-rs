// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use axum::extract::{Path, Query};
use sqlx::types::Json as DbJson;

use super::{catalog_api::*, *};
use crate::grpc::{self, Discovery, GrpcError, GrpcTarget};

mod registry;
use registry::{ServiceChange, ServiceWriteError};

pub(super) fn router() -> Router<Arc<GatewayService>> {
    Router::new()
        .route("/admin/grpc", get(list).post(register))
        .route("/admin/grpc/{id}", get(detail).put(update))
        .route("/admin/grpc/{id}/methods", get(methods))
        .route("/admin/grpc/{id}/state", post(set_state))
        .route("/admin/grpc/{id}/reflect", post(reflect))
        .route("/admin/grpc/{id}/delete", post(delete))
}

#[derive(Deserialize, Serialize, sqlx::FromRow)]
struct ServiceConfig {
    name: String,
    target: String,
    description: Option<String>,
    #[serde(default = "enabled")]
    reflection_enabled: bool,
    #[serde(default)]
    tls_enabled: bool,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
    #[serde(default)]
    grpc_metadata: DbJson<BTreeMap<String, String>>,
    #[serde(default)]
    tags: DbJson<Vec<Value>>,
    team_id: Option<String>,
    #[serde(default = "public")]
    visibility: String,
}

impl ServiceConfig {
    fn target(&self) -> GrpcTarget<'_> {
        GrpcTarget {
            address: &self.target,
            tls: self.tls_enabled,
            certificate: self.tls_cert_path.as_deref(),
            key: self.tls_key_path.as_deref(),
        }
    }

    fn validate(&mut self) -> Result<String, CatalogApiError> {
        self.name = self.name.trim().to_owned();
        let slug = slugify(&self.name);
        if slug.is_empty()
            || self.name.chars().count() > 255
            || self.name.contains(['<', '>'])
            || self.name.chars().any(char::is_control)
            || !matches!(self.visibility.as_str(), "private" | "team" | "public")
        {
            return Err(CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid gRPC service name or visibility",
            ));
        }
        self.target().url().map_err(|_| {
            CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Target must be in host:port format",
            )
        })?;
        Ok(slug)
    }
}

fn enabled() -> bool {
    true
}

fn public() -> String {
    "public".into()
}

#[derive(Serialize, sqlx::FromRow)]
struct ServiceRecord {
    id: String,
    slug: String,
    #[serde(flatten)]
    #[sqlx(flatten)]
    config: ServiceConfig,
    owner_email: Option<String>,
    team: Option<String>,
    enabled: bool,
    reachable: bool,
    service_count: i32,
    method_count: i32,
    discovered_services: DbJson<Value>,
    last_reflection: Option<String>,
    created_at: String,
    updated_at: String,
    #[serde(skip)]
    version: i32,
}

impl ServiceRecord {
    fn visible(&self, principal: Option<&Principal>) -> bool {
        access::catalog_scope(principal).visible(
            &self.config.visibility,
            self.config.team_id.as_deref(),
            self.owner_email.as_deref(),
        )
    }

    fn notify(&self, app: &GatewayService) {
        if self.method_count > 0 {
            app.subscriptions.changed(
                &self.config.visibility,
                self.config.team_id.as_deref(),
                self.owner_email.as_deref(),
            );
        }
    }
}

async fn require_access(
    app: &GatewayService,
    principal: &Principal,
) -> Result<(), CatalogApiError> {
    require_catalog_permission(app, principal, "admin.grpc", false).await?;
    if app.grpc.enabled {
        Ok(())
    } else {
        Err(CatalogApiError::detail(
            StatusCode::NOT_FOUND,
            "gRPC support is not available or disabled",
        ))
    }
}

async fn register(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(mut config): Json<ServiceConfig>,
) -> Result<(StatusCode, Json<ServiceRecord>), CatalogApiError> {
    require_access(&app, &principal).await?;

    let slug = config.validate()?;
    validate_public_visibility(&app, &config)?;
    require_target_permission(&app, &principal, config.team_id.as_deref()).await?;
    if let Some(team) = &config.team_id
        && !app
            .database
            .memberships(&principal.email)
            .await?
            .contains(team)
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access issue: the caller is not a member of the requested team.",
        ));
    }

    let target = config.target();
    let discovery = if config.reflection_enabled {
        match grpc::discover(&app.upstream, &target, app.grpc.timeout).await {
            Ok(discovery) => Some(discovery),
            Err(error) => {
                tracing::warn!(reason = %error, "gRPC service reflection failed");
                None
            }
        }
    } else {
        None
    };
    let id = Uuid::new_v4().simple().to_string();
    let client_ip = client_address(peer);
    let agent = user_agent(&headers);
    let inserted = app
        .database
        .insert_grpc_service(
            &id,
            &slug,
            &config,
            &principal.email,
            (client_ip.as_deref(), agent.as_deref()),
            discovery.as_ref(),
        )
        .await;
    let record = match inserted {
        Ok(record) => record,
        Err(error) => return Err(write_error(&app, &principal, &config.name, error.into()).await),
    };
    record.notify(&app);
    Ok((StatusCode::CREATED, Json(record)))
}

async fn detail(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<ServiceRecord>, CatalogApiError> {
    visible_record(&app, &principal, &id).await.map(Json)
}

async fn visible_record(
    app: &GatewayService,
    principal: &Principal,
    id: &str,
) -> Result<ServiceRecord, CatalogApiError> {
    require_access(app, principal).await?;
    app.database
        .load_grpc_service(id)
        .await?
        .filter(|record| record.visible(Some(principal)))
        .ok_or_else(|| {
            CatalogApiError::detail(
                StatusCode::NOT_FOUND,
                format!("gRPC service with ID '{id}' not found"),
            )
        })
}

#[derive(Default, Deserialize)]
struct ListQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    include_inactive: Option<String>,
    team_id: Option<String>,
}

async fn list(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    require_access(&app, &principal).await?;
    let include_inactive = flag(query.include_inactive.as_deref())?;
    let page = query.page.unwrap_or(1);
    let per_page = query
        .per_page
        .unwrap_or(i64::from(app.management_page_size));
    if page < 1 || !(1..=i64::from(app.management_max_page_size)).contains(&per_page) {
        return Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid pagination",
        ));
    }
    let per_page = per_page.max(i64::from(app.grpc.min_page_size));
    let team = query
        .team_id
        .as_deref()
        .filter(|team| !team.is_empty())
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid team ID"))?
        .map(|team| team.simple().to_string());
    if team
        .as_deref()
        .is_some_and(|team| !team_in_scope(&principal, team))
    {
        return Err(denied_team());
    }
    let (data, pagination) = app
        .database
        .list_grpc_services(
            access::catalog_scope(Some(&principal)),
            (include_inactive, team.as_deref()),
            (page, per_page, app.grpc.max_page_offset),
        )
        .await?;
    let links = app
        .grpc
        .include_page_links
        .then(|| pagination.links(include_inactive, team.as_deref()));
    Ok(Json(
        json!({"data":data,"pagination":pagination,"links":links}),
    ))
}

#[derive(Serialize)]
struct PaginationMeta {
    page: i64,
    per_page: i64,
    total_items: i64,
    total_pages: i64,
    has_next: bool,
    has_prev: bool,
    page_items: Option<i64>,
    next_cursor: Option<String>,
    prev_cursor: Option<String>,
}

impl PaginationMeta {
    fn new(mut page: i64, per_page: i64, total_items: i64) -> Self {
        let total_pages = total_items / per_page + i64::from(total_items % per_page != 0);
        if total_pages > 0 {
            page = page.min(total_pages);
        }
        Self {
            page,
            per_page,
            total_items,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
            page_items: None,
            next_cursor: None,
            prev_cursor: None,
        }
    }

    fn links(&self, include_inactive: bool, team: Option<&str>) -> Value {
        let link = |page| {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            if include_inactive {
                query.append_pair("include_inactive", "True");
            }
            if let Some(team) = team {
                query.append_pair("team_id", team);
            }
            query
                .append_pair("page", &i64::to_string(&page))
                .append_pair("per_page", &self.per_page.to_string());
            format!("/admin/grpc?{}", query.finish())
        };
        json!({
            "self":link(self.page), "first":link(1), "last":link(self.total_pages.max(1)),
            "next":self.has_next.then(|| link(self.page + 1)),
            "prev":self.has_prev.then(|| link(self.page - 1)),
        })
    }
}

fn validate_public_visibility(
    app: &GatewayService,
    config: &ServiceConfig,
) -> Result<(), CatalogApiError> {
    if config.visibility == "public"
        && config.team_id.is_some()
        && !app.grpc.allow_public_visibility
    {
        return Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Public visibility is disabled by platform configuration (ALLOW_PUBLIC_VISIBILITY=false).",
        ));
    }
    Ok(())
}

async fn require_target_permission(
    app: &GatewayService,
    principal: &Principal,
    team: Option<&str>,
) -> Result<(), CatalogApiError> {
    if team.is_some_and(|team| !team_in_scope(principal, team)) {
        return Err(denied_team());
    }
    let context = team.map_or(RoleContext::Global, RoleContext::Team);
    if app
        .access
        .allows(principal, "admin.grpc", context, false)
        .await?
    {
        Ok(())
    } else {
        Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ))
    }
}

fn team_in_scope(principal: &Principal, team: &str) -> bool {
    match &principal.visibility {
        TeamVisibility::Admin => true,
        TeamVisibility::Teams(allowed) => allowed.iter().any(|id| id == team),
        TeamVisibility::Public => false,
    }
}

async fn editable_record(
    app: &GatewayService,
    principal: &Principal,
    id: &str,
) -> Result<ServiceRecord, CatalogApiError> {
    let record = visible_record(app, principal, id).await?;
    require_target_permission(app, principal, record.config.team_id.as_deref()).await?;
    Ok(record)
}

async fn write_error(
    app: &GatewayService,
    principal: &Principal,
    name: &str,
    error: ServiceWriteError,
) -> CatalogApiError {
    match error {
        ServiceWriteError::Changed => CatalogApiError::detail(
            StatusCode::CONFLICT,
            "gRPC service changed during the request",
        ),
        ServiceWriteError::Database(sqlx::Error::Database(error))
            if error.is_unique_violation() =>
        {
            let mut message = format!("gRPC service with name '{name}' already exists");
            match app.database.grpc_service_named(name).await {
                Ok(Some(record)) if record.visible(Some(principal)) => {
                    if !record.enabled {
                        message.push_str(" (inactive)");
                    }
                    message.push_str(&format!(" (ID: {})", record.id));
                }
                Ok(_) => {}
                Err(error) => return error.into(),
            }
            CatalogApiError::detail(StatusCode::CONFLICT, message)
        }
        ServiceWriteError::Database(error) => error.into(),
    }
}

async fn update(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(patch): Json<serde_json::Map<String, Value>>,
) -> Result<Json<ServiceRecord>, CatalogApiError> {
    let prior = editable_record(&app, &principal, &id).await?;
    let mut merged = serde_json::to_value(&prior.config).expect("service configuration serializes");
    for (key, value) in patch {
        if key != "team_id"
            && let Some(field) = merged.get_mut(&key)
        {
            *field = value;
        }
    }
    let mut config = serde_json::from_value::<ServiceConfig>(merged).map_err(|_| {
        CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid gRPC service update",
        )
    })?;
    config.validate()?;
    if config.visibility != prior.config.visibility {
        validate_public_visibility(&app, &config)?;
    }
    let client_ip = client_address(peer);
    let agent = user_agent(&headers);
    let updated = mutate(
        &app,
        &principal,
        &prior,
        ServiceChange::Config {
            config: &config,
            modified_by: &principal.email,
            client_ip: client_ip.as_deref(),
            user_agent: agent.as_deref(),
        },
    )
    .await?;
    if prior.config.visibility != updated.config.visibility {
        prior.notify(&app);
        updated.notify(&app);
    }
    Ok(Json(updated))
}

#[derive(Deserialize)]
struct StateQuery {
    activate: Option<String>,
}

async fn set_state(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<StateQuery>,
) -> Result<Json<ServiceRecord>, CatalogApiError> {
    let prior = editable_record(&app, &principal, &id).await?;
    let activate = match query.activate.as_deref() {
        Some(value) => flag(Some(value))?,
        None => !prior.enabled,
    };
    let updated = mutate(&app, &principal, &prior, ServiceChange::State(activate)).await?;
    if prior.enabled != updated.enabled {
        updated.notify(&app);
    }
    Ok(Json(updated))
}

async fn reflect(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<ServiceRecord>, CatalogApiError> {
    let prior = editable_record(&app, &principal, &id).await?;
    let discovery = grpc::discover(&app.upstream, &prior.config.target(), app.grpc.timeout).await;
    let updated = mutate(
        &app,
        &principal,
        &prior,
        ServiceChange::Reflection(discovery.as_ref().ok()),
    )
    .await?;
    if let Err(error) = discovery {
        tracing::warn!(reason = %error, "gRPC service reflection failed");
        return Err(CatalogApiError::detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gRPC service error",
        ));
    }
    if prior.method_count > 0 {
        prior.notify(&app);
    } else {
        updated.notify(&app);
    }
    Ok(Json(updated))
}

async fn delete(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<StatusCode, CatalogApiError> {
    let prior = editable_record(&app, &principal, &id).await?;
    match app
        .database
        .change_grpc_service(&prior, ServiceChange::Delete)
        .await
    {
        Ok(_) => {
            prior.notify(&app);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(error) => Err(write_error(&app, &principal, &prior.config.name, error).await),
    }
}

async fn mutate(
    app: &GatewayService,
    principal: &Principal,
    prior: &ServiceRecord,
    change: ServiceChange<'_>,
) -> Result<ServiceRecord, CatalogApiError> {
    let name = match change {
        ServiceChange::Config { config, .. } => &config.name,
        _ => &prior.config.name,
    };
    match app.database.change_grpc_service(prior, change).await {
        Ok(Some(record)) => Ok(record),
        Ok(None) => Err(CatalogApiError::unavailable()),
        Err(error) => Err(write_error(app, principal, name, error).await),
    }
}

async fn methods(
    state: State<Arc<GatewayService>>,
    principal: Extension<Principal>,
    id: Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    let Json(record) = detail(state, principal, id).await?;
    let mut methods = Vec::new();
    if let Some(services) = record.discovered_services.0.as_object() {
        for (name, service) in services {
            if name.starts_with('_') {
                continue;
            }
            for method in service["methods"].as_array().into_iter().flatten() {
                let Some(method_name) = method["name"].as_str() else {
                    continue;
                };
                methods.push(json!({
                    "service": name,
                    "method": method_name,
                    "full_name": format!("{name}.{method_name}"),
                    "input_type": method["input_type"],
                    "output_type": method["output_type"],
                    "client_streaming": method["client_streaming"].as_bool().unwrap_or(false),
                    "server_streaming": method["server_streaming"].as_bool().unwrap_or(false),
                }));
            }
        }
    }
    Ok(Json(json!({"methods":methods})))
}

pub(super) async fn invoke(
    app: &GatewayService,
    tool: &CatalogTool,
    service_id: &str,
    request: &CallToolRequestParams,
    principal: Option<&Principal>,
) -> Result<Value, ToolError> {
    if tool.requires_gateway_policy || !tool.response_filter.trim().is_empty() {
        return Err(ToolError::Unavailable);
    }
    let record = app
        .database
        .load_grpc_service(service_id)
        .await?
        .filter(|record| record.enabled && record.visible(principal))
        .ok_or(ToolError::NotFound)?;

    let arguments = request
        .arguments
        .clone()
        .map_or_else(|| json!({}), Value::Object);
    match grpc::invoke(
        &app.upstream,
        &record.config.target(),
        &record.discovered_services.0,
        &tool.original_name,
        arguments,
        app.rest_timeout,
        app.grpc.max_message_bytes,
    )
    .await
    {
        Ok(value) => {
            let text = serde_json::to_string_pretty(&value).map_err(|_| ToolError::Unavailable)?;
            Ok(json!({"content":[ContentBlock::text(text)],"isError":false}))
        }
        Err(GrpcError::Timeout) => tool_result_error(format!(
            "Tool invocation timed out after {}s",
            app.rest_timeout.as_secs_f64(),
        )),
        Err(error) => {
            tracing::debug!(reason = %error, "gRPC tool invocation failed");
            tool_result_error(
                "gRPC invocation error: Method invocation failed: An unexpected error occurred",
            )
        }
    }
}
