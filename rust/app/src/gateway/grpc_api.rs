// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use axum::extract::Path;
use sqlx::types::Json as DbJson;

use super::{catalog_api::*, *};
use crate::grpc::{self, Discovery, GrpcError, GrpcTarget, ReflectedMethod};

pub(super) fn router() -> Router<Arc<GatewayService>> {
    Router::new()
        .route("/admin/grpc", post(register))
        .route("/admin/grpc/{id}", get(detail))
        .route("/admin/grpc/{id}/methods", get(methods))
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
}

impl ServiceRecord {
    fn visible(&self, principal: Option<&Principal>) -> bool {
        access::catalog_scope(principal).visible(
            &self.config.visibility,
            self.config.team_id.as_deref(),
            self.owner_email.as_deref(),
        )
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

    config.name = config.name.trim().to_owned();
    let slug = slugify(&config.name);
    if slug.is_empty()
        || config.name.chars().count() > 255
        || config.name.contains(['<', '>'])
        || config.name.chars().any(char::is_control)
        || !matches!(config.visibility.as_str(), "private" | "team" | "public")
    {
        return Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid gRPC service name or visibility",
        ));
    }
    if let Some(team) = &config.team_id {
        if config.visibility == "public" && !app.grpc.allow_public_visibility {
            return Err(CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Public visibility is disabled by platform configuration (ALLOW_PUBLIC_VISIBILITY=false).",
            ));
        }
        let in_scope = match &principal.visibility {
            TeamVisibility::Admin => true,
            TeamVisibility::Teams(teams) => teams.contains(team),
            TeamVisibility::Public => false,
        };
        if !in_scope
            || !app
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
    }

    let target = config.target();
    target.url().map_err(|_| {
        CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Target must be in host:port format",
        )
    })?;
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
    let record = app
        .database
        .insert_grpc_service(
            &id,
            &slug,
            &config,
            &principal.email,
            (client_ip.as_deref(), agent.as_deref()),
            discovery.as_ref(),
        )
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(error) if error.is_unique_violation() => CatalogApiError::detail(
                StatusCode::CONFLICT,
                format!("gRPC service with name '{}' already exists", config.name),
            ),
            _ => error.into(),
        })?;
    if record.method_count > 0 {
        app.subscriptions.changed(
            &config.visibility,
            config.team_id.as_deref(),
            Some(&principal.email),
        );
    }
    Ok((StatusCode::CREATED, Json(record)))
}

async fn detail(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<ServiceRecord>, CatalogApiError> {
    require_access(&app, &principal).await?;
    let record = app
        .database
        .load_grpc_service(&id)
        .await?
        .filter(|record| record.visible(Some(&principal)))
        .ok_or_else(|| {
            CatalogApiError::detail(
                StatusCode::NOT_FOUND,
                format!("gRPC service with ID '{id}' not found"),
            )
        })?;
    Ok(Json(record))
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

const SELECT_SERVICE: &str = "
    SELECT s.id, s.name, s.slug, s.description, s.target, s.reflection_enabled, s.tls_enabled,
           s.tls_cert_path, s.tls_key_path, COALESCE(s.grpc_metadata, '{}') AS grpc_metadata,
           s.enabled, s.reachable, s.service_count, s.method_count,
           COALESCE(s.discovered_services, '{}') AS discovered_services,
           REPLACE(CAST(s.last_reflection AS TEXT), ' ', 'T') AS last_reflection, s.tags,
           REPLACE(CAST(s.created_at AS TEXT), ' ', 'T') AS created_at,
           REPLACE(CAST(s.updated_at AS TEXT), ' ', 'T') AS updated_at,
           s.team_id, t.name AS team, s.owner_email, s.visibility
    FROM grpc_services s
    LEFT JOIN email_teams t ON t.id = s.team_id AND t.is_active = TRUE
    WHERE s.id = $1";

const INSERT_SERVICE: &str = "
    INSERT INTO grpc_services (
        id, slug, name, target, description, reflection_enabled, tls_enabled, tls_cert_path,
        tls_key_path, grpc_metadata, tags, team_id, owner_email, visibility, enabled,
        reachable, service_count, method_count, discovered_services, last_reflection,
        created_at, updated_at, created_by, created_from_ip, created_via, created_user_agent, version
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, TRUE,
        $15, $16, $17, $18, CASE WHEN $15 THEN CURRENT_TIMESTAMP END,
        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $13, $19, 'api', $20, 1)";

const INSERT_TOOL: &str = "
    INSERT INTO tools (id, name, original_name, custom_name, custom_name_slug, url, description,
        original_description, integration_type, grpc_service_id, input_schema, annotations,
        request_type, enabled, reachable, deprecated, expose_passthrough, jsonpath_filter,
        tags, created_at, updated_at, created_by, created_via, federation_source, version,
        team_id, owner_email, visibility)
    VALUES ($1, $2, $3, $3, $2, $4, $5, $5, 'gRPC', $6, $7, '{}',
        'SSE', TRUE, TRUE, FALSE, TRUE, '', '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
        'system', 'grpc-reflection', $8, 1, $9, $10, $11)";

impl Database {
    async fn load_grpc_service(&self, id: &str) -> Result<Option<ServiceRecord>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(SELECT_SERVICE)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(SELECT_SERVICE)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
        }
    }

    async fn insert_grpc_service(
        &self,
        id: &str,
        slug: &str,
        config: &ServiceConfig,
        owner: &str,
        (client_ip, user_agent): (Option<&str>, Option<&str>),
        discovery: Option<&Discovery>,
    ) -> Result<ServiceRecord, sqlx::Error> {
        let stored = discovery.map_or_else(|| json!({}), Discovery::stored);
        let methods = discovery
            .into_iter()
            .flat_map(|item| &item.services)
            .flat_map(|(service, details)| {
                details.methods.iter().filter_map(move |method| {
                    let full_name = format!("{service}.{}", method.name);
                    (full_name.len() <= 255).then_some((full_name, method))
                })
            })
            .collect::<Vec<_>>();
        let service_count = discovery.map_or(0, |item| item.services.len() as i32);
        let method_count = discovery.map_or(0, |item| {
            item.services
                .values()
                .map(|service| service.methods.len() as i32)
                .sum()
        });
        macro_rules! insert {
            ($pool:ident) => {{
                let mut transaction = $pool.begin().await?;
                sqlx::query(INSERT_SERVICE)
                    .bind(id)
                    .bind(slug)
                    .bind(&config.name)
                    .bind(&config.target)
                    .bind(&config.description)
                    .bind(config.reflection_enabled)
                    .bind(config.tls_enabled)
                    .bind(&config.tls_cert_path)
                    .bind(&config.tls_key_path)
                    .bind(&config.grpc_metadata)
                    .bind(&config.tags)
                    .bind(&config.team_id)
                    .bind(owner)
                    .bind(&config.visibility)
                    .bind(discovery.is_some())
                    .bind(service_count)
                    .bind(method_count)
                    .bind(DbJson(&stored))
                    .bind(client_ip)
                    .bind(user_agent)
                    .execute(&mut *transaction)
                    .await?;
                for (full_name, method) in &methods {
                    sqlx::query(INSERT_TOOL)
                        .bind(Uuid::new_v4().simple().to_string())
                        .bind(slugify(full_name))
                        .bind(full_name)
                        .bind(&config.target)
                        .bind(format!("gRPC method {full_name}"))
                        .bind(id)
                        .bind(DbJson(method_schema(method)))
                        .bind(&config.name)
                        .bind(&config.team_id)
                        .bind(owner)
                        .bind(&config.visibility)
                        .execute(&mut *transaction)
                        .await?;
                }
                let record = sqlx::query_as(SELECT_SERVICE)
                    .bind(id)
                    .fetch_one(&mut *transaction)
                    .await?;
                transaction.commit().await?;
                record
            }};
        }
        Ok(match self {
            Self::Sqlite(pool) => insert!(pool),
            Self::Postgres(pool) => insert!(pool),
        })
    }
}

fn method_schema(method: &ReflectedMethod) -> Value {
    json!({
        "type": "object",
        "properties": {},
        "x-grpc-input-type": method.input_type,
        "x-grpc-output-type": method.output_type,
        "x-grpc-client-streaming": method.client_streaming,
        "x-grpc-server-streaming": method.server_streaming,
    })
}
