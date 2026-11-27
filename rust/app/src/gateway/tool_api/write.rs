// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use super::*;
use crate::catalog::ToolWriteError;

mod authentication;

#[derive(Deserialize)]
pub(super) struct CreateTool {
    tool: ToolFields,
    #[serde(alias = "teamId")]
    team_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ToolFields {
    name: Option<String>,
    #[serde(alias = "custom_name")]
    custom_name: Option<String>,
    #[serde(alias = "display_name")]
    display_name: Option<String>,
    title: Option<String>,
    description: Option<String>,
    url: Option<String>,
    #[serde(alias = "integration_type")]
    integration_type: Option<String>,
    #[serde(alias = "request_type")]
    request_type: Option<String>,
    headers: Option<BTreeMap<String, String>>,
    #[serde(alias = "input_schema")]
    input_schema: Option<serde_json::Map<String, Value>>,
    #[serde(alias = "output_schema")]
    output_schema: Option<serde_json::Map<String, Value>>,
    annotations: Option<serde_json::Map<String, Value>>,
    #[serde(alias = "extension_metadata")]
    extension_metadata: Option<serde_json::Map<String, Value>>,
    #[serde(alias = "jsonpath_filter")]
    jsonpath_filter: Option<String>,
    #[serde(alias = "tool_validation_policy")]
    tool_validation_policy: Option<String>,
    #[serde(alias = "gateway_id")]
    gateway_id: Option<String>,
    #[serde(alias = "mcp_server_id")]
    mcp_server_id: Option<String>,
    #[serde(alias = "team_id")]
    team_id: Option<String>,
    visibility: Option<String>,
    tags: Option<Vec<Value>>,
    deprecated: Option<bool>,
    #[serde(alias = "base_url")]
    base_url: Option<String>,
    #[serde(alias = "path_template")]
    path_template: Option<String>,
    #[serde(alias = "query_mapping")]
    query_mapping: Option<BTreeMap<String, String>>,
    #[serde(alias = "header_mapping")]
    header_mapping: Option<BTreeMap<String, String>>,
    #[serde(alias = "timeout_ms")]
    timeout_ms: Option<i32>,
    #[serde(alias = "expose_passthrough")]
    expose_passthrough: Option<bool>,
    allowlist: Option<Vec<String>>,
    #[serde(alias = "plugin_chain_pre")]
    plugin_chain_pre: Option<Vec<String>>,
    #[serde(alias = "plugin_chain_post")]
    plugin_chain_post: Option<Vec<String>>,
    auth: Option<serde_json::Map<String, Value>>,
    #[serde(flatten)]
    credential_fields: serde_json::Map<String, Value>,
}

#[derive(Deserialize)]
pub(super) struct StateQuery {
    activate: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DeleteQuery {
    purge_metrics: Option<String>,
}

pub(super) async fn create(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(request): Json<CreateTool>,
) -> Result<Json<Value>, CatalogApiError> {
    let fields = request.tool;
    if request
        .team_id
        .as_ref()
        .zip(fields.team_id.as_ref())
        .is_some_and(|(outer, inner)| outer != inner)
    {
        return Err(denied_team());
    }
    let (team_id, visibility) = write_scope(
        &service,
        &principal,
        fields.visibility.as_deref().unwrap_or("public"),
        request.team_id.as_deref().or(fields.team_id.as_deref()),
        "tools.create",
    )
    .await?;
    let name = validate_name(
        fields
            .name
            .as_deref()
            .ok_or_else(|| invalid("Tool name is required"))?,
    )?;
    let mut record = ToolRecord {
        id: Uuid::new_v4().simple().to_string(),
        original_name: name.clone(),
        custom_name: name.clone(),
        display_name: Some(name),
        integration_type: "REST".to_owned(),
        request_type: "SSE".to_owned(),
        input_schema: json!({"type":"object","properties":{}}).to_string(),
        tags: "[]".to_owned(),
        owner_email: Some(principal.email.clone()),
        team_id,
        visibility,
        created_by: Some(principal.email.clone()),
        created_from_ip: client_address(peer),
        created_user_agent: user_agent(&headers),
        expose_passthrough: true,
        ..ToolRecord::default()
    };
    set_gateway(&service, &principal, &mut record, &fields).await?;
    apply_fields(&service, &mut record, fields, true)?;
    record.original_description.clone_from(&record.description);
    let created = service
        .database
        .save_managed_tool(None, &record)
        .await
        .map_err(|error| persistence_error(error, &record))?;
    publish(&service, &created);
    Ok(Json(metadata(&service, &created, true, true, true)))
}

pub(super) async fn update(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(fields): Json<ToolFields>,
) -> Result<Json<Value>, CatalogApiError> {
    let previous = editable(
        &service,
        &principal,
        &id,
        "tools.update",
        "update this tool",
    )
    .await?;
    let mut record = previous.clone();
    if fields.visibility.is_some() || fields.team_id.is_some() {
        let (team_id, visibility) = write_scope(
            &service,
            &principal,
            fields.visibility.as_deref().unwrap_or(&record.visibility),
            fields.team_id.as_deref().or(record.team_id.as_deref()),
            "tools.update",
        )
        .await?;
        record.team_id = team_id;
        record.visibility = visibility;
    }
    set_gateway(&service, &principal, &mut record, &fields).await?;
    apply_fields(&service, &mut record, fields, false)?;
    record.modified_by = Some(principal.email.clone());
    record.modified_from_ip = client_address(peer).or(record.modified_from_ip);
    record.modified_user_agent = user_agent(&headers).or(record.modified_user_agent);
    let updated = service
        .database
        .save_managed_tool(Some(&previous), &record)
        .await
        .map_err(|error| persistence_error(error, &record))?;
    if previous.visibility != updated.visibility || previous.team_id != updated.team_id {
        publish(&service, &previous);
    }
    publish(&service, &updated);
    Ok(Json(metadata(&service, &updated, true, true, true)))
}

pub(super) async fn set_state(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<StateQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    let enabled = query.activate.is_none() || flag(query.activate.as_deref())?;
    let (action, status) = if enabled {
        ("activate the Tool", "activated")
    } else {
        ("deactivate the Tool", "deactivated")
    };
    let previous = editable(&service, &principal, &id, "tools.update", action).await?;
    if enabled && let Some(reason) = &previous.validation_refusal {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            format!(
                "Tool '{}' cannot be enabled: {reason}. Change the validation policy, then refresh the gateway.",
                previous.original_name
            ),
        ));
    }
    let updated = service
        .database
        .set_managed_tool_state(&previous, enabled, enabled)
        .await
        .map_err(|error| persistence_error(error, &previous))?;
    if previous.enabled != updated.enabled || previous.reachable != updated.reachable {
        publish(&service, &updated);
    }
    Ok(Json(
        json!({"status":"success","message":format!("Tool {id} {status}"),"tool":metadata(&service,&updated,false,true,false)}),
    ))
}

pub(super) async fn delete(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    let previous = editable(
        &service,
        &principal,
        &id,
        "tools.delete",
        "delete this tool",
    )
    .await?;
    service
        .database
        .delete_managed_tool(&previous, flag(query.purge_metrics.as_deref())?)
        .await
        .map_err(|error| persistence_error(error, &previous))?;
    publish(&service, &previous);
    Ok(Json(
        json!({"status":"success","message":format!("Tool {id} permanently deleted")}),
    ))
}

async fn editable(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
    permission: &str,
    action: &str,
) -> Result<ToolRecord, CatalogApiError> {
    require_catalog_permission(service, principal, permission, true).await?;
    let tool = find_visible(service, principal, id).await?;
    require_target_permission(service, principal, permission, tool.team_id.as_deref()).await?;
    let owns = principal.is_global_admin()
        || tool.owner_email.as_deref() == Some(principal.email.as_str());
    let team_owner = if !owns
        && tool.visibility == "team"
        && let Some(team) = tool.team_id.as_deref()
    {
        service.database.team_owner(&principal.email, team).await?
    } else {
        false
    };
    if !owns && !team_owner {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            format!("Only the owner can {action}"),
        ));
    }
    Ok(tool)
}

async fn require_target_permission(
    service: &GatewayService,
    principal: &Principal,
    permission: &str,
    team: Option<&str>,
) -> Result<(), CatalogApiError> {
    let context = team.map_or(RoleContext::AnyTeam, RoleContext::Team);
    if !service
        .access
        .allows(principal, permission, context, true)
        .await?
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    Ok(())
}

async fn write_scope(
    service: &GatewayService,
    principal: &Principal,
    visibility: &str,
    team: Option<&str>,
    permission: &str,
) -> Result<(Option<String>, String), CatalogApiError> {
    if !matches!(visibility, "public" | "private" | "team") {
        return Err(invalid("Invalid tool visibility"));
    }
    let team = registration_team(service, principal, visibility, team)
        .await
        .map_err(|error| CatalogApiError(error.status, json!({"message":error.message})))?;
    require_target_permission(service, principal, permission, team.as_deref()).await?;
    Ok((team, visibility.to_owned()))
}

async fn set_gateway(
    service: &GatewayService,
    principal: &Principal,
    tool: &mut ToolRecord,
    fields: &ToolFields,
) -> Result<(), CatalogApiError> {
    if fields
        .gateway_id
        .as_ref()
        .zip(fields.mcp_server_id.as_ref())
        .is_some_and(|(id, alias)| id != alias)
    {
        return Err(invalid("gateway_id and mcp_server_id conflict"));
    }
    if let Some(id) = fields
        .gateway_id
        .as_deref()
        .or(fields.mcp_server_id.as_deref())
        && tool.gateway_id.as_deref() != Some(id)
    {
        let scope = access::catalog_scope(Some(principal));
        let gateway = service
            .database
            .gateway_records(id)
            .await?
            .into_iter()
            .find(|gateway| {
                gateway.id == id
                    && scope.visible(
                        &gateway.visibility,
                        gateway.team_id.as_deref(),
                        gateway.owner_email.as_deref(),
                    )
            })
            .ok_or_else(|| CatalogApiError::detail(StatusCode::NOT_FOUND, "Gateway not found"))?;
        tool.gateway_id = Some(gateway.id);
        tool.gateway_slug = gateway.slug;
    }
    Ok(())
}

fn apply_fields(
    service: &GatewayService,
    tool: &mut ToolRecord,
    mut fields: ToolFields,
    create: bool,
) -> Result<(), CatalogApiError> {
    if let Some(name) = fields.name.take() {
        let name = validate_name(&name)?;
        if tool.gateway_id.is_none() {
            tool.original_name.clone_from(&name);
        }
        tool.custom_name = name;
    }
    if let Some(name) = fields.custom_name.take() {
        tool.custom_name = validate_name(&name)?;
    }
    tool.custom_name_slug = slugify(&tool.custom_name);
    tool.name = if tool.gateway_slug.is_empty() {
        tool.custom_name_slug.clone()
    } else {
        format!("{}-{}", tool.gateway_slug, tool.custom_name_slug)
    };
    if tool.custom_name_slug.is_empty() || tool.name.len() > 255 {
        return Err(invalid("Invalid tool name"));
    }
    if let Some(display) = fields.display_name.take() {
        tool.display_name = Some(display_text(&display, 255)?);
    }
    if let Some(title) = fields.title.take() {
        tool.title = Some(display_text(&title, 255)?);
    }
    if let Some(description) = fields.description.take() {
        tool.description = Some(description.trim().chars().take(8192).collect());
    }
    if let Some(policy) = fields.tool_validation_policy.take() {
        if !policy.trim().is_empty() {
            return Err(invalid("Tool validation policy is unavailable"));
        }
        tool.tool_validation_policy = None;
    }
    if let Some(kind) = fields.integration_type.take() {
        if !matches!(kind.as_str(), "REST" | "MCP" | "A2A") {
            return Err(invalid("Unsupported tool integration type"));
        }
        tool.integration_type = kind;
    }
    if let Some(method) = fields.request_type.take() {
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "SSE" | "STDIO" | "STREAMABLEHTTP"
        ) {
            return Err(invalid("Unsupported tool request type"));
        }
        tool.request_type = method;
    }
    if let Some(url) = fields.url.take() {
        tool.url = Some(checked_endpoint(service, &url)?);
    }
    if let Some(schema) = fields.input_schema.take() {
        let schema = Value::Object(schema);
        validate_schema(&schema, "Invalid tool input schema")?;
        tool.input_schema = schema.to_string();
    }
    if let Some(schema) = fields.output_schema.take() {
        let schema = Value::Object(schema);
        validate_schema(&schema, "Invalid tool output schema")?;
        tool.output_schema = Some(schema.to_string());
    }
    if let Some(annotations) = fields.annotations.take() {
        tool.annotations = Some(Value::Object(annotations).to_string());
    }
    if let Some(extension) = fields.extension_metadata.take() {
        tool.extension_metadata = Some(Value::Object(extension).to_string());
    }
    if let Some(expression) = fields.jsonpath_filter.take() {
        tool.jsonpath_filter = expression;
    }
    if let Some(tags) = fields.tags.take() {
        tool.tags = normalized_tags(tags)?.to_string();
    }
    if let Some(deprecated) = fields.deprecated.take() {
        tool.deprecated = deprecated;
    }
    if let Some(headers) = fields.headers.take() {
        tool.headers = Some(authentication::prepare_headers(service, tool, headers)?);
    }
    if tool.integration_type == "REST" {
        apply_passthrough(service, tool, &mut fields, create)?;
    }
    authentication::apply(service, tool, fields.auth.take(), fields.credential_fields)?;
    Ok(())
}

fn apply_passthrough(
    service: &GatewayService,
    tool: &mut ToolRecord,
    fields: &mut ToolFields,
    create: bool,
) -> Result<(), CatalogApiError> {
    let url = tool
        .url
        .as_deref()
        .and_then(|value| reqwest::Url::parse(value).ok());
    if let Some(base) = fields.base_url.take() {
        tool.base_url = Some(
            checked_endpoint(service, &base)?
                .trim_end_matches('/')
                .to_owned(),
        );
    } else if tool.base_url.is_none()
        && let Some(url) = &url
    {
        tool.base_url = Some(url.origin().ascii_serialization());
    }
    if let Some(path) = fields.path_template.take() {
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('\\')
            || path.chars().any(char::is_control)
        {
            return Err(invalid("Invalid tool path template"));
        }
        tool.path_template = Some(path);
    } else if tool.path_template.is_none()
        && let Some(url) = &url
    {
        tool.path_template = Some(url.path().to_owned());
    }
    if let Some(timeout) = fields.timeout_ms.take() {
        if timeout <= 0 {
            return Err(invalid("Invalid tool timeout"));
        }
        tool.timeout_ms = Some(timeout);
    } else if create {
        tool.timeout_ms = Some(20_000);
    }
    if let Some(value) = fields.expose_passthrough.take() {
        tool.expose_passthrough = value;
    }
    if let Some(query) = fields.query_mapping.take() {
        tool.query_mapping = Some(json!(query).to_string());
    }
    if let Some(headers) = fields.header_mapping.take() {
        if headers.keys().any(|name| {
            HeaderName::from_bytes(name.as_bytes()).is_err()
                || authentication::protected_header(name)
                || name.to_ascii_lowercase().starts_with("mcp-")
        }) {
            return Err(invalid("Invalid tool header mapping"));
        }
        tool.header_mapping = Some(json!(headers).to_string());
    }
    if let Some(allowlist) = fields.allowlist.take() {
        tool.allowlist = Some(json!(allowlist).to_string());
    }
    if let Some(chain) = fields.plugin_chain_pre.take() {
        tool.plugin_chain_pre = Some(json!(chain).to_string());
    }
    if let Some(chain) = fields.plugin_chain_post.take() {
        tool.plugin_chain_post = Some(json!(chain).to_string());
    }
    Ok(())
}

fn checked_endpoint(service: &GatewayService, value: &str) -> Result<String, CatalogApiError> {
    let value = value.trim();
    if value.len() > 767 || service.upstream.check_endpoint(value).is_err() {
        return Err(invalid("Tool URL is invalid or disallowed"));
    }
    reqwest::Url::parse(value)
        .map(|url| url.to_string())
        .map_err(|_| invalid("Tool URL is invalid"))
}

fn validate_schema(schema: &Value, message: &'static str) -> Result<(), CatalogApiError> {
    jsonschema::options()
        .offline()
        .build(schema)
        .map_err(|_| invalid(message))?;
    Ok(())
}

fn validate_name(value: &str) -> Result<String, CatalogApiError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-/".contains(&byte))
        || !value.as_bytes()[0].is_ascii_alphanumeric() && !value.starts_with('_')
    {
        return Err(invalid("Invalid tool name"));
    }
    Ok(value.to_owned())
}

fn display_text(value: &str, limit: usize) -> Result<String, CatalogApiError> {
    let value = value.trim();
    if value.chars().count() > limit
        || value.chars().any(char::is_control)
        || value.contains(['<', '>'])
    {
        return Err(invalid("Invalid tool display text"));
    }
    Ok(value.to_owned())
}

fn invalid(message: &'static str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn publish(service: &GatewayService, tool: &ToolRecord) {
    service.subscriptions.changed(
        &tool.visibility,
        tool.team_id.as_deref(),
        tool.owner_email.as_deref(),
    );
}

fn persistence_error(error: ToolWriteError, tool: &ToolRecord) -> CatalogApiError {
    match error {
        ToolWriteError::Changed => CatalogApiError::detail(
            StatusCode::CONFLICT,
            format!(
                "Tool {} is currently being modified by another request",
                tool.id
            ),
        ),
        ToolWriteError::Duplicate { id, enabled } => {
            let message = if enabled {
                let visibility = match tool.visibility.as_str() {
                    "public" => "Public",
                    "team" => "Team",
                    _ => "Private",
                };
                format!("{visibility} Tool already exists with name: {}", tool.name)
            } else {
                format!(
                    "Tool name already exists but is inactive. Consider activating it with ID: {id}"
                )
            };
            CatalogApiError::detail(StatusCode::CONFLICT, message)
        }
        ToolWriteError::Database(sqlx::Error::Database(database))
            if database.is_unique_violation() =>
        {
            CatalogApiError::detail(
                StatusCode::CONFLICT,
                format!("Tool already exists with name: {}", tool.name),
            )
        }
        ToolWriteError::Database(error) => error.into(),
    }
}
