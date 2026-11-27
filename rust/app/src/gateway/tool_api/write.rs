// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use super::*;
use crate::catalog::ToolWriteError;
use crate::gateway::import_api::{ImportScope, Outcome, Strategy};

mod authentication;
pub(in crate::gateway) use authentication::protected_header;

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

pub(in crate::gateway) async fn import_tool(
    service: &GatewayService,
    import: &ImportScope<'_>,
    mut data: serde_json::Map<String, Value>,
) -> Result<Outcome, CatalogApiError> {
    let principal = import.principal;
    let name = validate_name(data["name"].as_str().unwrap_or_default())?;
    let slug = slugify(&name);
    let scope = access::catalog_scope(Some(principal));
    let candidates = service
        .database
        .managed_tools(scope, crate::catalog::CatalogEntryFilters::associated(true))
        .await?;
    let matching = candidates
        .iter()
        .filter(|tool| {
            tool.gateway_id.is_none() && (tool.original_name == name || tool.name == slug)
        })
        .collect::<Vec<_>>();
    let owned = matching
        .iter()
        .copied()
        .find(|tool| tool.owner_email.as_deref() == Some(principal.email.as_str()));
    let previous = owned.or_else(|| (matching.len() == 1).then(|| matching[0]));
    let mut renamed = None;
    let previous = if matching.is_empty() {
        None
    } else {
        match import.strategy {
            Strategy::Skip => return Ok(Outcome::Skipped),
            Strategy::Fail => {
                return Err(CatalogApiError::detail(
                    StatusCode::CONFLICT,
                    format!("Tool name conflict: {name}"),
                ));
            }
            Strategy::Rename => {
                let suffix = format!("_imported_{}", Timestamp::now().as_second());
                let base: String = name.chars().take(255 - suffix.len()).collect();
                let new_name = format!("{base}{suffix}");
                data.insert("name".into(), new_name.clone().into());
                renamed = Some(new_name);
                None
            }
            Strategy::Update => {
                if let Some(previous) = previous
                    && import.owns(previous.owner_email.as_deref())
                {
                    Some(previous)
                } else {
                    return Err(CatalogApiError::detail(
                        StatusCode::FORBIDDEN,
                        format!("Permission denied: cannot update tool {name}"),
                    ));
                }
            }
        }
    };
    let original_description = data
        .remove("original_description")
        .and_then(|value| value.as_str().map(str::to_owned));
    data.retain(|key, _| {
        matches!(
            key.as_str(),
            "name"
                | "displayName"
                | "display_name"
                | "description"
                | "url"
                | "integration_type"
                | "request_type"
                | "headers"
                | "input_schema"
                | "output_schema"
                | "annotations"
                | "jsonpath_filter"
                | "tool_validation_policy"
                | "tags"
                | "auth_type"
                | "auth_value"
        )
    });
    let auth_type = data.remove("auth_type");
    let auth_value = match data.remove("auth_value") {
        Some(Value::String(stored)) => Some(stored),
        None | Some(Value::Null) => None,
        Some(_) => return Err(invalid("Invalid imported tool credentials")),
    };
    if let Some(stored) = auth_value {
        let auth_type = auth_type
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| invalid("Missing imported tool authentication type"))?;
        let cipher = service
            .credential_cipher
            .as_ref()
            .ok_or_else(|| invalid("Tool credential encryption unavailable"))?;
        let encoded = if cipher.open::<serde::de::IgnoredAny>(&stored).is_ok() {
            stored
        } else if let Some(source) = import.rekey {
            let plain = CredentialCipher::new(source)
                .open::<Value>(&stored)
                .map_err(|_| invalid("Invalid imported tool credentials"))?;
            cipher
                .seal(&plain)
                .map_err(|_| invalid("Tool credential encryption failed"))?
        } else {
            return Err(invalid("Invalid imported tool credentials"));
        };
        data.insert(
            "auth".into(),
            json!({"auth_type":auth_type,"auth_value":encoded}),
        );
    }
    if let Some(Value::Object(headers)) = data.get_mut("headers") {
        if previous.is_none() {
            headers.retain(|_, value| value.as_str() != Some(MASK));
        }
        for value in headers.values_mut() {
            let Some(encoded) = value.get(SECRET_HEADER).and_then(Value::as_str) else {
                continue;
            };
            let decoded = service
                .credential_cipher
                .as_ref()
                .and_then(|cipher| cipher.open::<Value>(encoded).ok())
                .or_else(|| {
                    import
                        .rekey
                        .and_then(|key| CredentialCipher::new(key).open::<Value>(encoded).ok())
                })
                .and_then(|value| value.get("data").and_then(Value::as_str).map(str::to_owned))
                .ok_or_else(|| invalid("Invalid imported tool headers"))?;
            *value = Value::String(decoded);
        }
    }
    data.entry("request_type")
        .or_insert_with(|| Value::String("GET".into()));
    let fields: ToolFields = serde_json::from_value(Value::Object(data))
        .map_err(|_| invalid("Invalid imported tool"))?;
    let mut record = previous.cloned().unwrap_or_else(|| ToolRecord {
        id: Uuid::new_v4().simple().to_string(),
        original_name: name.clone(),
        custom_name: name.clone(),
        display_name: Some(renamed.clone().unwrap_or_else(|| name.clone())),
        integration_type: "REST".into(),
        request_type: "GET".into(),
        input_schema: json!({"type":"object","properties":{}}).to_string(),
        tags: "[]".into(),
        owner_email: Some(principal.email.clone()),
        team_id: import.team_id.map(str::to_owned),
        visibility: import.visibility().into(),
        created_by: Some(principal.email.clone()),
        created_via: Some("import".into()),
        import_batch_id: Some(import.batch_id.into()),
        federation_source: Some(format!("imported-by-{}", principal.email)),
        expose_passthrough: true,
        ..ToolRecord::default()
    });
    apply_fields(service, &mut record, fields, previous.is_none()).await?;
    if previous.is_some() {
        record.modified_by = Some(principal.email.clone());
        record.modified_via = Some("import".into());
    } else {
        record.original_description = original_description.or_else(|| record.description.clone());
    }
    let saved = service
        .database
        .save_managed_tool(previous, &record)
        .await
        .map_err(|error| persistence_error(error, &record))?;
    publish(service, &saved);
    Ok(if previous.is_some() {
        Outcome::Updated
    } else {
        Outcome::Created
    })
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
    apply_fields(&service, &mut record, fields, true).await?;
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
    apply_fields(&service, &mut record, fields, false).await?;
    record.modified_by = Some(principal.email.clone());
    record.modified_via = Some("api".into());
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

async fn apply_fields(
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
        if expression.trim_start().starts_with(['.', '$']) {
            return Err(invalid(
                "jsonpath_filter is a jq or JSONPath filter, which is no longer supported; write a CEL expression over 'response', for example 'response.items.map(i, i.name)'",
            ));
        }
        service
            .response_filters
            .validate(&expression)
            .await
            .map_err(|error| {
                CatalogApiError::detail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("jsonpath_filter is not a valid CEL expression: {error}"),
                )
            })?;
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
    if tool.auth_type.as_deref() == Some("sigv4")
        && tool
            .url
            .as_deref()
            .and_then(|url| url::Url::parse(url).ok())
            .is_some_and(|url| crate::sigv4::has_query_signature(&url))
    {
        return Err(invalid(
            "A presigned URL cannot be combined with auth_type 'sigv4'",
        ));
    }
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
        if headers
            .values()
            .any(|name| mapped_header_name(name).is_none())
        {
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
    if value.contains('{') {
        return Ok(value.to_owned());
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
