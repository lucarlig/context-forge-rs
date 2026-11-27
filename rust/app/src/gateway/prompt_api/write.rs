// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::catalog::{PromptWriteError, slugify};
use crate::gateway::import_api::{ImportScope, Outcome, Strategy};
use serde_json::Map;

#[derive(Deserialize)]
pub(super) struct CreatePrompt {
    prompt: PromptFields,
    #[serde(alias = "teamId")]
    team_id: Option<String>,
    visibility: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PromptFields {
    name: Option<String>,
    #[serde(alias = "custom_name")]
    custom_name: Option<String>,
    #[serde(alias = "display_name")]
    display_name: Option<String>,
    title: Option<String>,
    description: Option<String>,
    template: Option<String>,
    arguments: Option<Vec<Argument>>,
    tags: Option<Vec<Value>>,
    #[serde(alias = "team_id")]
    team_id: Option<String>,
    visibility: Option<String>,
    #[serde(alias = "gateway_id")]
    gateway_id: Option<String>,
    #[serde(alias = "mcp_server_id")]
    mcp_server_id: Option<String>,
}

#[derive(Deserialize)]
struct Argument {
    name: String,
    description: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct StateQuery {
    activate: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DeleteQuery {
    purge_metrics: Option<String>,
}

pub(in crate::gateway) async fn import_prompt(
    service: &GatewayService,
    import: &ImportScope<'_>,
    mut data: Map<String, Value>,
) -> Result<Outcome, CatalogApiError> {
    if let Some(name) = data
        .remove("original_name")
        .filter(|name| !name.is_null() && name.as_str() != Some(""))
    {
        data.insert("name".into(), name);
    }
    let arguments = import_arguments(data.remove("input_schema"))?;
    data.retain(|key, _| {
        matches!(
            key.as_str(),
            "name" | "custom_name" | "display_name" | "description" | "template" | "tags"
        )
    });
    let mut fields: PromptFields = serde_json::from_value(Value::Object(data))
        .map_err(|_| invalid("Invalid imported prompt"))?;
    if fields.template.is_none() {
        return Err(invalid("Prompt template is required"));
    }
    fields.arguments = Some(arguments);
    let original_name = validate_name(fields.name.as_deref().unwrap_or_default())?;
    let mut custom_name = match fields.custom_name.as_deref() {
        Some(name) => validate_name(name)?,
        None => original_name.clone(),
    };
    let scope = access::catalog_scope(Some(import.principal));
    let slug = slugify(&custom_name);
    if slug.is_empty() || slug.len() > 255 {
        return Err(invalid("Invalid prompt name"));
    }
    let candidates = service
        .database
        .import_prompt_candidates(scope, &slug)
        .await?;
    let previous = if candidates.is_empty() {
        None
    } else {
        match import.strategy {
            Strategy::Skip => return Ok(Outcome::Skipped),
            Strategy::Fail => {
                return Err(CatalogApiError::detail(
                    StatusCode::CONFLICT,
                    format!("Prompt name conflict: {original_name}"),
                ));
            }
            Strategy::Rename => {
                let suffix = format!("_imported_{}", Timestamp::now().as_second());
                let base: String = original_name.chars().take(255 - suffix.len()).collect();
                custom_name = format!("{base}{suffix}");
                fields.display_name = Some(custom_name.clone());
                None
            }
            Strategy::Update => {
                let previous = candidates
                    .iter()
                    .find(|record| {
                        record.owner_email.as_deref() == Some(import.principal.email.as_str())
                    })
                    .or_else(|| (candidates.len() == 1).then(|| &candidates[0]));
                Some(
                    previous
                        .filter(|record| import.owns(record.owner_email.as_deref()))
                        .ok_or_else(|| {
                            CatalogApiError::detail(
                                StatusCode::FORBIDDEN,
                                format!("Permission denied: cannot update prompt {original_name}"),
                            )
                        })?,
                )
            }
        }
    };

    let actor = &import.principal.email;
    let mut record = previous.cloned().unwrap_or_else(|| PromptRecord {
        id: Uuid::new_v4().simple().to_string(),
        original_name,
        display_name: Some(custom_name.clone()),
        tags: "[]".into(),
        owner_email: Some(actor.clone()),
        team_id: import.team_id.map(str::to_owned),
        visibility: import.visibility().into(),
        created_by: Some(actor.clone()),
        created_via: Some("import".into()),
        import_batch_id: Some(import.batch_id.into()),
        federation_source: Some(format!("imported-by-{actor}")),
        ..PromptRecord::default()
    });
    if previous.is_some() {
        record.modified_by = Some(actor.clone());
        record.modified_via = Some("import".into());
    }
    record.custom_name = custom_name;
    set_names(&mut record)?;
    apply_fields(service, &mut record, fields, true)?;
    let saved = service
        .database
        .save_managed_prompt(previous, &record)
        .await
        .map_err(|error| persistence_error(error, &record))?;
    publish(service, &saved);
    Ok(if previous.is_some() {
        Outcome::Updated
    } else {
        Outcome::Created
    })
}

fn import_arguments(schema: Option<Value>) -> Result<Vec<Argument>, CatalogApiError> {
    let Some(Value::Object(mut schema)) = schema else {
        return Ok(Vec::new());
    };
    let Some(properties) = schema.remove("properties") else {
        return Ok(Vec::new());
    };
    let Value::Object(properties) = properties else {
        return Err(invalid("Invalid imported prompt input schema properties"));
    };
    properties
        .into_iter()
        .map(|(name, property)| {
            let Value::Object(mut property) = property else {
                return Err(invalid("Invalid imported prompt input schema property"));
            };
            let description = match property.remove("description") {
                Some(Value::String(description)) => Some(description),
                Some(Value::Null) => None,
                None => Some(String::new()),
                _ => return Err(invalid("Invalid imported prompt argument description")),
            };
            Ok(Argument { name, description })
        })
        .collect()
}

pub(super) async fn create(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(request): Json<CreatePrompt>,
) -> Result<Json<Value>, CatalogApiError> {
    let fields = request.prompt;
    if request
        .team_id
        .as_ref()
        .zip(fields.team_id.as_ref())
        .is_some_and(|(outer, inner)| outer != inner)
    {
        return Err(denied_team());
    }
    let visibility = request
        .visibility
        .as_deref()
        .or(fields.visibility.as_deref())
        .unwrap_or("public");
    validate_visibility(visibility)?;
    let team_id = registration_team(
        &service,
        &principal,
        visibility,
        request.team_id.as_deref().or(fields.team_id.as_deref()),
    )
    .await
    .map_err(|error| CatalogApiError(error.status, json!({"message":error.message})))?;
    require_target_permission(&service, &principal, "prompts.create", team_id.as_deref()).await?;
    let gateway_id = fields
        .gateway_id
        .as_deref()
        .or(fields.mcp_server_id.as_deref());
    if fields
        .gateway_id
        .as_ref()
        .zip(fields.mcp_server_id.as_ref())
        .is_some_and(|(id, alias)| id != alias)
    {
        return Err(invalid("gateway_id and mcp_server_id conflict"));
    }
    let scope = access::catalog_scope(Some(&principal));
    let gateway = if let Some(id) = gateway_id {
        Some(
            service
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
                .ok_or_else(|| invalid("Gateway not found"))?,
        )
    } else {
        None
    };
    let original_name = validate_name(
        fields
            .name
            .as_deref()
            .ok_or_else(|| invalid("Prompt name is required"))?,
    )?;
    let custom_name = fields
        .custom_name
        .as_deref()
        .map(validate_name)
        .transpose()?
        .unwrap_or_else(|| original_name.clone());
    if fields.template.is_none() {
        return Err(invalid("Prompt template is required"));
    }
    let mut record = PromptRecord {
        id: Uuid::new_v4().simple().to_string(),
        original_name,
        custom_name,
        gateway_id: gateway_id.map(str::to_owned),
        gateway_slug: gateway.map(|gateway| gateway.slug),
        tags: "[]".to_owned(),
        owner_email: Some(principal.email.clone()),
        team_id,
        visibility: visibility.to_owned(),
        created_by: Some(principal.email.clone()),
        created_from_ip: client_address(peer),
        created_user_agent: user_agent(&headers),
        ..PromptRecord::default()
    };
    set_names(&mut record)?;
    record.display_name = Some(record.custom_name.clone());
    apply_fields(&service, &mut record, fields, true)?;
    let created = service
        .database
        .save_managed_prompt(None, &record)
        .await
        .map_err(|error| persistence_error(error, &record))?;
    publish(&service, &created);
    Ok(Json(metadata(&created, true)))
}

pub(super) async fn update(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(fields): Json<PromptFields>,
) -> Result<Json<Value>, CatalogApiError> {
    let previous = editable(
        &service,
        &principal,
        &id,
        "prompts.update",
        "update this prompt",
    )
    .await?;
    let mut record = previous.clone();
    if let Some(name) = fields.name.as_deref() {
        let name = validate_name(name)?;
        if record.gateway_id.is_none() {
            record.original_name.clone_from(&name);
        }
        record.custom_name = name;
    }
    if let Some(name) = fields.custom_name.as_deref() {
        record.custom_name = validate_name(name)?;
    }
    if fields.name.is_some() || fields.custom_name.is_some() {
        set_names(&mut record)?;
    }
    if fields.visibility.is_some() || fields.team_id.is_some() {
        let visibility = fields.visibility.as_deref().unwrap_or(&record.visibility);
        validate_visibility(visibility)?;
        let team = fields.team_id.as_deref().or(record.team_id.as_deref());
        let team = registration_team(&service, &principal, visibility, team)
            .await
            .map_err(|error| CatalogApiError(error.status, json!({"message":error.message})))?;
        require_target_permission(&service, &principal, "prompts.update", team.as_deref()).await?;
        record.team_id = team;
        record.visibility = visibility.to_owned();
    }
    record.modified_by = Some(principal.email.clone());
    record.modified_via = Some("api".into());
    record.modified_from_ip = client_address(peer).or(record.modified_from_ip);
    record.modified_user_agent = user_agent(&headers).or(record.modified_user_agent);
    apply_fields(&service, &mut record, fields, false)?;
    let updated = service
        .database
        .save_managed_prompt(Some(&previous), &record)
        .await
        .map_err(|error| persistence_error(error, &record))?;
    if previous.visibility != updated.visibility || previous.team_id != updated.team_id {
        publish(&service, &previous);
    }
    publish(&service, &updated);
    Ok(Json(metadata(&updated, true)))
}

pub(super) async fn set_state(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<StateQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    let enabled = query.activate.is_none() || flag(query.activate.as_deref())?;
    let (action, status) = if enabled {
        ("activate the Prompt", "activated")
    } else {
        ("deactivate the Prompt", "deactivated")
    };
    let previous = editable(&service, &principal, &id, "prompts.update", action).await?;
    let updated = service
        .database
        .set_managed_prompt_state(&previous, enabled)
        .await
        .map_err(|error| persistence_error(error, &previous))?;
    if previous.enabled != enabled {
        publish(&service, &updated);
    }
    Ok(Json(
        json!({"status":"success","message": format!("Prompt {id} {status}"), "prompt":metadata(&updated, false)}),
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
        "prompts.delete",
        "delete this prompt",
    )
    .await?;
    service
        .database
        .delete_managed_prompt(&previous, flag(query.purge_metrics.as_deref())?)
        .await
        .map_err(|error| persistence_error(error, &previous))?;
    publish(&service, &previous);
    Ok(Json(
        json!({"status":"success","message":format!("Prompt {id} deleted")}),
    ))
}

async fn editable(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
    permission: &str,
    action: &str,
) -> Result<PromptRecord, CatalogApiError> {
    require_catalog_permission(service, principal, permission, true).await?;
    let scope = access::catalog_scope(Some(principal));
    let record = service
        .database
        .managed_prompt(id)
        .await?
        .filter(|prompt| {
            scope.visible(
                &prompt.visibility,
                prompt.team_id.as_deref(),
                prompt.owner_email.as_deref(),
            )
        })
        .ok_or_else(|| {
            CatalogApiError::detail(StatusCode::NOT_FOUND, format!("Prompt not found: {id}"))
        })?;
    let team = record.team_id.as_deref();
    require_target_permission(service, principal, permission, team).await?;
    let owns = principal.is_global_admin()
        || record.owner_email.as_deref() == Some(principal.email.as_str());
    let team_owner = if !owns
        && record.visibility == "team"
        && let Some(team) = team
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
    Ok(record)
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

fn set_names(record: &mut PromptRecord) -> Result<(), CatalogApiError> {
    record.custom_name_slug = slugify(&record.custom_name);
    record.name = match record.gateway_slug.as_deref() {
        Some(gateway) => format!("{gateway}-{}", record.custom_name_slug),
        None => record.custom_name_slug.clone(),
    };
    if record.custom_name_slug.is_empty() || record.name.len() > 255 {
        return Err(invalid("Invalid prompt name"));
    }
    Ok(())
}

fn apply_fields(
    service: &GatewayService,
    record: &mut PromptRecord,
    fields: PromptFields,
    create: bool,
) -> Result<(), CatalogApiError> {
    if let Some(display_name) = fields.display_name {
        record.display_name = Some(validate_name(&display_name)?);
    }
    if let Some(title) = fields.title {
        record.title = Some(validate_name(&title)?);
    }
    if let Some(description) = fields.description {
        record.description = Some(description.trim().chars().take(8192).collect());
    }
    if let Some(tags) = fields.tags {
        record.tags = normalized_tags(tags)?.to_string();
    }
    let mut required = None;
    if let Some(template) = fields.template {
        let template = if create { template.trim() } else { &template };
        if template.len() > service.max_prompt_bytes {
            let actual = format_bytes(template.len());
            let max = format_bytes(service.max_prompt_bytes);
            return Err(CatalogApiError(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"detail":{
                    "error":"Prompt template size limit exceeded",
                    "message":format!("Prompt template size ({actual}) exceeds maximum allowed size ({max})"),
                    "actual_size":template.len(),"max_size":service.max_prompt_bytes,
                }}),
            ));
        }
        required = Some(validate_template(template, &record.original_name, create)?);
        record.template = Some(template.to_owned());
    }
    if create || fields.arguments.is_some() {
        let required = match required {
            Some(required) => required,
            None => validate_template(
                record.template.as_deref().unwrap_or_default(),
                &record.original_name,
                create,
            )?,
        };
        let mut properties = indexmap::IndexMap::new();
        for argument in fields.arguments.unwrap_or_default() {
            if argument.name.is_empty()
                || argument.name.len() > 255
                || argument.name.chars().any(char::is_control)
            {
                return Err(invalid("Invalid prompt argument name"));
            }
            let mut spec = json!({"type":"string"});
            if let Some(description) = argument.description {
                spec["description"] = json!(description);
            }
            properties.insert(argument.name, spec);
        }
        record.argument_schema = Some(
            serde_json::to_string(&ArgumentSchema {
                kind: "object".to_owned(),
                properties,
                required,
            })
            .map_err(|_| CatalogApiError::unavailable())?,
        );
    }
    Ok(())
}

fn validate_template(
    template: &str,
    name: &str,
    create: bool,
) -> Result<Vec<String>, CatalogApiError> {
    static FORMAT_FIELD: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\{\{[^}]*\}\}|\{%[^}]*%\}|\{#[^}]*#\}|\{([A-Za-z_][A-Za-z0-9_]*)\}")
            .expect("valid prompt argument expression")
    });
    let env = minijinja::Environment::new();
    let syntax = env.template_from_str(template).map_err(|error| {
        if error.detail().is_some_and(|detail| detail.starts_with("unexpected end of input, expected end of ")) {
            let location = if create { json!(["body","prompt","template"]) } else { json!(["body","template"]) };
            return CatalogApiError(StatusCode::UNPROCESSABLE_ENTITY, json!({"detail":[{
                "loc":location,"msg":"Value error, Template contains potentially dangerous expressions","type":"value_error",
            }]}));
        }
        let reason = format!("Invalid Jinja2 syntax: {}", error.detail().unwrap_or("invalid template"));
        CatalogApiError(StatusCode::BAD_REQUEST, json!({"detail":{
            "error":"Template validation failed","message":format!("Template '{name}' validation failed: {reason}"),
            "template_name":name,"reason":reason,"pattern":null,
        }}))
    })?;
    let mut required = syntax.undeclared_variables(false);
    required.extend(
        FORMAT_FIELD
            .captures_iter(template)
            .filter_map(|found| found.get(1))
            .map(|name| name.as_str().to_owned()),
    );
    let mut required: Vec<_> = required.into_iter().collect();
    required.sort_unstable();
    Ok(required)
}

fn validate_name(name: &str) -> Result<String, CatalogApiError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > 255
        || name.chars().any(char::is_control)
        || name.contains(['<', '>'])
    {
        return Err(invalid("Invalid prompt name"));
    }
    Ok(name.to_owned())
}

fn validate_visibility(visibility: &str) -> Result<(), CatalogApiError> {
    if !matches!(visibility, "public" | "team" | "private") {
        return Err(invalid("Invalid prompt visibility"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn publish(service: &GatewayService, prompt: &PromptRecord) {
    service.subscriptions.changed(
        &prompt.visibility,
        prompt.team_id.as_deref(),
        prompt.owner_email.as_deref(),
    );
}

fn persistence_error(error: PromptWriteError, prompt: &PromptRecord) -> CatalogApiError {
    match error {
        PromptWriteError::Changed => CatalogApiError::detail(
            StatusCode::CONFLICT,
            format!(
                "Prompt {} is currently being modified by another request",
                prompt.id
            ),
        ),
        PromptWriteError::Duplicate { id, enabled } => {
            let visibility = match prompt.visibility.as_str() {
                "public" => "Public",
                "team" => "Team",
                _ => "Private",
            };
            let mut message = format!(
                "{visibility} Prompt already exists with name: {}",
                prompt.name
            );
            if !enabled {
                use std::fmt::Write as _;
                write!(message, " (currently inactive, ID: {id})").expect("string write");
            }
            CatalogApiError::detail(StatusCode::CONFLICT, message)
        }
        PromptWriteError::Database(sqlx::Error::Database(database))
            if database.is_unique_violation() =>
        {
            CatalogApiError::detail(
                StatusCode::CONFLICT,
                format!("Prompt already exists with name: {}", prompt.name),
            )
        }
        PromptWriteError::Database(error) => error.into(),
    }
}
