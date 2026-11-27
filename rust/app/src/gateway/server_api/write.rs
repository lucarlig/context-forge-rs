// SPDX-License-Identifier: Apache-2.0

use serde::Deserializer;
use serde_json::Map;

use super::*;
use crate::catalog::{ServerInterfaceInput, ServerLinkUpdate, ServerWriteError};

#[derive(Deserialize)]
pub(super) struct CreateServer {
    server: Option<Value>,
    virtual_server: Option<Value>,
    #[serde(alias = "teamId")]
    team_id: Option<String>,
    visibility: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ServerFields {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    icon: Option<String>,
    tags: Option<Vec<Value>>,
    #[serde(alias = "team_id")]
    team_id: Option<String>,
    visibility: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    instructions: Option<Option<String>>,
    #[serde(default, alias = "oauth_enabled", deserialize_with = "nullable")]
    oauth_enabled: Option<Option<bool>>,
    #[serde(default, alias = "oauth_config", deserialize_with = "nullable")]
    oauth_config: Option<Option<Map<String, Value>>>,
    #[serde(alias = "associated_tools")]
    associated_tools: Option<Vec<String>>,
    #[serde(alias = "associated_resources")]
    associated_resources: Option<Vec<String>>,
    #[serde(alias = "associated_prompts")]
    associated_prompts: Option<Vec<String>>,
    #[serde(alias = "associated_a2a_agents")]
    associated_a2a_agents: Option<Vec<String>>,
    interfaces: Option<Vec<InterfaceInput>>,
}

#[derive(Deserialize)]
struct InterfaceInput {
    protocol: String,
    binding: String,
    version: Option<String>,
    tenant: Option<String>,
    #[serde(default = "enabled")]
    enabled: bool,
}

fn enabled() -> bool {
    true
}

fn nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
pub(super) struct StateQuery {
    activate: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DeleteQuery {
    purge_metrics: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ApprovalInput {
    version: i32,
}

pub(super) async fn create(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(request): Json<CreateServer>,
) -> Result<(StatusCode, Json<Value>), CatalogApiError> {
    if request
        .server
        .as_ref()
        .zip(request.virtual_server.as_ref())
        .is_some_and(|(a, b)| a != b)
    {
        return Err(invalid("server and virtual_server conflict"));
    }
    let mut fields: ServerFields = serde_json::from_value(
        request
            .server
            .or(request.virtual_server)
            .ok_or_else(|| invalid("Server data is required"))?,
    )
    .map_err(|_| invalid("Invalid virtual server data"))?;
    let visibility = request
        .visibility
        .as_deref()
        .or(fields.visibility.as_deref())
        .unwrap_or("public");
    if request
        .team_id
        .as_ref()
        .zip(fields.team_id.as_ref())
        .is_some_and(|(outer, inner)| outer != inner)
    {
        return Err(denied_team());
    }
    let team_id = write_scope(
        &service,
        &principal,
        visibility,
        request.team_id.as_deref().or(fields.team_id.as_deref()),
        "servers.create",
    )
    .await?;
    let name = validate_name(
        fields
            .name
            .take()
            .as_deref()
            .ok_or_else(|| invalid("Server name is required"))?,
    )?;
    let id = fields
        .id
        .take()
        .as_deref()
        .map(server_uuid)
        .transpose()?
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let mut server = ServerRecord {
        id,
        name,
        team_id,
        visibility: visibility.to_owned(),
        owner_email: Some(principal.email.clone()),
        created_by: Some(principal.email.clone()),
        created_from_ip: client_address(peer),
        created_user_agent: user_agent(&headers),
        tags: "[]".to_owned(),
        ..ServerRecord::default()
    };
    let links = apply_fields(&service, &principal, &mut server, fields, true).await?;
    let server = service
        .database
        .save_managed_server(
            None,
            &server,
            &links,
            access::catalog_scope(Some(&principal)),
        )
        .await
        .map_err(|error| persistence_error(error, &server, true))?;
    publish(&service, &server);
    Ok((
        StatusCode::CREATED,
        Json(with_links(&service, &principal, &server).await?),
    ))
}

pub(super) async fn update(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(mut fields): Json<ServerFields>,
) -> Result<Json<Value>, CatalogApiError> {
    let prior = editable(
        &service,
        &principal,
        &id,
        "servers.update",
        "update this server",
    )
    .await?;
    let mut server = prior.clone();
    if let Some(id) = fields.id.take() {
        server.id = server_uuid(&id)?;
    }
    if let Some(name) = fields.name.take() {
        server.name = validate_name(&name)?;
    }
    if fields.visibility.is_some() || fields.team_id.is_some() {
        let visibility = fields.visibility.as_deref().unwrap_or(&server.visibility);
        let team = fields.team_id.as_deref().or(server.team_id.as_deref());
        server.team_id =
            write_scope(&service, &principal, visibility, team, "servers.update").await?;
        server.visibility = visibility.to_owned();
    }
    let links = apply_fields(&service, &principal, &mut server, fields, false).await?;
    server.modified_by = Some(principal.email.clone());
    server.modified_from_ip = client_address(peer).or(server.modified_from_ip);
    server.modified_user_agent = user_agent(&headers).or(server.modified_user_agent);
    let server = service
        .database
        .save_managed_server(
            Some(&prior),
            &server,
            &links,
            access::catalog_scope(Some(&principal)),
        )
        .await
        .map_err(|error| persistence_error(error, &server, false))?;
    if prior.visibility != server.visibility || prior.team_id != server.team_id {
        publish(&service, &prior);
    }
    publish(&service, &server);
    Ok(Json(with_links(&service, &principal, &server).await?))
}

pub(super) async fn set_state(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<StateQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    let active = query.activate.is_none() || flag(query.activate.as_deref())?;
    let action = if active {
        "activate the Server"
    } else {
        "deactivate the Server"
    };
    let prior = editable(&service, &principal, &id, "servers.update", action).await?;
    let server = service
        .database
        .set_managed_server_state(&prior, active)
        .await
        .map_err(|error| persistence_error(error, &prior, false))?;
    if prior.enabled != server.enabled {
        publish(&service, &server);
    }
    Ok(Json(with_links(&service, &principal, &server).await?))
}

pub(super) async fn delete(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    let server = editable(
        &service,
        &principal,
        &id,
        "servers.delete",
        "delete this server",
    )
    .await?;
    service
        .database
        .delete_managed_server(&server, flag(query.purge_metrics.as_deref())?)
        .await
        .map_err(|error| persistence_error(error, &server, false))?;
    publish(&service, &server);
    Ok(Json(
        json!({"status":"success","message":format!("Server {id} deleted successfully")}),
    ))
}

pub(super) async fn approve(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(input): Json<ApprovalInput>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "servers.update", true).await?;
    require_oauth_admin(&principal)?;
    if input.version < 1 {
        return Err(invalid("Server version must be positive"));
    }
    let server = find_visible(&service, &principal, &id).await?;
    if server.version != Some(input.version) {
        return Err(review_again());
    }
    let config = decode_config(server.oauth_config.as_deref());
    if !server.oauth_enabled
        || oauth::oauth_issuers(&config, service.allow_http_oauth_loopback).is_empty()
    {
        return Err(invalid(
            "Enabled OAuth with a valid authorization server is required for approval",
        ));
    }
    let generation = Uuid::new_v4().simple().to_string();
    let version = service
        .database
        .approve_managed_server_oauth(&server, &generation)
        .await
        .map_err(|error| match error {
            ServerWriteError::Changed => review_again(),
            other => persistence_error(other, &server, false),
        })?;
    publish(&service, &server);
    Ok(Json(
        json!({"oauth_config_approved":true,"version":version}),
    ))
}

async fn editable(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
    permission: &str,
    action: &str,
) -> Result<ServerRecord, CatalogApiError> {
    require_catalog_permission(service, principal, permission, true).await?;
    let server = find_visible(service, principal, id).await?;
    let team = server.team_id.as_deref();
    require_for_team(service, principal, permission, team).await?;
    let owns = principal.is_global_admin()
        || server.owner_email.as_deref() == Some(principal.email.as_str());
    let team_owner = if !owns
        && server.visibility == "team"
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
    Ok(server)
}

async fn write_scope(
    service: &GatewayService,
    principal: &Principal,
    visibility: &str,
    team: Option<&str>,
    permission: &str,
) -> Result<Option<String>, CatalogApiError> {
    if !matches!(visibility, "public" | "private" | "team") {
        return Err(invalid("Invalid server visibility"));
    }
    let team = registration_team(service, principal, visibility, team)
        .await
        .map_err(|error| CatalogApiError(error.status, json!({"message":error.message})))?;
    require_for_team(service, principal, permission, team.as_deref()).await?;
    Ok(team)
}

async fn require_for_team(
    service: &GatewayService,
    principal: &Principal,
    permission: &str,
    team: Option<&str>,
) -> Result<(), CatalogApiError> {
    let role = team.map_or(RoleContext::AnyTeam, RoleContext::Team);
    if !service
        .access
        .allows(principal, permission, role, true)
        .await?
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    Ok(())
}

async fn apply_fields(
    service: &GatewayService,
    principal: &Principal,
    server: &mut ServerRecord,
    input: ServerFields,
    create: bool,
) -> Result<ServerLinkUpdate, CatalogApiError> {
    if let Some(description) = input.description {
        server.description = Some(description.trim().chars().take(8192).collect());
    }
    if let Some(icon) = input.icon {
        let icon = icon.trim();
        if !icon.is_empty() && service.upstream.check_endpoint(icon).is_err() {
            return Err(invalid("Invalid server icon URL"));
        }
        server.icon = Some(icon.to_owned());
    }
    if let Some(tags) = input.tags {
        server.tags = normalized_tags(tags)?.to_string();
    }
    if let Some(instructions) = input.instructions {
        if instructions
            .as_ref()
            .is_some_and(|text| text.chars().count() > 8192)
        {
            return Err(invalid("Instructions must be at most 8192 characters"));
        }
        server.instructions =
            instructions.map(|text| if create { text.trim().to_owned() } else { text });
    }
    if input.oauth_enabled.is_some() || input.oauth_config.is_some() {
        require_oauth_admin(principal)?;
        apply_oauth(
            service,
            server,
            input.oauth_enabled.flatten(),
            input.oauth_config,
        )
        .await?;
    }
    Ok(ServerLinkUpdate {
        tools: validate_link_ids(input.associated_tools, "associated_tools", create)?,
        resources: validate_link_ids(input.associated_resources, "associated_resources", create)?,
        prompts: validate_link_ids(input.associated_prompts, "associated_prompts", create)?,
        agents: validate_link_ids(input.associated_a2a_agents, "associated_a2a_agents", create)?,
        interfaces: input
            .interfaces
            .map(|interfaces| validate_interfaces(service, interfaces))
            .transpose()?,
    })
}

async fn apply_oauth(
    service: &GatewayService,
    server: &mut ServerRecord,
    enabled: Option<bool>,
    input: Option<Option<Map<String, Value>>>,
) -> Result<(), CatalogApiError> {
    let was_enabled = server.oauth_enabled;
    let old = decode_config(server.oauth_config.as_deref());
    server.oauth_enabled = enabled.unwrap_or(was_enabled);
    let mut config = match (enabled, input) {
        (Some(false), _) | (_, Some(None)) => Value::Null,
        (_, Some(Some(config))) => Value::Object(config),
        (_, None) => old.clone(),
    };
    if config != old {
        protect_oauth(service, &mut config, Some(&old)).await?;
    }
    if config != old || server.oauth_enabled != was_enabled {
        server.oauth_config_generation = Some(Uuid::new_v4().simple().to_string());
        server.oauth_config_approved = server.oauth_enabled
            && !oauth::oauth_issuers(&config, service.allow_http_oauth_loopback).is_empty();
        server.oauth_config = (!config.is_null()).then(|| config.to_string());
    }
    Ok(())
}

async fn protect_oauth(
    service: &GatewayService,
    value: &mut Value,
    before: Option<&Value>,
) -> Result<(), CatalogApiError> {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                let old = before.and_then(|before| before.get(key));
                if let Some(secret) = value.as_str().filter(|text| !text.is_empty())
                    && is_oauth_secret(key)
                {
                    if secret == "*****" {
                        *value = old
                            .filter(|old| old.is_string())
                            .cloned()
                            .ok_or_else(|| invalid("Masked OAuth secret has no stored value"))?;
                        continue;
                    }
                    let vault = service.vault.as_ref().ok_or_else(|| {
                        CatalogApiError::detail(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "OAuth credential encryption unavailable",
                        )
                    })?;
                    if let Some(old) = old.and_then(Value::as_str)
                        && SecretEnvelope::is_encrypted(old)
                        && vault
                            .open(old.to_owned())
                            .await
                            .is_ok_and(|plain| plain.as_str() == secret)
                    {
                        *value = old.into();
                        continue;
                    }
                    *value = vault
                        .seal(Zeroizing::new(secret.to_owned()))
                        .await
                        .map_err(|_| CatalogApiError::unavailable())?
                        .into();
                } else {
                    Box::pin(protect_oauth(service, value, old)).await?;
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter_mut().enumerate() {
                Box::pin(protect_oauth(
                    service,
                    value,
                    before.and_then(|before| before.get(index)),
                ))
                .await?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn decode_config(config: Option<&str>) -> Value {
    config
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_default()
}

fn require_oauth_admin(principal: &Principal) -> Result<(), CatalogApiError> {
    if principal.is_global_admin() {
        return Ok(());
    }
    Err(CatalogApiError::detail(
        StatusCode::FORBIDDEN,
        "Virtual-server OAuth settings require unrestricted platform-admin authority",
    ))
}

fn validate_interfaces(
    service: &GatewayService,
    inputs: Vec<InterfaceInput>,
) -> Result<Vec<ServerInterfaceInput>, CatalogApiError> {
    let mut seen = HashSet::new();
    inputs
        .into_iter()
        .map(|input| {
            let protocol = input.protocol.trim().to_ascii_lowercase();
            let binding = input.binding.trim().to_owned();
            if !valid_component(&protocol, 50, b"._-")
                || binding.len() > 255
                || service.upstream.check_endpoint(&binding).is_err()
                || input
                    .version
                    .as_deref()
                    .is_some_and(|version| !valid_component(version.trim(), 20, b"._+-"))
                || input.tenant.as_deref().is_some_and(|tenant| {
                    tenant.chars().count() > 255 || tenant.chars().any(char::is_control)
                })
            {
                return Err(invalid("Invalid server interface"));
            }
            if !seen.insert((protocol.clone(), binding.clone())) {
                return Err(invalid("Duplicate server protocol binding"));
            }
            Ok(ServerInterfaceInput {
                protocol,
                binding,
                version: input.version.map(|value| value.trim().to_owned()),
                tenant: input.tenant.map(|value| value.trim().to_owned()),
                enabled: input.enabled,
            })
        })
        .collect()
}

fn valid_component(value: &str, len: usize, special: &[u8]) -> bool {
    value.len() <= len
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || special.contains(&byte))
}

fn server_uuid(input: &str) -> Result<String, CatalogApiError> {
    let input = input.trim();
    if !matches!(input.len(), 32 | 36) {
        return Err(invalid("Invalid server ID"));
    }
    Uuid::parse_str(input)
        .map(|id| id.simple().to_string())
        .map_err(|_| invalid("Invalid server ID"))
}

fn validate_link_ids(
    ids: Option<Vec<String>>,
    field: &'static str,
    create: bool,
) -> Result<Option<Vec<String>>, CatalogApiError> {
    ids.map(|ids|ids.into_iter().map(|input| {
        server_uuid(&input).map_err(|_| {
            let location=if create {json!(["body","server",field])} else {json!(["body",field])};
            CatalogApiError(StatusCode::UNPROCESSABLE_ENTITY,json!({"detail":[{
                "type":"value_error","loc":location,"msg":format!("Value error, Invalid ID format: '{input}'. {field} must contain UUID values, not names. Use UUIDs from the respective entity listings.")
            }]}))
        })
    }).collect()).transpose()
}

fn validate_name(name: &str) -> Result<String, CatalogApiError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > 255
        || name.chars().any(char::is_control)
        || name.contains(['<', '>'])
    {
        return Err(invalid("Invalid server name"));
    }
    Ok(name.to_owned())
}

fn publish(service: &GatewayService, server: &ServerRecord) {
    service.subscriptions.changed(
        &server.visibility,
        server.team_id.as_deref(),
        server.owner_email.as_deref(),
    );
}

fn invalid(message: &'static str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn review_again() -> CatalogApiError {
    CatalogApiError::detail(
        StatusCode::CONFLICT,
        "Server changed. Review its OAuth configuration again.",
    )
}

fn persistence_error(
    error: ServerWriteError,
    server: &ServerRecord,
    create: bool,
) -> CatalogApiError {
    match error {
        ServerWriteError::Changed => CatalogApiError::detail(
            StatusCode::CONFLICT,
            format!(
                "Server {} is currently being modified by another request",
                server.id
            ),
        ),
        ServerWriteError::Duplicate { id, enabled } => {
            let visibility = match server.visibility.as_str() {
                "public" => "Public",
                "team" => "Team",
                _ => "Private",
            };
            let mut message = format!(
                "{visibility} Server already exists with name: {}",
                server.name
            );
            if !enabled {
                use std::fmt::Write as _;
                write!(message, " (currently inactive, ID: {id})").expect("string write");
            }
            CatalogApiError::detail(StatusCode::CONFLICT, message)
        }
        ServerWriteError::DuplicateId => CatalogApiError::detail(
            StatusCode::CONFLICT,
            format!("Server with ID {} already exists", server.id),
        ),
        ServerWriteError::MissingLinks { kind, ids } => {
            let action = if create { "register" } else { "update" };
            let message = if let [id] = ids.as_slice() {
                format!(
                    "{} with id {id} does not exist.",
                    kind.trim_end_matches('s')
                )
            } else {
                let quoted = ids
                    .iter()
                    .map(|id| format!("'{id}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{kind} with ids {{{quoted}}} do not exist.")
            };
            CatalogApiError::detail(
                StatusCode::BAD_REQUEST,
                format!("Failed to {action} server: {message}"),
            )
        }
        ServerWriteError::Database(sqlx::Error::Database(database))
            if database.is_unique_violation() || database.is_foreign_key_violation() =>
        {
            CatalogApiError::detail(
                StatusCode::CONFLICT,
                "Server change conflicts with an existing record",
            )
        }
        ServerWriteError::Database(error) => error.into(),
    }
}
