// SPDX-License-Identifier: Apache-2.0

use std::sync::LazyLock;

use percent_encoding::percent_decode_str;
use regex::Regex;

use super::events::ResourceEvent;
use super::*;
use crate::catalog::ResourceWriteError;

static UNSAFE_HTML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)</?(?:script|iframe|object|embed|link|meta|base|form|img|svg|video|audio|source|track|area|map|canvas|applet|frame|frameset|html|head|body|style)\b")
        .expect("valid resource HTML pattern")
});

pub struct ResourceLimits {
    pub max_bytes: usize,
    pub strict_mime: bool,
    pub allowed_mime: Vec<String>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_bytes: 102400,
            strict_mime: false,
            allowed_mime: [
                "text/plain",
                "text/markdown",
                "text/html",
                "text/csv",
                "application/json",
                "application/xml",
                "application/yaml",
                "application/pdf",
                "application/octet-stream",
                "image/png",
                "image/jpeg",
                "image/gif",
                "image/svg+xml",
                "image/webp",
                "audio/mpeg",
                "audio/wav",
                "video/mp4",
                "video/webm",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        }
    }
}

#[derive(Default, Deserialize)]
pub(super) struct ResourceFields {
    uri: Option<String>,
    name: Option<String>,
    #[serde(alias = "customName")]
    custom_name: Option<String>,
    description: Option<String>,
    title: Option<String>,
    #[serde(alias = "mimeType")]
    mime_type: Option<String>,
    #[serde(alias = "uriTemplate")]
    uri_template: Option<String>,
    content: Option<String>,
    tags: Option<Vec<Value>>,
    #[serde(alias = "extensionMetadata")]
    extension_metadata: Option<serde_json::Map<String, Value>>,
    #[serde(alias = "teamId")]
    team_id: Option<String>,
    visibility: Option<String>,
    #[serde(alias = "gatewayId")]
    gateway_id: Option<String>,
    #[serde(alias = "mcpServerId")]
    mcp_server_id: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct CreateRequest {
    resource: ResourceFields,
    #[serde(alias = "teamId")]
    team_id: Option<String>,
    visibility: Option<String>,
}

pub(super) async fn create(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(request): Json<CreateRequest>,
) -> Result<Json<Value>, ResourceError> {
    let mut fields = request.resource;
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
    let team = registration_team(
        &service,
        &principal,
        visibility,
        request.team_id.as_deref().or(fields.team_id.as_deref()),
    )
    .await
    .map_err(|error| ResourceError(error.status, json!({"message":error.message})))?;
    let role = team
        .as_deref()
        .map_or(RoleContext::AnyTeam, RoleContext::Team);
    if !service
        .access
        .allows(&principal, "resources.create", role, true)
        .await?
    {
        return Err(ResourceError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    let uri = fields
        .uri
        .take()
        .ok_or_else(|| invalid("Resource URI is required"))?;
    let name = fields
        .name
        .take()
        .ok_or_else(|| invalid("Resource name is required"))?;
    let body = fields
        .content
        .take()
        .ok_or_else(|| invalid("Resource content is required"))?;
    let name = validate_name(&name)?;
    let uri = validate_uri(&uri)?;
    let mut record = ResourceRecord {
        id: Uuid::new_v4().simple().to_string(),
        uri,
        name: name.clone(),
        original_name: Some(name.clone()),
        custom_name_slug: Some(slugify(&name)),
        owner_email: Some(principal.email.clone()),
        team_id: team,
        visibility: visibility.to_owned(),
        created_by: Some(principal.email.clone()),
        created_from_ip: client_address(peer),
        created_user_agent: user_agent(&headers),
        ..ResourceRecord::default()
    };
    record.gateway_id = resolve_gateway_id(fields.gateway_id.take(), fields.mcp_server_id.take())?;
    if let Some(gateway_id) = record.gateway_id.as_deref() {
        let scope = access::catalog_scope(Some(&principal));
        let visible = service
            .database
            .gateway_records(gateway_id)
            .await?
            .into_iter()
            .any(|gateway| {
                gateway.id == gateway_id
                    && scope.visible(
                        &gateway.visibility,
                        gateway.team_id.as_deref(),
                        gateway.owner_email.as_deref(),
                    )
            });
        if !visible {
            return Err(ResourceError::detail(
                StatusCode::NOT_FOUND,
                "Gateway not found",
            ));
        }
    }
    record.tags = "[]".to_owned();
    apply_metadata(
        &service.resource_limits,
        &mut record,
        fields,
        Some(body.trim()),
    )?;
    let record = service
        .database
        .save_managed_resource(None, &record, Some(body.trim()))
        .await
        .map_err(|error| persistence_error(error, &record))?;
    publish(&service, &record, ResourceEvent::Added);
    Ok(Json(metadata(&record, true)))
}

pub(super) async fn update(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(mut fields): Json<ResourceFields>,
) -> Result<Json<Value>, ResourceError> {
    let previous = editable(&service, &principal, &id, "resources.update", "update").await?;
    let mut record = previous.clone();
    if let Some(visibility) = fields.visibility.take() {
        validate_visibility(&visibility)?;
        if principal.visibility == TeamVisibility::Public && visibility != "public" {
            return Err(denied_team());
        }
        record.visibility = visibility;
    }
    if let Some(team) = fields.team_id.take()
        && record.team_id.as_deref() != Some(&team)
    {
        let permitted = match &principal.visibility {
            TeamVisibility::Admin => true,
            TeamVisibility::Teams(teams) => teams.contains(&team),
            TeamVisibility::Public => false,
        };
        if !permitted
            || !service.database.active_team(&team).await?
            || !principal.is_global_admin()
                && !service.database.team_owner(&principal.email, &team).await?
        {
            return Err(denied_team());
        }
        record.team_id = Some(team);
    }
    if record.visibility == "team" && record.team_id.is_none() {
        return Err(invalid("Cannot set visibility to 'team' without a team_id"));
    }
    let requested_name = fields.custom_name.take().or_else(|| {
        if record.gateway_id.is_none() {
            fields.name.take()
        } else {
            None
        }
    });
    if let Some(name) = requested_name {
        let name = validate_name(&name)?;
        let slug = slugify(&name);
        record.name = if let Some(gateway_id) = &record.gateway_id {
            let gateway = service
                .database
                .gateway_records(gateway_id)
                .await?
                .into_iter()
                .find(|gateway| &gateway.id == gateway_id)
                .ok_or_else(|| ResourceError::detail(StatusCode::NOT_FOUND, "Gateway not found"))?;
            format!("{}-{slug}", gateway.slug)
        } else {
            name
        };
        record.custom_name_slug = Some(slug);
    }
    record.modified_by = Some(principal.email.clone());
    if let Some(ip) = client_address(peer) {
        record.modified_from_ip = Some(ip);
    }
    if let Some(agent) = user_agent(&headers) {
        record.modified_user_agent = Some(agent);
    }
    let body = fields.content.take();
    apply_metadata(
        &service.resource_limits,
        &mut record,
        fields,
        body.as_deref(),
    )?;
    let record = service
        .database
        .save_managed_resource(Some(&previous), &record, body.as_deref())
        .await
        .map_err(|error| persistence_error(error, &record))?;
    if record.visibility != previous.visibility || record.team_id != previous.team_id {
        service.subscriptions.changed(
            &previous.visibility,
            previous.team_id.as_deref(),
            previous.owner_email.as_deref(),
        );
    }
    publish(&service, &record, ResourceEvent::Updated);
    Ok(Json(metadata(&record, true)))
}

#[derive(Deserialize)]
pub(super) struct StateRequest {
    activate: Option<String>,
}

pub(super) async fn set_state(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<StateRequest>,
) -> Result<Json<Value>, ResourceError> {
    let enabled = query
        .activate
        .as_deref()
        .map(|input| flag(Some(input)))
        .transpose()?
        .unwrap_or(true);
    let previous = editable(
        &service,
        &principal,
        &id,
        "resources.update",
        "change the state of",
    )
    .await?;
    let record = service
        .database
        .set_managed_resource_state(&previous, enabled)
        .await
        .map_err(|error| persistence_error(error, &previous))?;
    if record.enabled != previous.enabled {
        let event = if enabled {
            ResourceEvent::Activated
        } else {
            ResourceEvent::Deactivated
        };
        publish(&service, &record, event);
    }
    let action = if enabled { "activated" } else { "deactivated" };
    Ok(Json(
        json!({"status":"success","message":format!("Resource {id} {action}"),"resource":metadata(&record,false)}),
    ))
}

#[derive(Deserialize)]
pub(super) struct DeleteRequest {
    purge_metrics: Option<String>,
}

pub(super) async fn delete(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<DeleteRequest>,
) -> Result<Json<Value>, ResourceError> {
    let resource = editable(&service, &principal, &id, "resources.delete", "delete").await?;
    service
        .database
        .delete_managed_resource(&resource, flag(query.purge_metrics.as_deref())?)
        .await
        .map_err(|error| persistence_error(error, &resource))?;
    publish(&service, &resource, ResourceEvent::Deleted);
    Ok(Json(
        json!({"status":"success","message":format!("Resource {id} deleted")}),
    ))
}

async fn editable(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
    permission: &str,
    action: &str,
) -> Result<ResourceRecord, ResourceError> {
    require_resources(service, principal, permission, true).await?;
    let resource = find_visible(service, principal, id, true).await?;
    let team = resource.team_id.as_deref();
    let role = team.map_or(RoleContext::AnyTeam, RoleContext::Team);
    if !service
        .access
        .allows(principal, permission, role, true)
        .await?
    {
        return Err(ResourceError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    let owned =
        principal.is_global_admin() || resource.owner_email.as_deref() == Some(&principal.email);
    let team_owner = if !owned
        && resource.visibility == "team"
        && let Some(team) = team
    {
        service.database.team_owner(&principal.email, team).await?
    } else {
        false
    };
    if !owned && !team_owner {
        return Err(ResourceError::detail(
            StatusCode::FORBIDDEN,
            format!("Only the owner can {action} this resource"),
        ));
    }
    Ok(resource)
}

fn apply_metadata(
    limits: &ResourceLimits,
    record: &mut ResourceRecord,
    input: ResourceFields,
    body: Option<&str>,
) -> Result<(), ResourceError> {
    let uri_changed = input.uri.is_some() || record.mime_type.is_none();
    if let Some(uri) = input.uri {
        record.uri = validate_uri(&uri)?;
    }
    if let Some(template) = input.uri_template {
        record.uri_template = Some(validate_uri(&template)?);
    }
    if let Some(description) = input.description {
        record.description = Some(description.trim().chars().take(8192).collect());
    }
    if let Some(title) = input.title {
        if title.chars().count() > 255 || title.chars().any(char::is_control) {
            return Err(invalid("Invalid resource title"));
        }
        record.title = Some(title);
    }
    if uri_changed || input.mime_type.is_some() {
        let url = url::Url::parse(&record.uri).ok();
        let path = url.as_ref().map_or(record.uri.as_str(), url::Url::path);
        let inferred = mime_guess::from_path(path).first_raw();
        let mime = inferred
            .map(str::to_owned)
            .or_else(|| {
                input
                    .mime_type
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty())
            })
            .or_else(|| record.mime_type.clone())
            .unwrap_or_else(|| "text/plain".to_owned());
        validate_mime(limits, &mime)?;
        record.mime_type = Some(mime);
    }
    if let Some(body) = body {
        if body.len() > limits.max_bytes {
            return Err(ResourceError(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"detail":{
                    "error":"Resource content size limit exceeded",
                    "message":format!("Resource content size ({}) exceeds maximum allowed size ({})",
                        format_bytes(body.len()), format_bytes(limits.max_bytes)),
                    "actual_size":body.len(),"max_size":limits.max_bytes,
                }}),
            ));
        }
        if UNSAFE_HTML.is_match(body) {
            return Err(invalid(
                "Content contains HTML tags that may cause display issues",
            ));
        }
        record.size = Some(body.chars().count() as i32);
    }
    if let Some(tags) = input.tags {
        record.tags = normalized_tags(tags)?.to_string();
    }
    if let Some(extension) = input.extension_metadata {
        record.extension_metadata = Some(Value::Object(extension).to_string());
    }
    Ok(())
}

fn normalized_tags(tags: Vec<Value>) -> Result<Value, ResourceError> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for tag in tags {
        let label = tag
            .as_str()
            .or_else(|| tag.get("label").and_then(Value::as_str))
            .map(str::trim)
            .filter(|label| !label.is_empty() && !label.chars().any(char::is_control))
            .ok_or_else(|| invalid("Invalid resource tag"))?;
        let id = slugify(tag.get("id").and_then(Value::as_str).unwrap_or(label));
        if id.is_empty() {
            return Err(invalid("Invalid resource tag"));
        }
        if seen.insert(id.clone()) {
            normalized.push(json!({"id":id,"label":label}));
        }
    }
    Ok(json!(normalized))
}

fn validate_uri(input: &str) -> Result<String, ResourceError> {
    let input = input.trim();
    let decoded = percent_decode_str(input)
        .decode_utf8()
        .map_err(|_| invalid("Invalid resource URI encoding"))?;
    if input.is_empty()
        || input.len() > 255
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:/?=&%{}".contains(&byte))
        || input.bytes().enumerate().any(|(index, byte)| {
            byte == b'%'
                && !input
                    .as_bytes()
                    .get(index + 1..index + 3)
                    .is_some_and(|bytes| bytes.iter().all(u8::is_ascii_hexdigit))
        })
        || decoded.chars().any(char::is_control)
        || decoded.contains("..")
        || decoded.contains(['<', '>', '"', '\'', '\\'])
        || percent_decode_str(&decoded)
            .decode_utf8()
            .map_or(true, |again| again != decoded)
    {
        return Err(invalid("Invalid resource URI"));
    }
    Ok(input.to_owned())
}

fn validate_name(input: &str) -> Result<String, ResourceError> {
    let input = input.trim();
    if input.is_empty()
        || input.chars().count() > 255
        || input.chars().any(char::is_control)
        || input.contains(['<', '>'])
    {
        return Err(invalid("Invalid resource name"));
    }
    Ok(input.to_owned())
}

fn validate_visibility(visibility: &str) -> Result<(), ResourceError> {
    if !matches!(visibility, "public" | "private" | "team") {
        return Err(invalid("Invalid resource visibility"));
    }
    Ok(())
}

fn validate_mime(limits: &ResourceLimits, mime: &str) -> Result<(), ResourceError> {
    let bare = mime.split(';').next().unwrap_or_default().trim();
    if mime.chars().any(char::is_control)
        || bare.split_once('/').is_none_or(|(kind, subtype)| {
            [kind, subtype].into_iter().any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&byte))
            })
        })
    {
        return Err(invalid("Invalid resource MIME type"));
    }
    if limits.strict_mime
        && !limits
            .allowed_mime
            .iter()
            .any(|allowed| allowed == mime || allowed == bare)
    {
        let count = limits.allowed_mime.len();
        let mut allowed = limits.allowed_mime[..count.min(5)].join(", ");
        if count > 5 {
            use std::fmt::Write as _;
            write!(allowed, ", ... ({count} total)").expect("writing to a string is infallible");
        }
        return Err(ResourceError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            json!({"detail":{
                "error":"Unsupported Media Type","message":format!("MIME type '{mime}' is not allowed. Allowed types: {allowed}"),
                "mime_type":mime,"allowed_types":limits.allowed_mime,
            }}),
        ));
    }
    Ok(())
}

fn format_bytes(size: usize) -> String {
    if size < 1024 {
        format!("{size} B")
    } else if size < 1024 * 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    }
}

fn resolve_gateway_id(
    gateway: Option<String>,
    alias: Option<String>,
) -> Result<Option<String>, ResourceError> {
    if gateway
        .as_ref()
        .zip(alias.as_ref())
        .is_some_and(|(gateway, alias)| gateway != alias)
    {
        return Err(invalid("gateway_id and mcp_server_id conflict"));
    }
    Ok(gateway.or(alias))
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|agent| agent.to_str().ok())
        .map(str::to_owned)
}

fn client_address(peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> Option<String> {
    peer.map(|Extension(ConnectInfo(peer))| peer.ip().to_string())
}

fn publish(service: &GatewayService, record: &ResourceRecord, event: ResourceEvent) {
    service.subscriptions.changed(
        &record.visibility,
        record.team_id.as_deref(),
        record.owner_email.as_deref(),
    );
    service.resource_events.publish(event, record);
}

fn invalid(detail: &'static str) -> ResourceError {
    ResourceError::detail(StatusCode::UNPROCESSABLE_ENTITY, detail)
}

fn denied_team() -> ResourceError {
    ResourceError(
        StatusCode::FORBIDDEN,
        json!({
            "message":"Access issue: This API token does not have the required permissions for this team."
        }),
    )
}

fn persistence_error(error: ResourceWriteError, resource: &ResourceRecord) -> ResourceError {
    match error {
        ResourceWriteError::Duplicate { id, enabled } => {
            let mut visible = resource.visibility.clone();
            visible[..1].make_ascii_uppercase();
            let inactive = if enabled {
                String::new()
            } else {
                format!(" (currently inactive, ID: {id})")
            };
            ResourceError::detail(
                StatusCode::CONFLICT,
                format!(
                    "{visible} resource already exists with URI: {} — resource URIs must be unique within this scope (names may repeat).{inactive}",
                    resource.uri
                ),
            )
        }
        ResourceWriteError::Changed => {
            ResourceError::detail(StatusCode::CONFLICT, "Resource changed during the request")
        }
        ResourceWriteError::Database(error)
            if error
                .as_database_error()
                .is_some_and(|error| error.is_unique_violation()) =>
        {
            ResourceError::detail(StatusCode::CONFLICT, "Resource already exists")
        }
        ResourceWriteError::Database(error) => error.into(),
    }
}
