// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use axum::extract::ConnectInfo;
use serde::Deserializer;

use super::*;
use crate::{
    catalog::{GatewayConnectionRow, GatewayMode},
    credentials::UpdateAuthError,
};

#[derive(Deserialize)]
pub(crate) struct GatewayUpdate {
    name: Option<String>,
    description: Option<String>,
    url: Option<String>,
    transport: Option<String>,
    visibility: Option<String>,
    #[serde(alias = "teamId")]
    team_id: Option<String>,
    tags: Option<Vec<Value>>,
    #[serde(alias = "passthroughHeaders")]
    passthrough_headers: Option<Vec<String>>,
    #[serde(alias = "identityPropagation")]
    identity_propagation: Option<Value>,
    #[serde(
        default,
        alias = "refreshIntervalSeconds",
        deserialize_with = "nullable_field"
    )]
    refresh_interval_seconds: Option<Option<i32>>,
    #[serde(alias = "gatewayMode")]
    gateway_mode: Option<String>,
    #[serde(default, alias = "oneTimeAuth")]
    one_time_auth: Option<bool>,
    #[serde(flatten)]
    auth: AuthInput,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

fn nullable_field<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

pub(crate) async fn update(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<GatewayUpdate>,
) -> Result<Json<Value>, UpdateError> {
    let previous = manageable(
        &service,
        &principal,
        id,
        "gateways.update",
        "Only the owner can update this gateway",
    )
    .await?;
    if previous.status != "active" {
        return Err(ManagementError::LifecycleInProgress.into());
    }
    let mut gateway = previous.clone();
    let (mut auth, one_time_auth) = apply_fields(&service, &principal, &mut gateway, input).await?;
    gateway.modified_by = Some(principal.email.clone());
    if let Some(Extension(ConnectInfo(address))) = peer {
        gateway.modified_from_ip = Some(address.ip().to_string());
    }
    if let Some(agent) = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
    {
        gateway.modified_user_agent = Some(agent.to_owned());
    }

    let transport = UpstreamTransport::from_name(&gateway.transport).ok_or_else(|| {
        UpdateError::message(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unsupported gateway transport",
        )
    })?;
    let destination_changed =
        gateway.url != previous.url || gateway.transport != previous.transport;
    let mut connection = service
        .database
        .gateway_connection(&previous.id, &previous.url, true, Some(previous.version))
        .await
        .map_err(ManagementError::from)?;
    let auth_changed = if let Some(connection) = &mut connection {
        let changed = auth.apply_update(
            connection,
            service.credential_cipher.as_ref(),
            service.query_auth_hosts.as_ref(),
            &gateway.url,
        )?;
        if changed && !one_time_auth {
            gateway.auth_type = Some(connection.kind.clone());
            gateway.auth_value.clone_from(&connection.headers);
            gateway.auth_query_params.clone_from(&connection.query);
            gateway.sigv4_config.clone_from(&connection.sigv4);
            gateway.oauth_config.clone_from(&connection.oauth);
        }
        changed || one_time_auth
    } else {
        if auth.has_update() || one_time_auth {
            return Err(ManagementError::ConcurrentChange.into());
        }
        false
    };
    let discovered = discover_updated_gateway(
        &service,
        &gateway,
        transport,
        connection,
        destination_changed || auth_changed,
    )
    .await?;
    if one_time_auth {
        gateway.auth_type = Some("one_time_auth".into());
        gateway.auth_value = None;
        gateway.auth_query_params = None;
        gateway.oauth_config = None;
        gateway.sigv4_config = None;
    }
    if discovered.is_some() {
        gateway.reachable = true;
    }
    let discovery =
        discovered
            .as_ref()
            .map(|(tools, capabilities, metadata)| CatalogRefreshInput {
                tools,
                capabilities,
                metadata,
                include_resources: true,
                include_prompts: true,
                activating: false,
            });
    match service
        .database
        .update_gateway_metadata(
            &previous,
            &gateway,
            discovery,
            service.credential_cipher.as_ref(),
        )
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return Err(ManagementError::ConcurrentChange.into()),
        Err(RegistrationError::NameConflict) => {
            return Err(UpdateError::message(
                StatusCode::CONFLICT,
                "Gateway name already exists",
            ));
        }
        Err(RegistrationError::UrlConflict) => {
            return Err(UpdateError::message(
                StatusCode::CONFLICT,
                "Gateway already exists",
            ));
        }
        Err(RegistrationError::ToolNameConflict) => {
            return Err(ManagementError::ToolNameConflict.into());
        }
        Err(RegistrationError::Database(error)) => return Err(ManagementError::from(error).into()),
        Err(error) => {
            return Err(UpdateError::message(
                StatusCode::BAD_REQUEST,
                error.to_string(),
            ));
        }
    }
    if destination_changed
        || auth_changed
        || previous.visibility != gateway.visibility
        || previous.team_id != gateway.team_id
    {
        service.subscriptions.removed(
            &previous.id,
            &previous.visibility,
            previous.team_id.as_deref(),
            previous.owner_email.as_deref(),
        );
    }
    service.subscriptions.changed(
        &gateway.visibility,
        gateway.team_id.as_deref(),
        gateway.owner_email.as_deref(),
    );
    let updated = service
        .database
        .gateway_records(&gateway.id)
        .await
        .map_err(ManagementError::from)?
        .into_iter()
        .next()
        .ok_or(ManagementError::ConcurrentChange)?;
    Ok(Json(response(&updated, service.credential_cipher.as_ref())))
}

async fn apply_fields(
    service: &GatewayService,
    principal: &Principal,
    gateway: &mut GatewayRecord,
    input: GatewayUpdate,
) -> Result<(AuthInput, bool), UpdateError> {
    let GatewayUpdate {
        name,
        description,
        url,
        transport,
        visibility,
        team_id,
        tags,
        passthrough_headers,
        identity_propagation,
        refresh_interval_seconds,
        gateway_mode,
        one_time_auth,
        auth,
        extra,
    } = input;
    if let Some(name) = name {
        let name = name.trim();
        let slug = slugify(name);
        if slug.is_empty() || name.len() > 255 {
            return Err(UpdateError::validation(
                "name",
                "Value error, Gateway name cannot be empty",
                "value_error",
                None,
            ));
        }
        gateway.name = name.to_owned();
        gateway.slug = slug;
    }
    if let Some(description) = description {
        gateway.description = Some(description.trim().to_owned());
    }
    if let Some(url) = url {
        let url = url.trim();
        if let Ok(parsed) = url::Url::parse(url)
            && !matches!(parsed.scheme(), "http" | "https" | "ws" | "wss")
        {
            let mut error = UpdateError::validation(
                "url",
                "Value error, Gateway URL must start with one of: http://, https://, ws://, wss://",
                "value_error",
                None,
            );
            error.1["reason_code"] = "url_scheme_not_allowed".into();
            return Err(error);
        }
        service.upstream.check_endpoint(url).map_err(|_| {
            UpdateError::message(
                StatusCode::BAD_REQUEST,
                "Gateway URL is invalid or disallowed",
            )
        })?;
        gateway.url = url.to_owned();
    }
    if let Some(transport) = transport {
        let transport = UpstreamTransport::from_name(&transport).ok_or_else(|| {
            UpdateError::validation(
                "transport",
                &format!("Value error, Invalid transport type: '{transport}'. Must be one of: SSE, STREAMABLEHTTP (case-insensitive)"),
                "value_error", None,
            )
        })?;
        gateway.transport = transport.name().to_owned();
    }
    if let Some(mode) = gateway_mode {
        match mode.as_str() {
            "cache" => gateway.gateway_mode = GatewayMode::Cache.name().to_owned(),
            "direct_proxy" if service.direct_proxy_timeout.is_some() => {
                gateway.gateway_mode = GatewayMode::DirectProxy.name().to_owned()
            }
            "direct_proxy" => {
                return Err(UpdateError::message(
                    StatusCode::BAD_REQUEST,
                    "Direct proxy gateway mode is disabled",
                ));
            }
            _ => {
                return Err(UpdateError::message(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Unsupported gateway mode",
                ));
            }
        }
    }
    if let Some(visibility) = visibility {
        if !matches!(visibility.as_str(), "public" | "private" | "team") {
            return Err(UpdateError::validation(
                "visibility",
                "Invalid gateway visibility",
                "value_error",
                None,
            ));
        }
        if principal.visibility == TeamVisibility::Public && visibility != "public" {
            return Err(ManagementError::Denied.into());
        }
        gateway.visibility = visibility;
    }
    if let Some(team) = team_id.filter(|team| Some(team.as_str()) != gateway.team_id.as_deref()) {
        let in_scope = match &principal.visibility {
            TeamVisibility::Admin => true,
            TeamVisibility::Teams(teams) => teams.iter().any(|id| id == &team),
            TeamVisibility::Public => false,
        };
        if !in_scope
            || !service
                .database
                .active_team(&team)
                .await
                .map_err(ManagementError::from)?
            || !principal.is_global_admin()
                && !service
                    .database
                    .team_owner(&principal.email, &team)
                    .await
                    .map_err(ManagementError::from)?
        {
            return Err(ManagementError::Denied.into());
        }
        gateway.team_id = Some(team);
    }
    if gateway.visibility == "team" && gateway.team_id.is_none() {
        return Err(UpdateError::validation(
            "team_id",
            "Team visibility requires a team",
            "value_error",
            None,
        ));
    }
    if let Some(interval) = refresh_interval_seconds {
        if interval.is_some_and(|value| value < 60) {
            return Err(UpdateError::validation(
                "refresh_interval_seconds",
                "Input should be greater than or equal to 60",
                "greater_than_equal",
                Some(json!({"ge":60})),
            ));
        }
        gateway.refresh_interval_seconds = interval;
    }
    if let Some(tags) = tags {
        if tags.iter().any(|tag| {
            tag.as_str().is_none_or(|label| label.trim().is_empty())
                && !(tag["id"].is_string() && tag["label"].is_string())
        }) {
            return Err(UpdateError::validation(
                "tags",
                "Invalid gateway tag",
                "value_error",
                None,
            ));
        }
        gateway.tags = json!(tags).to_string();
    }
    if let Some(headers) = passthrough_headers {
        if headers
            .iter()
            .any(|name| HeaderName::from_bytes(name.as_bytes()).is_err())
        {
            return Err(UpdateError::validation(
                "passthrough_headers",
                "Invalid passthrough header name",
                "value_error",
                None,
            ));
        }
        gateway.passthrough_headers = Some(json!(headers).to_string());
    }
    if let Some(identity) = identity_propagation {
        service
            .identity_forwarding
            .validate(&identity)
            .map_err(|_| {
                UpdateError::validation(
                    "identity_propagation",
                    "Invalid upstream identity propagation configuration",
                    "value_error",
                    None,
                )
            })?;
        gateway.identity_propagation = Some(identity.to_string());
    }
    if extra.iter().any(|(name, value)| {
        let normalized = name
            .chars()
            .filter(|character| *character != '_')
            .collect::<String>()
            .to_ascii_lowercase();
        matches!(
            normalized.as_str(),
            "cacertificate"
                | "cacertificatesig"
                | "signingalgorithm"
                | "clientcert"
                | "clientkey"
                | "toolvalidationpolicy"
        ) || normalized == "authvalue" && !value.is_null() && value.as_str() != Some("*****")
    }) {
        return Err(UpdateError::message(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unsupported gateway configuration update",
        ));
    }
    Ok((auth, one_time_auth.unwrap_or(false)))
}

async fn discover_updated_gateway(
    service: &GatewayService,
    gateway: &GatewayRecord,
    transport: UpstreamTransport,
    connection: Option<GatewayConnectionRow>,
    connection_changed: bool,
) -> Result<
    Option<(
        Vec<ToolDefinition>,
        Value,
        crate::upstream::DiscoveredMetadata,
    )>,
    UpdateError,
> {
    let Some(connection) = connection else {
        if connection_changed {
            return Err(UpdateError::message(
                StatusCode::BAD_GATEWAY,
                "Could not load upstream authentication",
            ));
        }
        return Ok(None);
    };
    let Ok(credentials) = service
        .connection_credentials(&gateway.id, &gateway.url, connection, None, None)
        .await
    else {
        if connection_changed {
            return Err(UpdateError::message(
                StatusCode::BAD_GATEWAY,
                "Could not load upstream authentication",
            ));
        }
        return Ok(None);
    };
    let discovered = service
        .upstream
        .discover_catalog(UpstreamEndpoint {
            url: &gateway.url,
            transport,
            credentials: credentials.as_ref(),
        })
        .await;
    match discovered {
        Ok((catalog, metadata)) => {
            let tools = catalog
                .tools
                .into_iter()
                .map(serde_json::from_value)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| {
                    UpdateError::message(
                        StatusCode::BAD_GATEWAY,
                        "Upstream returned an invalid tool",
                    )
                })?;
            Ok(Some((tools, catalog.capabilities, metadata)))
        }
        Err(UpstreamError::InvalidUrl | UpstreamError::BlockedDestination)
            if connection_changed =>
        {
            Err(UpdateError::message(
                StatusCode::BAD_REQUEST,
                "Gateway URL is invalid or disallowed",
            ))
        }
        Err(error) if connection_changed => {
            let endpoint = url::Url::parse(&gateway.url)
                .ok()
                .map(|mut url| {
                    url.set_query(None);
                    url.set_fragment(None);
                    url.to_string()
                })
                .unwrap_or_default();
            let detail = match error {
                UpstreamError::Status(status) => format!("server responded with HTTP {status}"),
                error => error.to_string(),
            };
            Err(UpdateError::message(
                StatusCode::BAD_GATEWAY,
                format!("Failed to initialize gateway at {endpoint}: {detail}"),
            ))
        }
        Err(error) => {
            tracing::warn!(gateway = %gateway.id, %error, "gateway update discovery failed");
            Ok(None)
        }
    }
}

pub(crate) struct UpdateError(StatusCode, Value);

impl UpdateError {
    fn message(status: StatusCode, message: impl Into<String>) -> Self {
        Self(status, json!({"message":message.into()}))
    }

    fn validation(field: &str, message: &str, kind: &str, context: Option<Value>) -> Self {
        let mut entry = json!({"loc":["body",field],"msg":message,"type":kind});
        if let Some(context) = context {
            entry["ctx"] = context;
        }
        Self(StatusCode::UNPROCESSABLE_ENTITY, json!({"detail":[entry]}))
    }
}

impl From<ManagementError> for UpdateError {
    fn from(error: ManagementError) -> Self {
        match error {
            ManagementError::NotFound(_) => {
                Self::message(StatusCode::NOT_FOUND, "Gateway not found")
            }
            ManagementError::Ownership(message) => Self::message(StatusCode::FORBIDDEN, message),
            ManagementError::Denied => Self::message(StatusCode::FORBIDDEN, "Access denied"),
            ManagementError::Conflict(_) | ManagementError::ToolNameConflict => Self::message(
                StatusCode::CONFLICT,
                "Gateway tool name conflicts with an existing tool",
            ),
            ManagementError::ConcurrentChange | ManagementError::LifecycleInProgress => {
                Self::message(StatusCode::CONFLICT, "Gateway changed during request")
            }
            _ => Self::message(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        }
    }
}

impl From<UpdateAuthError> for UpdateError {
    fn from(error: UpdateAuthError) -> Self {
        match error {
            UpdateAuthError::Auth(AuthError::Encryption(_)) => Self::message(
                StatusCode::SERVICE_UNAVAILABLE,
                "Gateway credential encryption unavailable",
            ),
            error => Self::validation("auth_type", &error.to_string(), "value_error", None),
        }
    }
}

impl IntoResponse for UpdateError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}
