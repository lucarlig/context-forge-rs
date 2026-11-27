// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::catalog::GatewayConnectionRow;

#[derive(Deserialize)]
pub(super) struct AgentPatch {
    name: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    description: Option<Option<String>>,
    endpoint_url: Option<String>,
    agent_type: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    protocol_binding: Option<Option<String>>,
    protocol_version: Option<String>,
    capabilities: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "nullable")]
    skills: Option<Option<Vec<Map<String, Value>>>>,
    config: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "nullable")]
    passthrough_headers: Option<Option<Vec<String>>>,
    tags: Option<Vec<Value>>,
    #[serde(default, deserialize_with = "nullable")]
    team_id: Option<Option<String>>,
    visibility: Option<String>,
    #[serde(flatten)]
    uaid: UaidInput,
    #[serde(flatten)]
    auth: AuthInput,
}

fn nullable<'de, D, T>(input: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(input).map(Some)
}

pub(super) async fn update(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(mut patch): Json<AgentPatch>,
) -> Result<Json<Value>, CatalogApiError> {
    let previous = editable(&app, &principal, &id, "a2a.update", "update this agent").await?;
    let mut agent = previous.clone();
    patch.apply_metadata(&mut agent)?;
    validate_scope(&app, &principal, &previous, &agent).await?;
    if (agent.name != previous.name || agent.team_id != previous.team_id)
        && app.database.agent_has_enforced_binding(&previous).await?
        && !app.database.agent_has_enforced_binding(&agent).await?
    {
        return Err(CatalogApiError::detail(
            StatusCode::CONFLICT,
            "The A2A agent update would remove an enforced invocation policy",
        ));
    }
    let endpoint_changed = agent.endpoint_url != previous.endpoint_url;
    if endpoint_changed {
        app.upstream
            .check_endpoint(&agent.endpoint_url)
            .map_err(|_| {
                CatalogApiError::detail(
                    StatusCode::BAD_REQUEST,
                    "Outbound A2A URL blocked by URL policy",
                )
            })?;
        if previous.uaid.is_some() && !app.uaid.permits_endpoint(&agent.endpoint_url) {
            return Err(invalid(
                "A2A UAID agent endpoint is blocked by the domain allowlist",
            ));
        }
    }
    if previous.uaid.is_none()
        && let Some(uaid) = patch
            .uaid
            .generate(&app.uaid, &agent.endpoint_url, &agent.name, false)
            .map_err(invalid)?
    {
        agent.set_uaid(uaid);
    }
    if let Some(config) = patch.auth.oauth_config() {
        oauth::validate_config(&app, config, previous.oauth_config.as_ref())?;
    }
    let mut auth = GatewayConnectionRow {
        kind: agent.auth_type.clone().unwrap_or_default(),
        headers: agent.stored_headers().map(std::borrow::Cow::into_owned),
        query: agent.auth_query_params.clone(),
        oauth: agent
            .oauth_config
            .as_ref()
            .map(|config| config.0.to_string()),
        ..GatewayConnectionRow::default()
    };
    if patch
        .auth
        .apply_agent_update(
            &mut auth,
            app.credential_cipher.as_ref(),
            app.vault.as_ref(),
            app.query_auth_hosts.as_ref(),
            &agent.endpoint_url,
            endpoint_changed,
        )
        .await
        .map_err(|error| invalid(error.to_string()))?
    {
        agent.auth_type = (!auth.kind.is_empty()).then_some(auth.kind);
        agent.auth_value = auth.headers;
        agent.auth_query_params = auth.query;
        agent.oauth_config = auth
            .oauth
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| CatalogApiError::unavailable())?
            .map(DbJson);
    }
    agent.modified_by = Some(principal.email.clone());
    agent.modified_from_ip = client_address(peer).or(agent.modified_from_ip);
    agent.modified_user_agent = user_agent(&headers).or(agent.modified_user_agent);
    let result = app
        .database
        .update_agent(&previous, &agent)
        .await
        .map_err(|error| write_error(error, &agent))?;
    if previous.visibility != result.visibility || previous.team_id != result.team_id {
        changed(&app, &previous);
    }
    changed(&app, &result);
    tracing::info!(actor = %principal.email, agent_id = %id, version = result.version, "A2A agent updated");
    Ok(Json(read_agent(&result)))
}

impl AgentPatch {
    fn apply_metadata(&mut self, agent: &mut AgentRecord) -> Result<(), CatalogApiError> {
        if let Some(name) = self.name.take() {
            let name = name.trim();
            agent.slug = agent_slug(name)?;
            agent.name = name.to_owned();
        }
        if let Some(endpoint) = self.endpoint_url.take() {
            agent.endpoint_url = endpoint.trim().to_owned();
        }
        if let Some(description) = self.description.take() {
            agent.description = description;
        }
        if let Some(agent_type) = self.agent_type.take() {
            agent.agent_type = agent_type;
        }
        if let Some(binding) = self.protocol_binding.take() {
            agent.protocol_binding = binding;
        }
        if let Some(version) = self.protocol_version.take() {
            agent.protocol_version = version;
        }
        if let Some(capabilities) = self.capabilities.take() {
            agent.capabilities = DbJson(Value::Object(capabilities));
        }
        if let Some(skills) = self.skills.take() {
            agent.skills = skills.map(|skills| DbJson(json!(skills)));
        }
        if let Some(config) = self.config.take() {
            agent.config = DbJson(Value::Object(config));
        }
        if let Some(headers) = self.passthrough_headers.take() {
            let mut names = Vec::new();
            for name in headers
                .into_iter()
                .flatten()
                .map(|name| name.trim().to_owned())
            {
                if !name.is_empty() {
                    HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| invalid("Invalid passthrough header name"))?;
                    names.push(name);
                }
            }
            agent.passthrough_headers = (!names.is_empty()).then_some(DbJson(names));
        }
        if let Some(tags) = self.tags.take() {
            agent.tags = DbJson(normalized_tags(tags)?);
        }
        if let Some(team) = self.team_id.take() {
            agent.team_id = team;
        }
        if let Some(visibility) = self.visibility.take() {
            agent.visibility = visibility;
        }
        if agent.endpoint_url.len() > 767
            || agent.agent_type.is_empty()
            || agent.agent_type.len() > 50
            || agent.protocol_version.len() > 10
            || agent
                .protocol_binding
                .as_deref()
                .is_some_and(|binding| !matches!(binding, "jsonrpc" | "http_json"))
            || !matches!(agent.visibility.as_str(), "public" | "team" | "private")
        {
            return Err(invalid("Invalid A2A agent configuration"));
        }
        Ok(())
    }
}

async fn validate_scope(
    app: &GatewayService,
    principal: &Principal,
    previous: &AgentRecord,
    next: &AgentRecord,
) -> Result<(), CatalogApiError> {
    if previous.visibility == next.visibility && previous.team_id == next.team_id {
        return Ok(());
    }
    let team = next.team_id.as_deref();
    if next.visibility == "team" && team.is_none() {
        return Err(invalid("Cannot set visibility to 'team' without a team_id"));
    }
    let allowed = match &principal.visibility {
        TeamVisibility::Admin => true,
        TeamVisibility::Teams(teams) => team.is_none_or(|id| teams.iter().any(|team| team == id)),
        TeamVisibility::Public => next.visibility == "public" && team.is_none(),
    };
    if !allowed {
        return Err(denied_team());
    }
    if let Some(team) = team {
        if !app.database.active_team(team).await? {
            return Err(invalid(format!("Team {team} not found")));
        }
        if (next.team_id != previous.team_id || next.visibility == "team")
            && !app.database.team_owner(&principal.email, team).await?
        {
            return Err(denied_team());
        }
    }
    let role = team.map_or(RoleContext::AnyTeam, RoleContext::Team);
    if !app
        .access
        .allows(principal, "a2a.update", role, true)
        .await?
    {
        return Err(denied_team());
    }
    Ok(())
}

#[derive(Deserialize)]
pub(super) struct StateQuery {
    activate: Option<String>,
}

pub(super) async fn set_state(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<StateQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    let enabled = query
        .activate
        .as_deref()
        .map(|value| flag(Some(value)))
        .transpose()?
        .unwrap_or(true);
    let action = if enabled {
        "activate the Agent"
    } else {
        "deactivate the Agent"
    };
    let previous = editable(&app, &principal, &id, "a2a.update", action).await?;
    let result = app
        .database
        .set_agent_state(&previous, enabled)
        .await
        .map_err(|error| write_error(error, &previous))?;
    changed(&app, &result);
    tracing::info!(actor = %principal.email, agent_id = %id, enabled, "A2A agent state set");
    Ok(Json(read_agent(&result)))
}

#[derive(Deserialize)]
pub(super) struct DeleteQuery {
    purge_metrics: Option<String>,
}

pub(super) async fn remove(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    let purge_metrics = flag(query.purge_metrics.as_deref())?;
    let previous = editable(&app, &principal, &id, "a2a.delete", "delete this agent").await?;
    app.database
        .delete_agent(&previous, purge_metrics)
        .await
        .map_err(|error| write_error(error, &previous))?;
    changed(&app, &previous);
    tracing::info!(actor = %principal.email, agent_id = %id, purge_metrics, "A2A agent deleted");
    Ok(Json(
        json!({"status":"success","message":format!("A2A Agent {id} deleted successfully")}),
    ))
}

async fn editable(
    app: &GatewayService,
    principal: &Principal,
    id: &str,
    permission: &str,
    action: &str,
) -> Result<AgentRecord, CatalogApiError> {
    require(app, principal, permission).await?;
    let agent = find(app, Some(principal), AgentLookup::Id(id)).await?;
    let role = agent
        .team_id
        .as_deref()
        .map_or(RoleContext::AnyTeam, RoleContext::Team);
    if !app.access.allows(principal, permission, role, true).await? {
        return Err(denied_team());
    }
    if !owns_agent(app, principal, &agent).await? {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            format!("Only the owner can {action}"),
        ));
    }
    Ok(agent)
}

fn changed(app: &GatewayService, agent: &AgentRecord) {
    app.subscriptions.changed(
        &agent.visibility,
        agent.team_id.as_deref(),
        agent.owner_email.as_deref(),
    );
}

pub(super) fn write_error(error: AgentWriteError, agent: &AgentRecord) -> CatalogApiError {
    let message = match error {
        AgentWriteError::Duplicate { id, enabled } => {
            let visibility = match agent.visibility.as_str() {
                "team" => "Team",
                "private" => "Private",
                _ => "Public",
            };
            let mut message = format!(
                "{visibility} A2A Agent already exists with name: {}",
                agent.slug
            );
            if !enabled {
                message.push_str(&format!(" (currently inactive, ID: {id})"));
            }
            message
        }
        AgentWriteError::Changed | AgentWriteError::ToolConflict => error.to_string(),
        AgentWriteError::Database(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            "An A2A agent or its MCP tool already uses this name".into()
        }
        AgentWriteError::Database(error) => return error.into(),
    };
    CatalogApiError::detail(StatusCode::CONFLICT, message)
}

fn invalid(message: impl Into<String>) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}
