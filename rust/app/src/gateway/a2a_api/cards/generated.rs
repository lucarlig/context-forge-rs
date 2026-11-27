// SPDX-License-Identifier: Apache-2.0

use super::{document, *};
use axum::http::header::CACHE_CONTROL;

pub(in crate::gateway::a2a_api) async fn read(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, CatalogApiError> {
    require(&app, &principal, "a2a.read").await?;
    let scope = access::catalog_scope(Some(&principal));
    let card = if let Some(agent) = app
        .database
        .find_agent(scope, AgentLookup::Id(&id))
        .await?
        .filter(|agent| agent.enabled)
    {
        standalone(&agent)
    } else if let Some(server) = app
        .database
        .managed_server(&id)
        .await?
        .filter(|server| server.enabled && server.is_visible(scope))
        && let Some(interface) = app.database.server_card_interface(&id).await?
    {
        let agents = app.database.server_card_agents(&id, scope).await?;
        let capabilities = aggregate(&agents);
        let protocol = interface.protocol.to_ascii_lowercase();
        let binding = protocol
            .strip_prefix("a2a-")
            .filter(|value| !value.is_empty())
            .unwrap_or("jsonrpc")
            .to_ascii_uppercase();
        Card {
            name: &server.name,
            description: server.description.as_deref(),
            version: server
                .version
                .map_or_else(|| "None".into(), |version| version.to_string()),
            endpoint: &interface.binding,
            protocol: interface.version.as_deref().unwrap_or("1.0"),
            binding: &binding,
            tenant: interface.tenant.as_deref(),
            capabilities,
        }
        .wire()
    } else {
        return Err(CatalogApiError::detail(
            StatusCode::NOT_FOUND,
            "agent not found",
        ));
    };
    Ok(([(CACHE_CONTROL, "private, no-store")], Json(card)))
}

fn standalone(agent: &AgentRecord) -> Value {
    let caps = &agent.capabilities.0;
    let capabilities = CardCapabilities {
        streaming: document::truthy(&caps["streaming"]),
        push: document::truthy(&caps["pushNotifications"]),
        history: document::truthy(&caps["stateTransitionHistory"]),
        extensions: document::truthy(&caps["extensions"]).then(|| caps["extensions"].clone()),
        input_modes: modes(caps, "defaultInputModes"),
        output_modes: modes(caps, "defaultOutputModes"),
        skills: skills(agent).cloned().collect(),
    };
    let mut card = Card {
        name: &agent.name,
        description: agent.description.as_deref(),
        version: agent.version.to_string(),
        endpoint: &agent.endpoint_url,
        protocol: &agent.protocol_version,
        binding: "JSONRPC",
        tenant: agent.tenant.as_deref(),
        capabilities,
    }
    .wire();
    if card.get("supportedInterfaces").is_some() {
        if let Some(icon) = agent.icon_url.as_deref().filter(|icon| !icon.is_empty()) {
            card["iconUrl"] = json!(icon);
        }
        if let Some((name, scheme)) = security(agent) {
            card["securitySchemes"] = json!({(name):scheme});
            card["securityRequirements"] = json!([{"schemes":{(name):{}}}]);
        }
    }
    card
}

struct Card<'a> {
    name: &'a str,
    description: Option<&'a str>,
    version: String,
    endpoint: &'a str,
    protocol: &'a str,
    binding: &'a str,
    tenant: Option<&'a str>,
    capabilities: CardCapabilities,
}

#[derive(Default)]
struct CardCapabilities {
    streaming: bool,
    push: bool,
    history: bool,
    extensions: Option<Value>,
    input_modes: Vec<String>,
    output_modes: Vec<String>,
    skills: Vec<Value>,
}

impl Card<'_> {
    fn wire(self) -> Value {
        let caps = self.capabilities;
        let mut card = json!({
            "name":self.name, "description":self.description.unwrap_or_default(), "version":self.version,
            "url":null, "protocolVersion":null, "supportsAuthenticatedExtendedCard":true,
            "defaultInputModes":mode_wire(caps.input_modes), "defaultOutputModes":mode_wire(caps.output_modes),
            "skills":caps.skills, "capabilities":{"streaming":caps.streaming,"pushNotifications":caps.push},
        });
        if super::super::protocol::is_modern(self.protocol) {
            let mut interface = json!({"url":self.endpoint, "protocolBinding":self.binding, "protocolVersion":self.protocol});
            if let Some(tenant) = self.tenant.filter(|tenant| !tenant.is_empty()) {
                interface["tenant"] = json!(tenant);
            }
            card["supportedInterfaces"] = json!([interface]);
            card["capabilities"]["extendedAgentCard"] = json!(true);
            if let Some(extensions) = caps.extensions {
                card["capabilities"]["extensions"] = extensions;
            }
        } else {
            card["url"] = json!(self.endpoint);
            card["protocolVersion"] = json!(self.protocol);
            card["capabilities"]["stateTransitionHistory"] = json!(caps.history);
        }
        card
    }
}

fn aggregate(agents: &[AgentRecord]) -> CardCapabilities {
    let mut result = CardCapabilities::default();
    let mut seen = HashSet::new();
    for agent in agents {
        let caps = &agent.capabilities.0;
        result.streaming |= document::truthy(&caps["streaming"]);
        result.push |= document::truthy(&caps["pushNotifications"]);
        for skill in skills(agent) {
            let include = skill
                .get("id")
                .is_none_or(|id| id.as_str().is_some_and(|id| seen.insert(id)));
            if include {
                result.skills.push(skill.clone());
            }
        }
        for (key, all) in [
            ("defaultInputModes", &mut result.input_modes),
            ("defaultOutputModes", &mut result.output_modes),
        ] {
            for mode in modes(caps, key) {
                if !all.contains(&mode) {
                    all.push(mode);
                }
            }
        }
    }
    result
}

fn skills(agent: &AgentRecord) -> impl Iterator<Item = &Value> {
    agent
        .skills
        .as_ref()
        .and_then(|skills| skills.0.as_array())
        .or_else(|| agent.capabilities.0["skills"].as_array())
        .into_iter()
        .flatten()
        .filter(|skill| skill.is_object())
}

fn modes(caps: &Value, key: &str) -> Vec<String> {
    caps[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn mode_wire(modes: Vec<String>) -> Value {
    if modes.is_empty() {
        json!(["text"])
    } else {
        json!(modes)
    }
}

fn security(agent: &AgentRecord) -> Option<(&'static str, Value)> {
    let kind = agent.auth_type.as_deref()?.to_ascii_lowercase();
    Some(match kind.as_str() {
        "basic" => (
            "basicAuth",
            json!({"httpAuthSecurityScheme":{"scheme":"basic"}}),
        ),
        "bearer" => (
            "bearerAuth",
            json!({"httpAuthSecurityScheme":{"scheme":"bearer"}}),
        ),
        "query_param" => {
            let params: Map<String, Value> =
                serde_json::from_str(agent.auth_query_params.as_deref()?).ok()?;
            let name = params.keys().next()?;
            (
                "apiKeyAuth",
                json!({"apiKeySecurityScheme":{"location":"query","name":name}}),
            )
        }
        "oauth" => ("oauth2Auth", oauth_scheme(&agent.oauth_config.as_ref()?.0)?),
        _ => return None,
    })
}

fn oauth_scheme(config: &Value) -> Option<Value> {
    let url = |key: &str| {
        let url = config[key].as_str()?;
        discovery::base_url(url).ok()?;
        Some(url)
    };
    let token_url = url("token_url")?;
    let field = if document::truthy(&config["scopes"]) {
        &config["scopes"]
    } else {
        &config["scope"]
    };
    let scopes: Map<String, Value> = if let Some(raw) = field.as_str() {
        raw.split(|ch: char| ch == ',' || ch.is_whitespace())
            .filter(|scope| !scope.is_empty())
            .map(|scope| (scope.to_owned(), json!(scope)))
            .collect()
    } else {
        field
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|scope| !scope.is_empty())
            .map(|scope| (scope.to_owned(), json!(scope)))
            .collect()
    };
    let flows = match config["grant_type"].as_str()? {
        "client_credentials" => json!({"clientCredentials":{"tokenUrl":token_url,"scopes":scopes}}),
        "authorization_code" => {
            json!({"authorizationCode":{"authorizationUrl":url("authorization_url")?,
            "tokenUrl":token_url,"scopes":scopes}})
        }
        _ => return None,
    };
    Some(json!({"oauth2SecurityScheme":{"flows":flows}}))
}
