// SPDX-License-Identifier: Apache-2.0

use serde_json::{Map, Value, json};
use url::Url;

pub(super) fn validate(raw: &Value) -> Option<bool> {
    if raw["name"]
        .as_str()
        .is_none_or(|name| name.trim().is_empty())
    {
        return None;
    }
    let legacy = raw["supportedInterfaces"].as_array().is_none();
    if legacy {
        if !has_url(raw) {
            return None;
        }
    } else {
        interface(raw)?;
    }
    let caps = &raw["capabilities"];
    let interfaces = &raw["additionalInterfaces"];
    if truthy(caps)
        && (!caps.is_object()
            || ["streaming", "pushNotifications"]
                .iter()
                .any(|flag| !caps[*flag].is_null() && !caps[*flag].is_boolean()))
        || truthy(interfaces) && !interfaces.is_array()
    {
        return None;
    }
    let schemes = &raw["securitySchemes"];
    if !schemes.is_null()
        && !schemes.as_object().is_some_and(|schemes| {
            schemes.values().all(|scheme| {
                let Some(object) = scheme.as_object() else {
                    return false;
                };
                let body = object
                    .iter()
                    .find_map(|(key, value)| {
                        (key.ends_with("SecurityScheme") && value.is_object()).then_some(value)
                    })
                    .unwrap_or(scheme);
                let flows = &body["flows"];
                flows.is_null()
                    || flows.as_object().is_some_and(|flows| {
                        flows.values().all(|flow| {
                            flow.is_object()
                                && (flow["scopes"].is_null() || flow["scopes"].is_object())
                        })
                    })
            })
        })
    {
        return None;
    }
    let key = if legacy {
        "security"
    } else {
        "securityRequirements"
    };
    if !valid_requirements(&raw[key], legacy) {
        return None;
    }
    let skills = &raw["skills"];
    if !skills.is_null()
        && !skills.as_array().is_some_and(|skills| {
            skills
                .iter()
                .all(|skill| skill.is_object() && valid_requirements(&skill[key], legacy))
        })
    {
        return None;
    }
    Some(legacy)
}

fn valid_requirements(requirements: &Value, legacy: bool) -> bool {
    requirements.is_null()
        || requirements.as_array().is_some_and(|requirements| {
            requirements.iter().all(|entry| {
                let Some(entry) = entry.as_object() else {
                    return false;
                };
                if legacy {
                    entry.values().all(string_list)
                } else {
                    entry.get("schemes").is_none_or(|schemes| {
                        schemes.is_null()
                            || schemes.as_object().is_some_and(|schemes| {
                                schemes.values().all(|scopes| {
                                    scopes.is_object()
                                        && (scopes["list"].is_null()
                                            || string_list(&scopes["list"]))
                                })
                            })
                    })
                }
            })
        })
}

fn string_list(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|values| values.iter().all(Value::is_string))
}

fn has_url(value: &Value) -> bool {
    value["url"].as_str().is_some_and(|url| !url.is_empty())
}

pub(super) fn interface(card: &Value) -> Option<&Value> {
    let mut interfaces = card["supportedInterfaces"]
        .as_array()?
        .iter()
        .filter(|interface| has_url(interface));
    let first = interfaces.next()?;
    if json_rpc(first) {
        Some(first)
    } else {
        interfaces.find(|item| json_rpc(item)).or(Some(first))
    }
}

pub(super) fn json_rpc(interface: &Value) -> bool {
    interface.get("protocolBinding").is_none_or(|binding| {
        binding
            .as_str()
            .is_some_and(|binding| binding.eq_ignore_ascii_case("JSONRPC"))
    })
}

pub(super) fn normalize_legacy(raw: &Value) -> Value {
    let protocol = defaulted(&raw["protocolVersion"], json!("0.3"));
    let mut interfaces = vec![json!({
        "url":raw["url"],
        "protocolBinding":defaulted(&raw["preferredTransport"], json!("JSONRPC")),
        "protocolVersion":protocol,
    })];
    for other in raw["additionalInterfaces"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| has_url(entry))
    {
        interfaces.push(json!({
            "url":other["url"], "protocolBinding":defaulted(&other["transport"], json!("JSONRPC")),
            "protocolVersion":protocol,
        }));
    }
    let mut card = Map::new();
    for key in [
        "name",
        "description",
        "version",
        "provider",
        "documentationUrl",
        "iconUrl",
        "defaultInputModes",
        "defaultOutputModes",
        "signatures",
    ] {
        if let Some(value) = raw.get(key) {
            card.insert(key.into(), value.clone());
        }
    }
    if let Some(skills) = raw["skills"].as_array() {
        let skills = skills
            .iter()
            .filter_map(Value::as_object)
            .map(|skill| {
                let mut skill = skill.clone();
                if let Some(security) = skill.remove("security").filter(truthy) {
                    skill.insert(
                        "securityRequirements".into(),
                        legacy_requirements(&security),
                    );
                }
                Value::Object(skill)
            })
            .collect::<Vec<_>>();
        card.insert("skills".into(), json!(skills));
    }
    let caps = &raw["capabilities"];
    let mut capabilities = json!({
        "streaming":truthy(&caps["streaming"]), "pushNotifications":truthy(&caps["pushNotifications"]),
        "extendedAgentCard":truthy(&raw["supportsAuthenticatedExtendedCard"]),
    });
    if truthy(&caps["extensions"]) {
        capabilities["extensions"] = caps["extensions"].clone();
    }
    card.insert("supportedInterfaces".into(), json!(interfaces));
    card.insert("capabilities".into(), capabilities);
    let schemes: Map<String, Value> = raw["securitySchemes"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(name, scheme)| legacy_scheme(scheme).map(|scheme| (name.clone(), scheme)))
        .collect();
    if !schemes.is_empty() || truthy(&raw["security"]) {
        card.insert(
            "securityRequirements".into(),
            legacy_requirements(&raw["security"]),
        );
    }
    if !schemes.is_empty() {
        card.insert("securitySchemes".into(), Value::Object(schemes));
    }
    Value::Object(card)
}

fn legacy_requirements(value: &Value) -> Value {
    let requirements = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .map(|requirement| {
            let schemes: Map<String, Value> = requirement
                .iter()
                .map(|(key, scopes)| {
                    (
                        key.clone(),
                        if truthy(scopes) {
                            json!({"list":scopes})
                        } else {
                            json!({})
                        },
                    )
                })
                .collect();
            json!({"schemes":schemes})
        })
        .collect::<Vec<_>>();
    json!(requirements)
}

fn legacy_scheme(scheme: &Value) -> Option<Value> {
    Some(
        match scheme["type"].as_str()?.to_ascii_lowercase().as_str() {
            "http" => {
                json!({"httpAuthSecurityScheme":{"scheme":scheme.get("scheme").cloned().unwrap_or(json!(""))}})
            }
            "apikey" => {
                json!({"apiKeySecurityScheme":{"location":scheme.get("in").cloned().unwrap_or(json!("header")),
            "name":scheme.get("name").cloned().unwrap_or(json!(""))}})
            }
            "oauth2" => {
                json!({"oauth2SecurityScheme":{"flows":scheme.get("flows").cloned().unwrap_or(json!({}))}})
            }
            "openidconnect" => {
                json!({"openIdConnectSecurityScheme":{"openIdConnectUrl":scheme.get("openIdConnectUrl").cloned().unwrap_or(json!(""))}})
            }
            "mutualtls" => json!({"mtlsSecurityScheme":{}}),
            _ => return None,
        },
    )
}

pub(super) fn suggest(card: &Value) -> (Value, Vec<String>) {
    let Some(interface) = interface(card) else {
        return (json!({}), vec![]);
    };
    let mut warnings = Vec::new();
    if !json_rpc(interface) {
        let binding = format_value(&interface["protocolBinding"]);
        warnings.push(format!("No JSONRPC interface is declared. ContextForge calls agents over JSONRPC, but the selected interface uses {binding}."));
    }
    let caps = &card["capabilities"];
    let mut capabilities = json!({
        "streaming":truthy(&caps["streaming"]), "pushNotifications":truthy(&caps["pushNotifications"]),
        "skills":defaulted(&card["skills"], json!([])),
    });
    if truthy(&caps["extensions"]) {
        capabilities["extensions"] = caps["extensions"].clone();
    }
    for key in ["defaultInputModes", "defaultOutputModes"] {
        if truthy(&card[key]) {
            capabilities[key] = card[key].clone();
        }
    }
    let mut agent = Map::from_iter([
        ("name".into(), card["name"].clone()),
        ("endpoint_url".into(), interface["url"].clone()),
        (
            "protocol_version".into(),
            json!(format_value(&defaulted(
                &interface["protocolVersion"],
                json!("1.0")
            ))),
        ),
        ("capabilities".into(), capabilities),
    ]);
    if truthy(&card["description"]) {
        agent.insert("description".into(), card["description"].clone());
    }
    if truthy(&card["version"]) {
        agent.insert("version".into(), json!(format_value(&card["version"])));
    }
    let auth = suggest_auth(card, &mut warnings);
    warn_skills(card, &mut warnings);
    warn_oauth(
        &auth,
        interface["url"].as_str().unwrap_or_default(),
        &mut warnings,
    );
    agent.extend(auth);
    (Value::Object(agent), warnings)
}

fn suggest_auth(card: &Value, warnings: &mut Vec<String>) -> Map<String, Value> {
    let mut chosen = Map::new();
    for requirement in card["securityRequirements"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let Some(required) = requirement["schemes"].as_object() else {
            continue;
        };
        if required.len() > 1 {
            let names = required
                .keys()
                .map(|name| format!("'{name}'"))
                .collect::<Vec<_>>()
                .join(", ");
            warnings.push(format!("Security schemes {names} are required together. ContextForge stores one auth type, so this requirement was not mapped."));
            continue;
        }
        for (name, scopes) in required {
            let scheme = card["securitySchemes"].get(name).and_then(Value::as_object);
            let mapped = scheme.and_then(|scheme| {
                let (key, body) = scheme
                    .iter()
                    .find(|(key, body)| key.ends_with("SecurityScheme") && body.is_object())?;
                auth_fields(key, body, scopes)
            });
            match mapped {
                Some(fields) if chosen.is_empty() => chosen = fields,
                Some(_) => warnings.push(format!(
                    "Security scheme '{name}' is an alternative that was not selected."
                )),
                None => warnings.push(format!(
                    "Security scheme '{name}' is not supported and was ignored."
                )),
            }
        }
    }
    chosen
}

fn auth_fields(key: &str, body: &Value, scopes: &Value) -> Option<Map<String, Value>> {
    let fields = match key {
        "httpAuthSecurityScheme" => {
            let kind = body["scheme"].as_str()?.to_ascii_lowercase();
            if !matches!(kind.as_str(), "basic" | "bearer") {
                return None;
            }
            json!({"auth_type":kind})
        }
        "apiKeySecurityScheme" if truthy(&body["name"]) => {
            let location = body["location"]
                .as_str()
                .unwrap_or("header")
                .to_ascii_lowercase();
            match location.as_str() {
                "query" => json!({"auth_type":"query_param","auth_query_param_key":body["name"]}),
                "header" => json!({"auth_type":"authheaders","auth_header_key":body["name"]}),
                _ => return None,
            }
        }
        "oauth2SecurityScheme" => {
            let flows = &body["flows"];
            let scopes = defaulted(&scopes["list"], json!([]));
            if let Some(flow) = flows.get("clientCredentials") {
                json!({"auth_type":"oauth","oauth_config":{"grant_type":"client_credentials","token_url":flow["tokenUrl"],"scopes":scopes}})
            } else {
                let flow = flows.get("authorizationCode")?;
                json!({"auth_type":"oauth","oauth_config":{"grant_type":"authorization_code",
                    "authorization_url":flow["authorizationUrl"],"token_url":flow["tokenUrl"],"scopes":scopes}})
            }
        }
        _ => return None,
    };
    match fields {
        Value::Object(fields) => Some(fields),
        _ => None,
    }
}

fn warn_skills(card: &Value, warnings: &mut Vec<String>) {
    let names = card["skills"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|skill| truthy(&skill["securityRequirements"]))
        .map(|skill| {
            let name = [&skill["id"], &skill["name"]]
                .into_iter()
                .find(|value| truthy(value));
            let label = name.map_or_else(|| "unnamed".into(), format_value);
            format!("'{}'", label.chars().take(60).collect::<String>())
        })
        .collect::<Vec<_>>();
    if names.is_empty() {
        return;
    }
    let mut listed = names[..names.len().min(3)].join(", ");
    if names.len() > 3 {
        listed.push_str(&format!(" and {} more", names.len() - 3));
    }
    let (subject, pronoun) = if names.len() == 1 {
        (format!("Skill {listed} declares its"), "it")
    } else {
        (format!("Skills {listed} declare their"), "them")
    };
    warnings.push(format!("{subject} own security requirements. ContextForge stores one authentication configuration per agent, so configure authentication for {pronoun} manually."));
}

fn warn_oauth(auth: &Map<String, Value>, endpoint: &str, warnings: &mut Vec<String>) {
    let Some(config) = auth.get("oauth_config") else {
        return;
    };
    let agent = Url::parse(endpoint).ok();
    let agent_host = agent.as_ref().and_then(Url::host_str);
    for key in ["authorization_url", "token_url"] {
        let Some(parsed) = config[key].as_str().and_then(|url| Url::parse(url).ok()) else {
            continue;
        };
        let Some(host) = parsed.host_str() else {
            continue;
        };
        if Some(host) != agent_host {
            warnings.push(format!("The card's OAuth {key} points to '{host}', which differs from the agent host. Verify it before entering a client secret."));
        }
        if parsed.scheme() != "https" {
            warnings.push(format!("The card's OAuth {key} uses '{}', not https. Verify it before entering a client secret.", parsed.scheme()));
        }
    }
}

pub(super) fn additions(public: &Value, extended: &Value) -> Vec<String> {
    fn collect(paths: &mut Vec<String>, prefix: &str, public: &Value, extended: &Value) {
        if let Some(extended) = extended.as_object() {
            for (key, value) in extended {
                let path = format!("{prefix}{key}");
                if let Some(previous) = public.get(key) {
                    if value.is_object() && previous.is_object() {
                        collect(paths, &format!("{path}."), previous, value);
                    } else if value != previous {
                        paths.push(path);
                    }
                } else {
                    paths.push(path);
                }
            }
        }
    }
    let mut paths = Vec::new();
    collect(&mut paths, "", public, extended);
    paths.sort_unstable();
    paths
}

fn format_value(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

pub(super) fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

pub(super) fn defaulted(value: &Value, default: Value) -> Value {
    if truthy(value) {
        value.clone()
    } else {
        default
    }
}
