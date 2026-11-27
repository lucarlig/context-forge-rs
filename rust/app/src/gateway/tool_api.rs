// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use axum::extract::{Path, Query};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};

use super::{catalog_api::*, *};
use crate::{catalog::ToolRecord, credentials::decode_header_values};

const MASK: &str = "*****";
pub(super) const SECRET_HEADER: &str = "_mcpgateway_encrypted_header_value_v1";

mod write;
pub(super) use write::protected_header;
pub(super) use write::{change_state, create_record, editable, import_tool, remove, update_record};

pub(super) fn mapped_header_name(name: &str) -> Option<HeaderName> {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    let normalized = name.as_str();
    (!protected_header(normalized)
        && !crate::forward_headers::hop_header_name(normalized)
        && !normalized.starts_with("mcp-")
        && !normalized.starts_with("x-mcp-")
        && !normalized.starts_with("x-forwarded-user")
        && normalized != "x-upstream-authorization")
        .then_some(name)
}

#[derive(Deserialize)]
struct ToolDetailQuery {
    apijsonpath: Option<String>,
}

pub(super) fn router() -> Router<Arc<GatewayService>> {
    let mut routes = Router::new().route(
        "/v1/tools/generate-schemas-from-openapi",
        post(super::openapi::generate_schemas),
    );
    for base in ["/tools", "/v1/tools"] {
        routes = routes
            .route(base, get(list).post(write::create))
            .route(&format!("{base}/"), get(list).post(write::create))
            .route(
                &format!("{base}/{{id}}"),
                get(detail).put(write::update).delete(write::delete),
            )
            .route(&format!("{base}/{{id}}/state"), post(write::set_state))
            .route(&format!("{base}/{{id}}/toggle"), post(write::set_state))
            .route(&format!("{base}/preview/{{*name}}"), post(preview));
    }
    routes
}

async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<CatalogListQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "tools.read", true).await?;
    list_payload(&service, &principal, &query, None)
        .await
        .map(Json)
}

pub(super) async fn rpc_list(
    service: &GatewayService,
    principal: &Principal,
    server: Option<&CatalogServer>,
    cursor: Option<String>,
) -> Result<Value, CatalogApiError> {
    let query = CatalogListQuery {
        include_pagination: Some("true".into()),
        limit: Some(0),
        cursor,
        ..Default::default()
    };
    list_payload(service, principal, &query, server).await
}

async fn list_payload(
    service: &GatewayService,
    principal: &Principal,
    query: &CatalogListQuery,
    server: Option<&CatalogServer>,
) -> Result<Value, CatalogApiError> {
    let projection = JsonProjection::parse(query.apijsonpath.as_deref())?;
    let page = CatalogPage::prepare(service, principal, query, "rest/tools")?;
    let scope = access::catalog_scope(Some(principal));
    let tools = if let Some(server) = server {
        service
            .database
            .managed_server_tools(scope, &server.id, false)
            .await?
    } else {
        service
            .database
            .managed_tools(scope, page.filters())
            .await?
    };
    let teams = header_team_owners(service, principal, &tools).await?;
    let mut response = page.envelope(
        service,
        tools.iter().collect(),
        "tools",
        |tool| (&tool.created_at, &tool.id),
        |tool| {
            let team_owner = tool
                .team_id
                .as_deref()
                .and_then(|team| teams.get(team))
                .copied()
                .unwrap_or(false);
            metadata(
                service,
                tool,
                true,
                false,
                can_view_headers(principal, tool, team_owner),
            )
        },
    )?;
    if let Some(projection) = projection {
        if response.is_array() {
            response = projection.apply(&response);
        } else {
            response["tools"] = projection.apply(&response["tools"]);
        }
    }
    Ok(response)
}

async fn detail(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<ToolDetailQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "tools.read", true).await?;
    let tool = find_visible(&service, &principal, &id).await?;
    let owner = if tool.visibility == "team"
        && !can_view_headers(&principal, &tool, false)
        && access::catalog_scope(Some(&principal)).can_own()
        && let Some(team) = tool.team_id.as_deref()
    {
        service.database.team_owner(&principal.email, team).await?
    } else {
        false
    };
    let response = metadata(
        &service,
        &tool,
        true,
        true,
        can_view_headers(&principal, &tool, owner),
    );
    let projection = JsonProjection::parse(query.apijsonpath.as_deref())?;
    Ok(Json(match projection {
        Some(modifier) => modifier.apply(&response),
        None => response,
    }))
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreviewInput {
    arguments: Option<serde_json::Map<String, Value>>,
    #[serde(alias = "server_id")]
    server_id: Option<String>,
}

async fn preview(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(name): Path<String>,
    body: Option<Json<PreviewInput>>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "tools.preview", true).await?;
    if !service.tool_preview_enabled {
        return Err(CatalogApiError::detail(
            StatusCode::NOT_FOUND,
            "Tool preview is disabled",
        ));
    }
    let input = body.map(|Json(input)| input).unwrap_or_default();
    let server = input.server_id.as_deref().map(str::trim);
    let scope = access::catalog_scope(Some(&principal));
    if let Some(server) = server {
        if server.is_empty() || server.len() > 36 {
            return Err(CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid server ID",
            ));
        }
        if service
            .database
            .catalog_server(server)
            .await?
            .is_none_or(|server| !server.enabled || !server.is_visible(scope))
        {
            return Err(CatalogApiError::detail(
                StatusCode::NOT_FOUND,
                format!("Server not found: {server}"),
            ));
        }
    }
    let tools = service
        .database
        .tool_preview_candidates(scope, &name, server)
        .await?;
    let tool = match tools.as_slice() {
        [] => return Err(tool_missing(&name)),
        [tool] => tool,
        _ => {
            return Err(CatalogApiError::detail(
                StatusCode::BAD_REQUEST,
                format!(
                    "Tool name '{name}' is ambiguous across multiple scopes; use /servers/{{id}}/mcp to disambiguate."
                ),
            ));
        }
    };
    if tool.deprecated {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            deprecated_message(&name),
        ));
    }
    let schema = json_value(Some(&tool.input_schema));
    let arguments = Value::Object(input.arguments.unwrap_or_default());
    let (arguments, warning) = if schema.is_null() {
        (arguments, None)
    } else {
        service
            .schema_validation
            .validate(schema, arguments, crate::schema_validation::Target::Input)
            .await
            .map_err(|_| {
                CatalogApiError::detail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Tool preview validation could not complete",
                )
            })?
    };
    let warnings = warning
        .into_iter()
        .map(|message| json!({"code":"invalid_arguments","hook":null,"message":message}))
        .collect::<Vec<_>>();
    let annotations = json_value(tool.annotations.as_deref());
    Ok(Json(json!({
        "validated":warnings.is_empty(),
        "resolvedArguments":arguments,
        "target":{
            "kind": if tool.gateway_id.is_some() { "federated" } else { "local" },
            "gatewayName":tool.gateway_name,
        },
        "annotations":{
            "title":annotations["title"],"readOnlyHint":annotations["readOnlyHint"],
            "destructiveHint":annotations["destructiveHint"],"idempotentHint":annotations["idempotentHint"],
            "openWorldHint":annotations["openWorldHint"],
        },
        "preHooksRun":[],
        "warnings":warnings,
    })))
}

async fn find_visible(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
) -> Result<ToolRecord, CatalogApiError> {
    let scope = access::catalog_scope(Some(principal));
    service
        .database
        .managed_tool(id)
        .await?
        .filter(|tool| {
            scope.visible(
                &tool.visibility,
                tool.team_id.as_deref(),
                tool.owner_email.as_deref(),
            )
        })
        .ok_or_else(|| tool_missing(id))
}

pub(super) fn can_view_headers(principal: &Principal, tool: &ToolRecord, team_owner: bool) -> bool {
    principal.is_global_admin()
        || (access::catalog_scope(Some(principal)).can_own()
            && (tool.owner_email.as_deref() == Some(&principal.email)
                || (tool.visibility == "team" && team_owner)))
}

pub(super) async fn header_team_owners<'a>(
    service: &GatewayService,
    principal: &Principal,
    tools: &'a [ToolRecord],
) -> Result<HashMap<&'a str, bool>, sqlx::Error> {
    let mut teams = HashMap::new();
    if access::catalog_scope(Some(principal)).can_own() && !principal.is_global_admin() {
        for tool in tools {
            if tool.visibility == "team"
                && tool.headers.is_some()
                && let Some(team) = tool.team_id.as_deref()
                && !teams.contains_key(team)
            {
                teams.insert(
                    team,
                    service.database.team_owner(&principal.email, team).await?,
                );
            }
        }
    }
    Ok(teams)
}

pub(super) fn metadata(
    service: &GatewayService,
    tool: &ToolRecord,
    aliases: bool,
    full_auth: bool,
    reveal_headers: bool,
) -> Value {
    let mut response = json!(tool);
    response["created_at"] = tool.created_at.replacen(' ', "T", 1).into();
    response["updated_at"] = tool.updated_at.replacen(' ', "T", 1).into();
    response["mcp_server_id"] = json!(tool.gateway_id);
    response["displayName"] = json!(tool.display_name.as_deref().unwrap_or(&tool.custom_name));
    response["execution_count"] = Value::Null;
    response["metrics"] = Value::Null;
    for (key, encoded) in [
        ("input_schema", Some(tool.input_schema.as_str())),
        ("output_schema", tool.output_schema.as_deref()),
        ("extension_metadata", tool.extension_metadata.as_deref()),
        ("allowlist", tool.allowlist.as_deref()),
        ("query_mapping", tool.query_mapping.as_deref()),
        ("header_mapping", tool.header_mapping.as_deref()),
        ("plugin_chain_pre", tool.plugin_chain_pre.as_deref()),
        ("plugin_chain_post", tool.plugin_chain_post.as_deref()),
    ] {
        response[key] = json_value(encoded);
    }
    response["annotations"] = tool
        .annotations
        .as_deref()
        .and_then(|value| serde_json::from_str(value).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    response["tags"] = parse_tags(&tool.tags);
    response["headers"] = read_headers(service.credential_cipher.as_ref(), tool, reveal_headers);
    response["auth"] = masked_auth(service.credential_cipher.as_ref(), tool, full_auth, aliases);
    let mut sigv4 = json_value(tool.sigv4_config.as_deref());
    if tool.auth_type.as_deref() != Some("sigv4") {
        sigv4 = Value::Null;
    } else if let Some(fields) = sigv4.as_object_mut() {
        for key in ["secret_access_key", "session_token"] {
            if let Some(value) = fields.get_mut(key)
                && !value.is_null()
            {
                *value = MASK.into();
            }
        }
    }
    response["sigv4_config"] = sigv4;
    if aliases {
        alias_metadata(response)
    } else {
        response["meta"] = Value::Null;
        response
    }
}

fn json_value(text: Option<&str>) -> Value {
    text.and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_default()
}

fn parse_tags(text: &str) -> Value {
    let values = serde_json::from_str::<Vec<Value>>(text).unwrap_or_default();
    Value::Array(
        values
            .into_iter()
            .filter_map(|value| {
                if let Some(label) = value.as_str() {
                    let id = slugify(label);
                    return (!id.is_empty()).then(|| json!({"id":id,"label":label}));
                }
                (value["id"].is_string() && value["label"].is_string()).then_some(value)
            })
            .collect(),
    )
}

fn read_headers(cipher: Option<&CredentialCipher>, tool: &ToolRecord, reveal: bool) -> Value {
    let mut headers = json_value(tool.headers.as_deref());
    if let Some(values) = headers.as_object_mut() {
        for value in values.values_mut() {
            if !reveal {
                *value = MASK.into();
            } else if let Some(encrypted) = value.get(SECRET_HEADER).and_then(Value::as_str) {
                *value = cipher
                    .and_then(|cipher| cipher.open::<Value>(encrypted).ok())
                    .and_then(|payload| {
                        payload
                            .get("data")
                            .or_else(|| payload.get("value"))
                            .filter(|value| value.is_string())
                            .cloned()
                    })
                    .unwrap_or_else(|| MASK.into());
            } else if !value.is_string() {
                *value = MASK.into();
            }
        }
    }
    headers
}

fn masked_auth(
    cipher: Option<&CredentialCipher>,
    tool: &ToolRecord,
    full: bool,
    aliases: bool,
) -> Value {
    let Some(kind) = tool
        .auth_type
        .as_deref()
        .filter(|kind| *kind == "sigv4" || tool.auth_value.is_some())
    else {
        return Value::Null;
    };
    if !matches!(kind, "basic" | "bearer" | "authheaders" | "sigv4") {
        return Value::Null;
    }
    let mut auth = json!({
        "auth_type":kind,"auth_value":null,"username":"","password":"","token":"",
        "auth_header_key":"","auth_header_value":"","authHeaders":null,
    });
    if full
        && let (Some(cipher), Some(stored)) = (cipher, tool.auth_value.as_deref())
        && let Ok(values) = decode_stored_auth(cipher, stored)
    {
        let authorization = values
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str());
        match kind {
            "basic" => {
                if let Some(encoded) = authorization.and_then(|value| value.strip_prefix("Basic "))
                    && let Ok(decoded) = BASE64_STANDARD.decode(encoded).map(Zeroizing::new)
                    && let Ok(value) = std::str::from_utf8(&decoded)
                    && let Some((user, password)) = value.split_once(':')
                {
                    auth["username"] = user.into();
                    auth["password"] = if password.is_empty() {
                        Value::Null
                    } else {
                        MASK.into()
                    };
                }
            }
            "bearer" => auth["token"] = authorization.map_or(Value::Null, |_| MASK.into()),
            "authheaders" => {
                if let Some((first, value)) = values.iter().next() {
                    auth["auth_header_key"] = first.as_str().into();
                    auth["auth_header_value"] = if value.is_empty() {
                        Value::Null
                    } else {
                        MASK.into()
                    };
                    auth["authHeaders"] = json!(values.iter().map(|(key,value)| json!({
                        "key":key, "value":if value.is_empty() { Value::Null } else { MASK.into() },
                    })).collect::<Vec<_>>());
                }
            }
            _ => {}
        }
    }
    if aliases {
        let mut aliased = alias_metadata(auth);
        aliased
            .as_object_mut()
            .expect("auth object")
            .remove("_meta");
        aliased
    } else {
        auth
    }
}

fn tool_missing(id: &str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::NOT_FOUND, format!("Tool not found: {id}"))
}

pub(super) fn deprecated_message(name: &str) -> String {
    format!(
        "Tool '{name}' is deprecated and cannot be executed. Please update your agent to use an alternative tool."
    )
}

pub(super) fn decode_stored_auth(
    cipher: &CredentialCipher,
    stored: &str,
) -> Result<std::collections::BTreeMap<String, String>, CredentialError> {
    decode_header_values(Some(cipher), stored).or_else(|_| cipher.open(stored))
}

struct JsonProjection {
    main: serde_json_path::JsonPath,
    wildcard: bool,
    mapping: Vec<(String, serde_json_path::JsonPath)>,
}

impl JsonProjection {
    fn parse(raw: Option<&str>) -> Result<Option<Self>, CatalogApiError> {
        use serde_json_path::JsonPath;

        #[derive(Deserialize)]
        struct Query {
            jsonpath: Option<String>,
            mapping: Option<HashMap<String, String>>,
        }

        let Some(raw) = raw else {
            return Ok(None);
        };
        let error = |message| CatalogApiError::detail(StatusCode::BAD_REQUEST, message);
        if raw.len() > 1000 {
            return Err(CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "apijsonpath is too long",
            ));
        }
        let value: Value =
            serde_json::from_str(raw).map_err(|_| error("Invalid apijsonpath format"))?;
        let fields: Query =
            serde_json::from_value(value).map_err(|_| error("Invalid apijsonpath structure"))?;
        let path = fields.jsonpath.as_deref().unwrap_or("$[*]");
        if path.trim().is_empty() {
            return Err(error("JSONPath expression cannot be empty"));
        }
        let main = JsonPath::parse(path).map_err(|_| error("Invalid JSONPath expression"))?;
        let mapping = fields
            .mapping
            .unwrap_or_default()
            .into_iter()
            .map(|(key, source)| {
                let path = JsonPath::parse(&source).map_err(|_| {
                    CatalogApiError::detail(
                        StatusCode::BAD_REQUEST,
                        format!("Invalid JSONPath expression for key '{key}'"),
                    )
                })?;
                Ok((key, path))
            })
            .collect::<Result<_, CatalogApiError>>()?;
        Ok(Some(Self {
            main,
            wildcard: path == "$[*]",
            mapping,
        }))
    }

    fn apply(&self, response: &Value) -> Value {
        let matches = if self.wildcard && response.is_object() {
            vec![response]
        } else {
            self.main.query(response).all()
        };
        let mut results = if self.mapping.is_empty() {
            matches.into_iter().cloned().collect::<Vec<_>>()
        } else {
            matches
                .into_iter()
                .map(|result| {
                    Value::Object(
                        self.mapping
                            .iter()
                            .map(|(key, path)| {
                                let nodes = path.query(result).all();
                                let value = match nodes.as_slice() {
                                    [] => Value::Null,
                                    [one] => (*one).clone(),
                                    _ => json!(nodes),
                                };
                                (key.clone(), value)
                            })
                            .collect(),
                    )
                })
                .collect()
        };
        if results.len() == 1 && results[0].is_object() {
            results.pop().expect("one JSONPath result")
        } else {
            Value::Array(results)
        }
    }
}
