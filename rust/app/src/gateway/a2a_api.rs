// SPDX-License-Identifier: Apache-2.0

use axum::{
    extract::{Path, Query},
    http::HeaderValue,
};
use serde_json::Map;
use sqlx::types::Json as DbJson;

use super::{catalog_api::*, *};
use crate::catalog::{AgentLookup, AgentRecord, AgentWriteError};
use crate::schema_validation::Target;

mod protocol;
mod tasks;

const FAILURE: &str = "A2A agent invocation failed";

pub(super) fn router() -> Router<Arc<GatewayService>> {
    let mut router = Router::new();
    for base in ["/a2a", "/v1/a2a"] {
        router = router
            .route(base, get(list).post(register))
            .route(&format!("{base}/"), get(list).post(register))
            .route(&format!("{base}/{{id}}"), get(detail))
            .route(&format!("{base}/invoke"), post(invoke_by_id))
            .route(&format!("{base}/{{name}}/invoke"), post(invoke_by_name))
            .route(&format!("{base}/{{name}}/jsonrpc"), post(raw_rpc))
            .route(&format!("{base}/{{agent}}/tasks"), get(tasks::list))
            .route(
                &format!("{base}/{{agent}}/tasks/{{task}}"),
                get(tasks::detail),
            )
            .route(
                &format!("{base}/{{agent}}/tasks/{{task}}/cancel"),
                post(tasks::cancel),
            )
            .route(
                &format!("{base}/{{agent}}/tasks/{{task}}/messages"),
                post(tasks::continue_task),
            );
    }
    router
}

async fn require(
    app: &GatewayService,
    principal: &Principal,
    permission: &str,
) -> Result<(), CatalogApiError> {
    if !app.a2a_enabled {
        return Err(CatalogApiError(
            StatusCode::NOT_FOUND,
            json!({"detail":{"error":"a2a_disabled","message":"A2A is disabled on this gateway"}}),
        ));
    }
    require_catalog_permission(app, principal, permission, true).await
}

#[derive(Deserialize)]
struct Registration {
    agent: AgentInput,
    team_id: Option<String>,
    #[serde(default = "public")]
    visibility: String,
}

#[derive(Deserialize)]
struct AgentInput {
    name: String,
    description: Option<String>,
    endpoint_url: String,
    #[serde(default = "generic")]
    agent_type: String,
    protocol_binding: Option<String>,
    #[serde(default = "version_one")]
    protocol_version: String,
    #[serde(default)]
    capabilities: Map<String, Value>,
    skills: Option<Vec<Map<String, Value>>>,
    #[serde(default)]
    config: Map<String, Value>,
    passthrough_headers: Option<Vec<String>>,
    #[serde(default)]
    tags: Vec<Value>,
    #[serde(default)]
    generate_uaid: bool,
    #[serde(flatten)]
    auth: AuthInput,
}

fn public() -> String {
    "public".into()
}
fn generic() -> String {
    "generic".into()
}
fn version_one() -> String {
    "1.0".into()
}
fn query_interaction() -> String {
    "query".into()
}

async fn register(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(registration): Json<Registration>,
) -> Result<(StatusCode, Json<Value>), CatalogApiError> {
    require(&app, &principal, "a2a.create").await?;
    let input = registration.agent;
    let name = input.name.trim();
    let endpoint = input.endpoint_url.trim();
    let binding = input.protocol_binding.as_deref();
    let slug = slugify(name);
    if slug.is_empty()
        || name.chars().count() > 255
        || slug.chars().count() > 255
        || name.contains(['<', '>'])
        || name.chars().any(char::is_control)
        || endpoint.len() > 767
        || input.agent_type.is_empty()
        || input.agent_type.len() > 50
        || input.protocol_version.len() > 10
        || binding.is_some_and(|value| !matches!(value, "jsonrpc" | "http_json"))
        || !matches!(
            registration.visibility.as_str(),
            "public" | "team" | "private"
        )
    {
        return Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid A2A agent configuration",
        ));
    }
    if input.generate_uaid {
        return Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "A2A UAID registration is unavailable",
        ));
    }
    let team = registration_team(
        &app,
        &principal,
        &registration.visibility,
        registration.team_id.as_deref(),
    )
    .await
    .map_err(|error| CatalogApiError(error.status, json!({"message":error.message})))?;
    if !app
        .access
        .allows(
            &principal,
            "a2a.create",
            team.as_deref()
                .map_or(RoleContext::AnyTeam, RoleContext::Team),
            true,
        )
        .await?
    {
        return Err(denied_team());
    }
    app.upstream.check_endpoint(endpoint).map_err(|_| {
        CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "Outbound A2A URL blocked by URL policy",
        )
    })?;
    let auth = input
        .auth
        .prepare(
            app.credential_cipher.as_ref(),
            app.query_auth_hosts.as_ref(),
            endpoint,
        )
        .map_err(|error| {
            CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, error.to_string())
        })?;
    if auth.as_ref().is_some_and(|auth| {
        !matches!(
            auth.kind,
            "basic" | "bearer" | "authheaders" | "query_param"
        )
    }) {
        return Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unsupported A2A authentication method",
        ));
    }
    let encoded_query: Option<Value> = auth
        .as_ref()
        .and_then(|auth| auth.encoded_query.as_deref())
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| CatalogApiError::unavailable())?;
    let record = AgentRecord {
        id: Uuid::new_v4().simple().to_string(),
        name: name.to_owned(),
        slug,
        endpoint_url: endpoint.to_owned(),
        description: input.description,
        agent_type: input.agent_type,
        protocol_binding: input.protocol_binding,
        protocol_version: input.protocol_version,
        capabilities: DbJson(Value::Object(input.capabilities)),
        skills: input.skills.map(|skills| DbJson(json!(skills))),
        config: DbJson(Value::Object(input.config)),
        passthrough_headers: input.passthrough_headers.map(DbJson),
        tags: DbJson(normalized_tags(input.tags)?),
        auth_type: auth.as_ref().map(|auth| auth.kind.into()),
        auth_value: auth.and_then(|auth| auth.encoded_headers),
        auth_query_params: None,
        enabled: true,
        reachable: true,
        team_id: team,
        team: None,
        owner_email: Some(principal.email.clone()),
        visibility: registration.visibility,
        created_at: String::new(),
        updated_at: String::new(),
        created_by: None,
        created_from_ip: client_address(peer),
        created_via: None,
        created_user_agent: user_agent(&headers),
        modified_by: None,
        modified_from_ip: None,
        modified_via: None,
        modified_user_agent: None,
        import_batch_id: None,
        federation_source: None,
        last_interaction: None,
        version: 1,
        uaid: None,
        uaid_registry: None,
        uaid_proto: None,
        uaid_native_id: None,
    };
    let agent = app
        .database
        .insert_agent(&record, encoded_query.as_ref())
        .await
        .map_err(|error| match error {
            AgentWriteError::Duplicate { id, enabled } => {
                let inactive = if enabled { "" } else { " (inactive)" };
                CatalogApiError::detail(
                    StatusCode::CONFLICT,
                    format!(
                        "A2A agent with name '{}' already exists{inactive} (ID: {id})",
                        record.slug
                    ),
                )
            }
            AgentWriteError::Database(error) => error.into(),
        })?;
    app.subscriptions.changed(
        &agent.visibility,
        agent.team_id.as_deref(),
        agent.owner_email.as_deref(),
    );
    Ok((StatusCode::CREATED, Json(read_agent(&agent))))
}

async fn list(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<CatalogListQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    require(&app, &principal, "a2a.read").await?;
    let page = CatalogPage::prepare(&app, &principal, &query, "a2a/agents")?;
    let agents = app
        .database
        .list_agents(access::catalog_scope(Some(&principal)), page.filters())
        .await?;
    page.envelope(
        &app,
        agents,
        "agents",
        |item| (&item.created_at, &item.id),
        read_agent,
    )
    .map(Json)
}

async fn detail(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    require(&app, &principal, "a2a.read").await?;
    let agent = find(&app, Some(&principal), AgentLookup::Id(&id)).await?;
    Ok(Json(read_agent(&agent)))
}

fn read_agent(agent: &AgentRecord) -> Value {
    let mut data = serde_json::to_value(agent).expect("agent record serializes");
    data["createdAt"] = json!(agent.created_at.replace(' ', "T"));
    data["updatedAt"] = json!(agent.updated_at.replace(' ', "T"));
    data["lastInteraction"] = json!(
        agent
            .last_interaction
            .as_ref()
            .map(|time| time.replace(' ', "T"))
    );
    data["authValue"] = json!(agent.auth_value.as_ref().map(|_| "*****"));
    for key in [
        "metrics",
        "oauthConfig",
        "authUsername",
        "authPassword",
        "authToken",
        "authHeaderKey",
        "authHeaderValue",
        "authHeaders",
        "authQueryParamKey",
        "authQueryParamValueMasked",
    ] {
        data[key] = Value::Null;
    }
    if agent.auth_type.as_deref() == Some("query_param")
        && let Some(query) = agent.auth_query_params.as_deref()
        && let Ok(params) = serde_json::from_str::<Map<String, Value>>(query)
        && let Some(key) = params.keys().next()
    {
        data["authQueryParamKey"] = json!(key);
        data["authQueryParamValueMasked"] = json!("*****");
    }
    data
}

async fn find(
    app: &GatewayService,
    principal: Option<&Principal>,
    lookup: AgentLookup<'_>,
) -> Result<AgentRecord, CatalogApiError> {
    let (field, key) = match lookup {
        AgentLookup::Id(id) => ("ID", id),
        AgentLookup::Name(name) => ("name", name),
    };
    app.database
        .find_agent(access::catalog_scope(principal), lookup)
        .await?
        .ok_or_else(|| {
            CatalogApiError::detail(
                StatusCode::NOT_FOUND,
                format!("A2A Agent not found with {field}: {key}"),
            )
        })
}

#[derive(Deserialize)]
struct Invocation {
    #[serde(default)]
    parameters: Map<String, Value>,
    #[serde(default = "query_interaction")]
    interaction_type: String,
}

#[derive(Deserialize)]
struct InvocationById {
    agent_id: String,
    #[serde(flatten)]
    invocation: Invocation,
}

async fn invoke_by_id(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    Json(input): Json<InvocationById>,
) -> Result<Json<Value>, CatalogApiError> {
    require(&app, &principal, "a2a.invoke").await?;
    let agent = find(&app, Some(&principal), AgentLookup::Id(&input.agent_id)).await?;
    let result = invoke_recorded(&app, &agent, input.invocation, &headers).await?;
    Ok(Json(result))
}

async fn invoke_by_name(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Invocation>,
) -> Result<Json<Value>, CatalogApiError> {
    require(&app, &principal, "a2a.invoke").await?;
    let agent = find(&app, Some(&principal), AgentLookup::Name(&name)).await?;
    let result = invoke_recorded(&app, &agent, input, &headers).await?;
    Ok(Json(result))
}

async fn invoke_recorded(
    app: &GatewayService,
    agent: &AgentRecord,
    input: Invocation,
    headers: &HeaderMap,
) -> Result<Value, CatalogApiError> {
    let result = invoke(app, agent, input, Some(headers)).await?;
    tasks::record(app, &agent.id, &result, None).await;
    Ok(result)
}

async fn raw_rpc(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Map<String, Value>>,
) -> Result<Response, CatalogApiError> {
    require(&app, &principal, "a2a.invoke").await?;
    let id = body.get("id").cloned().filter(|id| !id.is_null());
    let validation = if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        let version = body
            .get("jsonrpc")
            .map(|version| {
                version
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| version.to_string())
            })
            .unwrap_or_else(|| "None".into());
        Some(format!(
            "Invalid or missing jsonrpc field. Expected '2.0', got '{version}'"
        ))
    } else if body
        .get("method")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        Some("Missing or invalid 'method' field in JSON-RPC request".into())
    } else if body
        .get("params")
        .is_some_and(|params| !params.is_null() && !params.is_object())
    {
        Some("JSON-RPC 'params' field must be an object or null".into())
    } else {
        None
    };
    if let Some(error) = validation {
        return Ok(rpc_error(StatusCode::BAD_REQUEST, -32600, &error, id));
    }

    let response = async {
        let agent = find(&app, Some(&principal), AgentLookup::Name(&name)).await?;
        invoke_recorded(
            &app,
            &agent,
            Invocation {
                parameters: body,
                interaction_type: query_interaction(),
            },
            &headers,
        )
        .await
    }
    .await;
    match response {
        Ok(result) if result.get("jsonrpc").is_some() => Ok(Json(result).into_response()),
        Ok(result) => {
            let mut envelope = json!({"jsonrpc":"2.0","result":result});
            if let Some(id) = id {
                envelope["id"] = id;
            }
            Ok(Json(envelope).into_response())
        }
        Err(error) => {
            let code = if error.0 == StatusCode::NOT_FOUND {
                -32001
            } else {
                -32603
            };
            Ok(rpc_error(
                error.0,
                code,
                error.1["detail"].as_str().unwrap_or(FAILURE),
                id,
            ))
        }
    }
}

fn rpc_error(status: StatusCode, code: i32, message: &str, id: Option<Value>) -> Response {
    let mut body = json!({"jsonrpc":"2.0","error":{"code":code,"message":message}});
    if let Some(id) = id {
        body["id"] = id;
    }
    (status, Json(body)).into_response()
}

async fn invoke(
    app: &GatewayService,
    agent: &AgentRecord,
    input: Invocation,
    incoming: Option<&HeaderMap>,
) -> Result<Value, CatalogApiError> {
    let fail = || CatalogApiError::detail(StatusCode::BAD_REQUEST, FAILURE);
    if !agent.enabled {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            format!("A2A Agent '{}' is disabled", agent.name),
        ));
    }
    if agent.uaid.as_deref().is_some_and(|value| !value.is_empty()) {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "A2A UAID routing is unavailable",
        ));
    }
    if app.database.agent_has_enforced_binding(agent).await? {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "A2A agent requires an unavailable invocation policy",
        ));
    }
    let jsonrpc = match agent.protocol_binding.as_deref() {
        Some("jsonrpc") => true,
        Some("http_json") => false,
        _ => {
            matches!(
                agent.agent_type.to_ascii_lowercase().as_str(),
                "generic" | "jsonrpc"
            ) || agent.endpoint_url.ends_with('/')
        }
    };
    let mut headers = HeaderMap::new();
    if let Some((incoming, allow)) = incoming.zip(agent.passthrough_headers.as_ref()) {
        for name in &allow.0 {
            if let Some(name) = tool_api::mapped_header_name(name)
                && name != "x-vault-tokens"
            {
                for value in incoming.get_all(&name) {
                    headers.append(&name, value.clone());
                }
            }
        }
    }
    let mut url = url::Url::parse(&agent.endpoint_url).map_err(|_| fail())?;
    match agent.auth_type.as_deref() {
        None | Some("none" | "") => {}
        Some("bearer" | "basic" | "authheaders") => {
            let stored = agent.auth_value.as_deref().ok_or_else(fail)?;
            let stored = if stored.starts_with(['"', '{']) {
                stored.to_owned()
            } else {
                json!(stored).to_string()
            };
            headers.extend(
                decode_headers(app.credential_cipher.as_ref(), &stored).map_err(|_| fail())?,
            );
        }
        Some("query_param") => {
            validate_query_host(app.query_auth_hosts.as_ref(), &agent.endpoint_url)
                .map_err(|_| fail())?;
            let stored = agent.auth_query_params.as_deref().ok_or_else(fail)?;
            let query = decode_query(app.credential_cipher.as_ref(), stored).map_err(|_| fail())?;
            let mut pairs = url
                .query_pairs()
                .filter(|(name, _)| !query.contains_key(name.as_ref()))
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect::<Vec<_>>();
            pairs.extend(query);
            url.set_query(None);
            url.query_pairs_mut().extend_pairs(pairs);
        }
        _ => return Err(fail()),
    }
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let payload = if jsonrpc {
        headers.insert(
            "a2a-version",
            HeaderValue::from_str(&protocol::version_header(&agent.protocol_version))
                .map_err(|_| fail())?,
        );
        headers
            .entry(header::ACCEPT)
            .or_insert(HeaderValue::from_static(
                "application/json, text/event-stream",
            ));
        protocol::rpc_request(input.parameters, &agent.protocol_version)
    } else {
        json!({"interaction_type":input.interaction_type,"parameters":input.parameters,"protocol_version":agent.protocol_version})
    };
    let mut request = reqwest::Request::new(reqwest::Method::POST, url);
    *request.headers_mut() = headers;
    *request.body_mut() = Some(payload.to_string().into());
    let response = app
        .upstream
        .with_timeout_cap(app.a2a_timeout)
        .rest_response(request, None)
        .await
        .map_err(|error| match error {
            UpstreamError::BlockedDestination | UpstreamError::InvalidUrl => {
                CatalogApiError::detail(
                    StatusCode::BAD_REQUEST,
                    "Outbound A2A URL blocked by URL policy",
                )
            }
            _ => fail(),
        })?;
    if response.status != StatusCode::OK {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            format!("A2A agent returned HTTP {}", response.status.as_u16()),
        ));
    }
    let data: Value = serde_json::from_slice(&response.body).map_err(|_| fail())?;
    if let Err(error) = app.database.record_agent_interaction(&agent.id).await {
        tracing::warn!(%error, "failed to record A2A interaction");
    }
    Ok(data)
}

pub(super) async fn call_tool(
    app: &GatewayService,
    tool: &CatalogTool,
    id: &str,
    request: &CallToolRequestParams,
    principal: Option<&Principal>,
    headers: Option<&HeaderMap>,
) -> Result<Value, ToolError> {
    if tool.requires_gateway_policy || !tool.response_filter.trim().is_empty() {
        return Err(ToolError::Unavailable);
    }
    let agent = app
        .database
        .find_agent(access::catalog_scope(principal), AgentLookup::Id(id))
        .await?
        .filter(|agent| agent.enabled)
        .ok_or(ToolError::NotFound)?;
    let arguments = request.arguments.clone().unwrap_or_default();
    match app
        .schema_validation
        .validate(
            tool.definition.input_schema.clone(),
            Value::Object(arguments.clone()),
            Target::Input,
        )
        .await
    {
        Ok((_, None)) => {}
        Ok((_, Some(error))) => {
            return Err(ToolError::InvalidArguments(format!(
                "Invalid arguments for tool '{}': {error}",
                request.name
            )));
        }
        Err(_) => return Err(ToolError::Unavailable),
    }
    let interaction_type = arguments
        .get("interaction_type")
        .and_then(Value::as_str)
        .unwrap_or("query")
        .to_owned();
    match invoke(
        app,
        &agent,
        Invocation {
            parameters: arguments,
            interaction_type,
        },
        headers,
    )
    .await
    {
        Ok(result) => {
            let value = result.get("response").unwrap_or(&result);
            let text = value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned);
            Ok(json!({"content":[ContentBlock::text(text)],"isError":false}))
        }
        Err(error) => tool_result_error(format!(
            "A2A agent error: {}",
            error.1["detail"].as_str().unwrap_or(FAILURE)
        )),
    }
}
