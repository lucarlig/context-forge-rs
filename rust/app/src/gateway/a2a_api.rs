// SPDX-License-Identifier: Apache-2.0

use axum::{
    extract::{Path, Query},
    http::HeaderValue,
};
use serde_json::Map;
use sqlx::types::Json as DbJson;

use super::{catalog_api::*, *};
use crate::catalog::{AgentInteraction, AgentLookup, AgentRecord, AgentWriteError};
use crate::schema_validation::Target;
use crate::uaid::{self, UaidInput};

mod admin;
pub(crate) use admin::{AdminA2aQuery, AdminAgentAction, a2a_agent_metadata};
mod cards;
mod diagnostics;
mod federation;
mod lifecycle;
mod oauth;
mod protocol;
mod push_configs;
mod tasks;

const FAILURE: &str = "A2A agent invocation failed";

pub(super) fn router() -> Router<Arc<GatewayService>> {
    let mut router = Router::new();
    for base in ["/a2a", "/v1/a2a"] {
        router = router
            .route(base, get(list).post(register))
            .route(&format!("{base}/"), get(list).post(register))
            .route(
                &format!("{base}/{{id}}"),
                get(detail).put(lifecycle::update).delete(lifecycle::remove),
            )
            .route(&format!("{base}/{{id}}/state"), post(lifecycle::set_state))
            .route(&format!("{base}/{{id}}/toggle"), post(lifecycle::set_state))
            .route(&format!("{base}/invoke"), post(invoke_by_id))
            .route(&format!("{base}/metrics"), get(diagnostics::metrics))
            .route(&format!("{base}/{{id}}/test"), post(diagnostics::test))
            .route(&format!("{base}/fetch-card"), post(cards::discover))
            .route(&format!("{base}/{{id}}/card"), get(cards::generated))
            .route(&format!("{base}/{{id}}/stored-card"), get(cards::stored))
            .route(
                &format!("{base}/{{id}}/stored-card/extended"),
                get(cards::stored_extended),
            )
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
            )
            .route(
                &format!("{base}/{{agent}}/tasks/{{task}}/pushNotificationConfigs"),
                push_configs::collection(),
            )
            .route(
                &format!("{base}/{{agent}}/tasks/{{task}}/pushNotificationConfigs/{{id}}"),
                push_configs::item(),
            );
    }
    router
}

async fn require(
    app: &GatewayService,
    principal: &Principal,
    permission: &str,
) -> Result<(), CatalogApiError> {
    require_enabled(app)?;
    require_catalog_permission(app, principal, permission, true).await
}

fn require_enabled(app: &GatewayService) -> Result<(), CatalogApiError> {
    if !app.a2a_enabled {
        return Err(CatalogApiError(
            StatusCode::NOT_FOUND,
            json!({"detail":{"error":"a2a_disabled","message":"A2A is disabled on this gateway"}}),
        ));
    }
    Ok(())
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
    #[serde(flatten)]
    uaid: UaidInput,
    #[serde(alias = "cardUrl")]
    card_url: Option<String>,
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
    let origin = WriteOrigin {
        address: client_address(peer),
        agent: user_agent(&headers),
        via: None,
    };
    let result = register_agent(&app, &principal, registration, origin, false).await?;
    Ok((StatusCode::CREATED, Json(result)))
}

async fn register_agent(
    app: &GatewayService,
    principal: &Principal,
    registration: Registration,
    origin: WriteOrigin,
    admin: bool,
) -> Result<Value, CatalogApiError> {
    let input = registration.agent;
    let name = input.name.trim();
    let endpoint = input.endpoint_url.trim();
    let binding = input.protocol_binding.as_deref();
    let slug = agent_slug(name)?;
    if endpoint.len() > 767
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
    let team = registration_team(
        app,
        principal,
        &registration.visibility,
        registration.team_id.as_deref(),
    )
    .await
    .map_err(|error| CatalogApiError(error.status, json!({"message":error.message})))?;
    if !app
        .access
        .allows(
            principal,
            "a2a.create",
            team.as_deref()
                .map_or(RoleContext::AnyTeam, RoleContext::Team),
            !admin,
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
    let uaid = input
        .uaid
        .generate(&app.uaid, endpoint, name, true)
        .map_err(|message| CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message))?;
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
            "basic" | "bearer" | "authheaders" | "query_param" | "oauth"
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
    let oauth_config = match input.auth.oauth_config() {
        Some(config) => Some(oauth::store(app, config).await?),
        None => None,
    };
    let cards = cards::registration(
        app,
        input.card_url.as_deref(),
        endpoint,
        auth.as_ref().map(|auth| &auth.credentials.headers),
    )
    .await?;
    let mut record = AgentRecord {
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
        created_from_ip: origin.address,
        created_via: origin.via.map(str::to_owned),
        created_user_agent: origin.agent,
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
        tenant: None,
        icon_url: None,
        oauth_config,
    };
    if let Some(uaid) = uaid {
        record.set_uaid(uaid);
    }
    let agent = app
        .database
        .insert_agent(
            &record,
            encoded_query.as_ref(),
            &cards::stored_rows(cards.as_ref()),
        )
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
            AgentWriteError::Changed | AgentWriteError::ToolConflict => {
                lifecycle::write_error(error, &record)
            }
            AgentWriteError::Database(error) => error.into(),
        })?;
    app.subscriptions.changed(
        &agent.visibility,
        agent.team_id.as_deref(),
        agent.owner_email.as_deref(),
    );
    Ok(read_agent(&agent))
}

fn agent_slug(name: &str) -> Result<String, CatalogApiError> {
    let slug = slugify(name);
    if slug.is_empty()
        || name.chars().count() > 255
        || slug.chars().count() > 255
        || name.contains(['<', '>'])
        || name.chars().any(char::is_control)
    {
        return Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid A2A agent configuration",
        ));
    }
    Ok(slug)
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
    data["skills"] = json!(agent.published_skills().collect::<Vec<_>>());
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
    if let Some(config) = agent.oauth_config.as_ref() {
        let mut masked = config.0.clone();
        server_api::mask_oauth_fields(&mut masked);
        data["oauthConfig"] = masked;
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

async fn owns_agent(
    app: &GatewayService,
    principal: &Principal,
    agent: &AgentRecord,
) -> Result<bool, CatalogApiError> {
    if agent.owner_email.as_deref() == Some(principal.email.as_str()) || principal.is_global_admin()
    {
        return Ok(true);
    }
    if agent.visibility == "team"
        && let Some(team) = agent.team_id.as_deref()
    {
        return Ok(app.database.team_owner(&principal.email, team).await?);
    }
    Ok(false)
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
    let result = federation::dispatch(
        &app,
        &principal,
        AgentLookup::Id(&input.agent_id),
        input.invocation,
        &headers,
    )
    .await?;
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
    let result =
        federation::dispatch(&app, &principal, AgentLookup::Name(&name), input, &headers).await?;
    Ok(Json(result))
}

async fn invoke_recorded(
    app: &GatewayService,
    agent: &AgentRecord,
    input: Invocation,
    headers: &HeaderMap,
) -> Result<Value, CatalogApiError> {
    let result = invoke(app, agent, input, Some(headers), InvocationSource::Api).await?;
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

    let response = federation::dispatch(
        &app,
        &principal,
        AgentLookup::Name(&name),
        Invocation {
            parameters: body,
            interaction_type: query_interaction(),
        },
        &headers,
    )
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

enum InvocationSource {
    Api,
    Tool,
}

async fn invoke(
    app: &GatewayService,
    agent: &AgentRecord,
    input: Invocation,
    incoming: Option<&HeaderMap>,
    source: InvocationSource,
) -> Result<Value, CatalogApiError> {
    let fail = || CatalogApiError::detail(StatusCode::BAD_REQUEST, FAILURE);
    let hops = incoming.map_or(0, uaid::hop_count);
    federation::check_hops(app, &agent.id, hops)?;
    if !agent.enabled {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            format!("A2A Agent '{}' is disabled", agent.name),
        ));
    }
    if agent.uaid.as_deref().is_some_and(|value| !value.is_empty())
        && (!app.uaid.permits_endpoint(&agent.endpoint_url)
            || agent
                .uaid_native_id
                .as_deref()
                .is_some_and(|endpoint| !app.uaid.permits_endpoint(endpoint)))
    {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "A2A UAID agent endpoint is blocked by the domain allowlist",
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
        Some("oauth") => {
            app.upstream
                .check_endpoint(&agent.endpoint_url)
                .map_err(|_| {
                    CatalogApiError::detail(
                        StatusCode::BAD_REQUEST,
                        "Outbound A2A URL blocked by URL policy",
                    )
                })?;
            headers.insert(
                header::AUTHORIZATION,
                oauth::authorization(app, agent).await?,
            );
        }
        Some("bearer" | "basic" | "authheaders") => {
            let stored = agent.stored_headers().ok_or_else(fail)?;
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
    if let Some(id) = crate::http_boundary::CorrelationId::current() {
        id.write_header(&mut headers);
    }
    uaid::stamp(&mut headers, hops);
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
    let span = OperationSpan::start(
        &app.database,"a2a.invoke","client",
        Some(SpanResource {kind:"agent",name:&agent.name,id:Some(&agent.id)}),
        || json!({
            "a2a.agent.name":agent.name,"a2a.agent.id":agent.id,"a2a.agent.type":agent.agent_type,
            "a2a.interaction_type":input.interaction_type.chars().take(50).collect::<String>(),
        }),
    ).await;
    span.inject_trace_context(request.headers_mut());
    let started = std::time::Instant::now();
    let result = span.scope(Box::pin(dispatch_upstream(app, request))).await;
    let failure = match &result {
        Ok(body) if protocol::has_rpc_error(body) => Some("A2A agent returned a JSON-RPC error"),
        Err(_) => Some(FAILURE),
        Ok(_) => None,
    };
    let outcome = failure.map_or(Outcome::Ok, Outcome::Error);
    if matches!(source, InvocationSource::Tool) {
        span.finish(outcome).await;
        return result;
    }
    let metric = app.a2a_metrics.record.then(|| AgentInteraction {
        response_time: started.elapsed(),
        kind: &input.interaction_type,
        failure,
    });
    if let Err(error) = app
        .database
        .record_agent_interaction(&agent.id, metric)
        .await
    {
        tracing::warn!(%error, "failed to record A2A interaction");
    }
    span.finish(outcome).await;
    result
}

async fn dispatch_upstream(
    app: &GatewayService,
    request: reqwest::Request,
) -> Result<Value, CatalogApiError> {
    let fail = || CatalogApiError::detail(StatusCode::BAD_REQUEST, FAILURE);
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
    serde_json::from_slice(&response.body).map_err(|_| fail())
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
        InvocationSource::Tool,
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
