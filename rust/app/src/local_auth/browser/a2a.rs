// SPDX-License-Identifier: Apache-2.0

use axum::http::Uri;
use serde_json::Map;

use super::{
    catalog::{AuthorizedForm, editor},
    forms::render_with_proof,
    sessions::authorized_read as authorize,
    *,
};
use crate::gateway::{
    AdminA2aQuery, AdminAgentAction, CatalogApiError, PaginationMeta, a2a_agent_metadata,
    catalog_query_flag,
};

pub(super) fn routes(mut router: Router<Arc<Accounts>>, base: &str) -> Router<Arc<Accounts>> {
    let path = format!("{base}/a2a");
    router = router
        .route(&path, get(read).layer(Extension(View::List)).post(save))
        .route(&format!("{path}/{{id}}"), get(detail))
        .route(&format!("{path}/new"), get(edit))
        .route(&format!("{path}/{{id}}/edit"), get(edit).post(save))
        .route(
            &format!("{path}/{{id}}/state"),
            post(change).layer(Extension(Mutation::State)),
        )
        .route(
            &format!("{path}/{{id}}/delete"),
            post(change).layer(Extension(Mutation::Delete)),
        )
        .route(&format!("{path}/{{id}}/test"), post(test));
    for (name, view) in [
        ("partial", View::Partial),
        ("search", View::Search),
        ("ids", View::Ids),
    ] {
        router = router.route(&format!("{path}/{name}"), get(read).layer(Extension(view)));
    }
    router
}

pub(super) async fn visible(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    team: Option<&str>,
) -> Result<bool, sqlx::Error> {
    Ok(service.admin_a2a_enabled() && allowed(accounts, principal, "a2a.read", team).await?)
}

async fn allowed(
    accounts: &Accounts,
    principal: &Principal,
    permission: &str,
    team: Option<&str>,
) -> Result<bool, sqlx::Error> {
    accounts
        .access
        .allows(
            principal,
            permission,
            team.map_or(RoleContext::AnyTeam, RoleContext::Team),
            false,
        )
        .await
}

#[derive(Clone, Copy)]
enum View {
    List,
    Partial,
    Search,
    Ids,
}

#[derive(Serialize)]
pub(super) struct Panel {
    rows: Vec<Row>,
    pagination: PaginationMeta,
    add: bool,
    previous: Option<String>,
    next: Option<String>,
    q: Option<String>,
    tags: Option<String>,
    team: Option<String>,
    include_inactive: bool,
}

#[derive(Serialize)]
struct Row {
    data: Value,
    edit: bool,
    delete: bool,
    test: bool,
}

fn query(uri: &Uri) -> Result<AdminA2aQuery, CatalogApiError> {
    Query::try_from_uri(uri)
        .map(|Query(query)| query)
        .map_err(|_| CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, "Invalid A2A query"))
}

pub(super) async fn panel(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    uri: Option<&Uri>,
    team: Option<&str>,
    include_inactive: bool,
) -> Result<Panel, CatalogApiError> {
    let mut filters = uri.map(query).transpose()?.unwrap_or_default();
    if filters.team_id.is_none() {
        filters.team_id = team.map(str::to_owned);
    }
    filters.include_inactive = Some(include_inactive.to_string());
    read_panel(accounts, service, principal, &filters, true).await
}

async fn read_panel(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    query: &AdminA2aQuery,
    home: bool,
) -> Result<Panel, CatalogApiError> {
    let page = service.admin_agent_page(principal, query).await?;
    let pagination = page.pagination;
    let team = page.team.or(query.team()?);
    let include_inactive = query.include_inactive()?;
    let mut rows = Vec::with_capacity(page.rows.len());
    for agent in &page.rows {
        let actions = service.admin_agent_controls(principal, agent).await?;
        rows.push(Row {
            data: a2a_agent_metadata(agent),
            edit: actions.edit,
            delete: actions.delete,
            test: actions.test,
        });
    }
    let link = |number: i64| {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        let root = &settings_for(accounts).root;
        let path = if home {
            params.append_pair("section", "a2a");
            "/admin/"
        } else {
            "/admin/a2a/partial"
        };
        for (name, value) in [
            ("team_id", team.as_deref()),
            ("q", query.q.as_deref()),
            ("tags", query.tags.as_deref()),
            ("render", query.render.as_deref()),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                params.append_pair(name, value);
            }
        }
        if include_inactive {
            params.append_pair("include_inactive", "true");
        }
        params
            .append_pair("page", &number.to_string())
            .append_pair("per_page", &pagination.per_page.to_string());
        format!("{root}{path}?{}", params.finish())
    };
    Ok(Panel {
        previous: pagination.has_prev.then(|| link(pagination.page - 1)),
        next: pagination.has_next.then(|| link(pagination.page + 1)),
        pagination,
        rows,
        add: allowed(accounts, principal, "a2a.create", team.as_deref()).await?,
        q: query.q.clone(),
        tags: query.tags.clone(),
        team,
        include_inactive,
    })
}

async fn read(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Extension(view): Extension<View>,
    request: Request,
) -> Response {
    let (principal, parts, proof) = match authorize(&accounts, request, peer).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let query = query(&parts.uri)?;
        let result = match view {
            View::List => Json(
                service
                    .admin_agent_page(&principal, &query)
                    .await?
                    .payload(),
            )
            .into_response(),
            View::Search => {
                Json(service.admin_agent_search(&principal, &query).await?).into_response()
            }
            View::Ids => Json(service.admin_agent_ids(&principal, &query).await?).into_response(),
            View::Partial => {
                let mode = query.render.as_deref().unwrap_or("");
                if !matches!(mode, "" | "controls" | "selector") {
                    return Err(CatalogApiError::detail(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Invalid A2A render mode",
                    ));
                }
                let agents = read_panel(&accounts, &service, &principal, &query, false).await?;
                render_with_proof(
                    &accounts,
                    "a2a.html",
                    context! {
                        agents,mode,proof,root => &settings_for(&accounts).root,
                    },
                    &proof,
                )
                .map_err(account_error)?
            }
        };
        Ok::<_, CatalogApiError>(result)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), async {
        response.await.into_response()
    })
    .await
}

fn account_error(error: AccountError) -> CatalogApiError {
    CatalogApiError::detail(
        error.0,
        error.1["detail"].as_str().unwrap_or("A2A request failed"),
    )
}

async fn detail(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let (principal, parts, _) = match authorize(&accounts, request, peer).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        service
            .admin_agent(&principal, &id, false)
            .await
            .map(Json)
            .into_response()
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

async fn edit(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Option<Path<String>>,
    request: Request,
) -> Response {
    let (principal, parts, proof) = match authorize(&accounts, request, peer).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let query = query(&parts.uri)?;
        let team = query.team()?;
        let id = path.map(|Path(id)| id);
        let agent = if let Some(id) = id.as_deref() {
            service.admin_agent(&principal, id, true).await?
        } else {
            service
                .require_admin_agent(&principal, "a2a.create")
                .await?;
            if !allowed(&accounts, &principal, "a2a.create", team.as_deref()).await? {
                return Err(CatalogApiError::detail(
                    StatusCode::FORBIDDEN,
                    "Permission denied",
                ));
            }
            Value::Null
        };
        let tags = agent["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|tag| {
                tag.as_str()
                    .or_else(|| tag["label"].as_str())
                    .or_else(|| tag["id"].as_str())
            })
            .collect::<Vec<_>>()
            .join(", ");
        let json = |key: &str| {
            agent
                .get(key)
                .filter(|value| !value.is_null())
                .map(Value::to_string)
        };
        render_with_proof(&accounts,"browser.html",context! {
            title => if id.is_some() {"Edit A2A agent"} else {"Add A2A agent"}, page => "a2a-edit",
            root => &settings_for(&accounts).root, agent, proof, id, tags,
            team => agent["teamId"].as_str().map(str::to_owned).or(team),
            include_inactive => query.include_inactive()?,
            capabilities => json("capabilities"), skills => json("skills"), config => json("config"),
            passthrough => json("passthroughHeaders"),
        }, &proof).map_err(account_error)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), async {
        response.await.into_response()
    })
    .await
}

fn fields(
    form: &Form,
    editing: bool,
    browser: bool,
) -> Result<Map<String, Value>, CatalogApiError> {
    let mut fields = Map::new();
    for name in [
        "name",
        "description",
        "endpoint_url",
        "visibility",
        "team_id",
    ] {
        if let Some(value) = form.value(name) {
            if name == "team_id" {
                if !value.is_empty() {
                    let team = AdminA2aQuery {
                        team_id: Some(value.to_owned()),
                        ..AdminA2aQuery::default()
                    }
                    .team()?;
                    fields.insert(name.into(), json!(team));
                }
            } else {
                fields.insert(name.to_owned(), value.into());
            }
        }
    }
    for name in [
        "protocol_version",
        "protocol_binding",
        "agent_type",
        "card_url",
    ] {
        if let Some(value) = editor::nonempty(form, name) {
            fields.insert(name.to_owned(), value.into());
        }
    }
    for name in ["capabilities", "skills", "config"] {
        editor::json_field(form, &mut fields, name)?;
    }
    if let Some(tags) = form.value("tags") {
        fields.insert(
            "tags".into(),
            json!(editor::comma_separated(tags).collect::<Vec<_>>()),
        );
    }
    if let Some(headers) = editor::nonempty(form, "passthrough_headers") {
        let list = serde_json::from_str(headers)
            .unwrap_or_else(|_| json!(editor::comma_separated(headers).collect::<Vec<_>>()));
        fields.insert("passthrough_headers".into(), list);
    }
    editor::credential_fields(form, &mut fields)?;
    if fields.contains_key("oauth_config") && !fields.contains_key("auth_type") {
        fields.insert("auth_type".into(), json!("oauth"));
    }
    if editing
        && !browser
        && form.get("auth_type") == "bearer"
        && editor::nonempty(form, "auth_token").is_none()
    {
        return Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Bearer authentication requires an auth token",
        ));
    }
    if catalog_query_flag(form.value("generate_uaid"))? {
        fields.insert("generate_uaid".into(), json!(true));
        for name in ["uaid_registry", "uaid_protocol", "uaid_native_id_override"] {
            if let Some(value) = editor::nonempty(form, name) {
                fields.insert(name.into(), value.into());
            }
        }
    }
    Ok(fields)
}

async fn save(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Option<Path<String>>,
    request: Request,
) -> Response {
    let id = path.map(|Path(id)| id);
    let permission = if id.is_some() {
        "a2a.update"
    } else {
        "a2a.create"
    };
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form(&accounts, permission, request, peer.ip(), false).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let browser = form.get("_dashboard") == "true";
        let result = async {
            let fields = fields(&form, id.is_some(), browser)?;
            service
                .save_admin_agent(&principal, id.as_deref(), fields, &parts.headers, peer)
                .await
        }
        .await;
        match (browser, result) {
            (true, Ok(_)) => redirect(&accounts, &principal, &form, None, true),
            (true, Err(error)) => error_page(&accounts, error),
            (false, Ok(_)) => {
                let message = if id.is_some() {
                    "A2A agent updated successfully"
                } else {
                    "A2A agent created successfully!"
                };
                Json(json!({"success":true,"message":message})).into_response()
            }
            (false, Err(error)) => {
                if !service.admin_a2a_enabled() {
                    error.into_response()
                } else {
                    error.form_response()
                }
            }
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

#[derive(Clone, Copy)]
enum Mutation {
    State,
    Delete,
}

async fn change(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Extension(mutation): Extension<Mutation>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let permission = match mutation {
        Mutation::State => "a2a.update",
        Mutation::Delete => "a2a.delete",
    };
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form(&accounts, permission, request, peer.ip(), false).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        if !service.admin_a2a_enabled() {
            return settings_for(&accounts).redirect("/admin#a2a-agents");
        }
        let action = match mutation {
            Mutation::State => {
                AdminAgentAction::State(form.get("activate").eq_ignore_ascii_case("true"))
            }
            Mutation::Delete => {
                AdminAgentAction::Delete(form.get("purge_metrics").eq_ignore_ascii_case("true"))
            }
        };
        let error = service
            .mutate_admin_agent(&principal, &id, action)
            .await
            .err()
            .map(|error| match (error.into_response().status(), mutation) {
                (StatusCode::FORBIDDEN, _) => "permission_denied",
                (StatusCode::NOT_FOUND, _) => "not_found",
                (_, Mutation::State) => "state_change_failed",
                (_, Mutation::Delete) => "delete_failed",
            });
        redirect(
            &accounts,
            &principal,
            &form,
            error,
            form.get("_dashboard") == "true",
        )
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

async fn test(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let json_allowed = forms::has_media_type(request.headers(), "application/json");
    let AuthorizedForm {
        principal,
        parts,
        form,
        json,
    } = match catalog::authorized_form(&accounts, "a2a.invoke", request, peer.ip(), json_allowed)
        .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let text = json
            .as_ref()
            .and_then(|value| value.get("query"))
            .and_then(Value::as_str)
            .or_else(|| form.value("query"));
        let result = service
            .test_admin_agent(&principal, &id, &parts.headers, text)
            .await;
        if form.get("_dashboard") != "true" {
            return result.map(Json).into_response();
        }
        match result {
            Ok(data) => render(context! {
                title => "A2A agent test", page => "a2a-test", root => &settings_for(&accounts).root,
                agent => data["agent_name"], result => serde_json::to_string_pretty(&data["result"]).unwrap_or_default(),
            }).into_response(),
            Err(error) => error_page(&accounts, error),
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

fn redirect(
    accounts: &Accounts,
    principal: &Principal,
    form: &Form,
    error: Option<&str>,
    browser: bool,
) -> Response {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    if browser {
        params.append_pair("section", "a2a");
    }
    if let Some(error) = error {
        params.append_pair("error", error);
    }
    if form.get("is_inactive_checked").eq_ignore_ascii_case("true") {
        params.append_pair("include_inactive", "true");
    }
    let requested_team = form.get("team_id");
    if let Some(team) = Uuid::parse_str(requested_team)
        .ok()
        .map(|_| requested_team.to_ascii_lowercase())
        .filter(|id| match &principal.visibility {
            TeamVisibility::Admin => true,
            TeamVisibility::Teams(teams) => teams.contains(id),
            TeamVisibility::Public => false,
        })
    {
        params.append_pair("team_id", &team);
    }
    let query = params.finish();
    let suffix = if query.is_empty() {
        String::new()
    } else {
        format!("/?{query}")
    };
    settings_for(accounts).redirect(&format!("/admin{suffix}#a2a-agents"))
}

fn error_page(accounts: &Accounts, error: CatalogApiError) -> Response {
    let message = error.form_message().to_owned();
    let status = error.into_response().status();
    render(context! {
        page => "a2a-error", title => "A2A request failed", error => message,
        root => &settings_for(accounts).root,
    })
    .map(|mut response| {
        *response.status_mut() = status;
        response
    })
    .into_response()
}
