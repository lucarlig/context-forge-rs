// SPDX-License-Identifier: Apache-2.0

pub(super) mod editor;

use std::{
    collections::{HashMap, hash_map::Entry},
    future::Future,
    net::IpAddr,
};

use axum::http::{Uri, request::Parts};

use super::*;
use crate::{
    gateway::{AdminListQuery, CatalogApiError, CatalogListing, CatalogMutation},
    tokens::TokenRequest,
};

pub(super) async fn list(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(kind): Extension<ManagedCatalog>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let Session { principal, .. } =
        match access(&accounts, request.headers(), request.uri(), peer.ip()).await {
            Ok(session) => session,
            Err(denial) => return Ok(denial.response(settings, request.headers())),
        };
    if password_change_pending(&accounts, &principal).await? {
        return Ok(settings.redirect(CHANGE));
    }
    let team = sessions::request_team(request.uri(), &principal);
    if !allows(&accounts, &principal, kind, "read", team.as_deref()).await? {
        return Ok(Denial(StatusCode::FORBIDDEN, "Permission denied", None)
            .response(settings, request.headers()));
    }
    let query = match read_query(request.uri()) {
        Ok(query) => query,
        Err(error) => return Ok(error.into_response()),
    };
    let (parts, _) = request.into_parts();
    let response = async {
        service
            .admin_catalog(kind, &principal, &query, None)
            .await
            .map(|listing| Json(listing).into_response())
            .unwrap_or_else(IntoResponse::into_response)
    };
    Ok(with_usage(&accounts, &principal, &parts, peer.ip(), response).await)
}

pub(super) async fn gateway_detail(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let Session { principal, .. } =
        match access(&accounts, request.headers(), request.uri(), peer.ip()).await {
            Ok(session) => session,
            Err(denial) => return Ok(denial.response(settings, request.headers())),
        };
    if password_change_pending(&accounts, &principal).await? {
        return Ok(settings.redirect(CHANGE));
    }
    let team = sessions::request_team(request.uri(), &principal);
    if !allows(
        &accounts,
        &principal,
        ManagedCatalog::Gateways,
        "read",
        team.as_deref(),
    )
    .await?
    {
        return Err(AccountError::detail(
            StatusCode::FORBIDDEN,
            "Permission denied",
        ));
    }
    let (parts, _) = request.into_parts();
    let response = async {
        service
            .admin_gateway_detail(&principal, id)
            .await
            .map(|value| Json(value).into_response())
            .unwrap_or_else(IntoResponse::into_response)
    };
    Ok(with_usage(&accounts, &principal, &parts, peer.ip(), response).await)
}

pub(super) async fn delete_gateway(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let AuthorizedForm {
        principal, parts, ..
    } = match authorized_form(&accounts, "gateways.delete", request, peer.ip(), false).await {
        Ok(form) => form,
        Err(response) => return *response,
    };
    let response = async {
        service
            .delete_admin_gateway(&principal, id)
            .await
            .unwrap_or_else(CatalogApiError::form_response)
    };
    with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

#[derive(Clone, Copy)]
pub(super) enum Action {
    State,
    Delete,
    Refresh,
}

impl Action {
    pub(super) fn path(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Delete => "delete",
            Self::Refresh => "tools/refresh",
        }
    }

    fn permission(self) -> &'static str {
        match self {
            Self::State | Self::Refresh => "update",
            Self::Delete => "delete",
        }
    }
}

pub(super) async fn mutate(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension((kind, action)): Extension<(ManagedCatalog, Action)>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, AccountError> {
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match authorized_form(
        &accounts,
        &format!("{}.{}", kind.name(), action.permission()),
        request,
        peer.ip(),
        false,
    )
    .await
    {
        Ok(form) => form,
        Err(response) => return Ok(*response),
    };
    let settings = settings_for(&accounts);
    let response = async {
        let affirmative = |name| form.get(name).eq_ignore_ascii_case("true");
        let mutation = match action {
            Action::State => CatalogMutation::State(
                form.value("activate")
                    .is_none_or(|value| value.eq_ignore_ascii_case("true")),
            ),
            Action::Delete => CatalogMutation::Delete {
                purge_metrics: affirmative("purge_metrics"),
            },
            Action::Refresh => CatalogMutation::Refresh,
        };
        let result = service
            .mutate_admin_catalog(kind, &principal, id, mutation, &parts.headers)
            .await;
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        match result {
            Err(error) => {
                query.append_pair("error", error);
            }
            Ok(Some(message)) => {
                query.append_pair("message", message);
            }
            Ok(None) => {}
        }
        if affirmative("is_inactive_checked") {
            query.append_pair("include_inactive", "true");
        }
        if let Ok(team) = Uuid::parse_str(form.get("team_id")) {
            query.append_pair("team_id", &team.simple().to_string());
        }
        let query = query.finish();
        let fragment = fragment(kind);
        let path = if query.is_empty() {
            format!("/admin#{fragment}")
        } else {
            format!("/admin/?{query}#{fragment}")
        };
        settings.redirect(&path)
    };
    Ok(with_usage(&accounts, &principal, &parts, peer.ip(), response).await)
}

pub(super) struct AuthorizedForm {
    pub(super) principal: Principal,
    pub(super) parts: Parts,
    pub(super) form: Form,
    pub(super) json: Option<serde_json::Map<String, Value>>,
}

pub(super) async fn authorized_form(
    accounts: &Accounts,
    permission: &str,
    request: Request,
    peer: IpAddr,
    json_allowed: bool,
) -> Result<AuthorizedForm, Box<Response>> {
    authorized_form_for_team(accounts, permission, request, peer, json_allowed, None).await
}

pub(super) async fn authorized_form_for_team(
    accounts: &Accounts,
    permission: &str,
    request: Request,
    peer: IpAddr,
    json_allowed: bool,
    target: Option<&str>,
) -> Result<AuthorizedForm, Box<Response>> {
    let settings = settings_for(accounts);
    let Session { principal, .. } =
        match access(accounts, request.headers(), request.uri(), peer).await {
            Ok(session) => session,
            Err(denial) => return Err(Box::new(denial.response(settings, request.headers()))),
        };
    if password_change_pending(accounts, &principal)
        .await
        .map_err(|error| Box::new(error.into_response()))?
    {
        return Err(Box::new(settings.redirect(CHANGE)));
    }
    let (parts, form, json) = if json_allowed
        && forms::has_media_type(request.headers(), "application/json")
    {
        let (parts, body) = request.into_parts();
        let bytes = axum::body::to_bytes(body, forms::MAX_FORM_BYTES)
            .await
            .map_err(|_| {
                Box::new(
                    AccountError::detail(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large")
                        .into_response(),
                )
            })?;
        let json = serde_json::from_slice(&bytes).map_err(|_| {
            Box::new(
                AccountError::detail(StatusCode::BAD_REQUEST, "Invalid JSON body").into_response(),
            )
        })?;
        (parts, Form::default(), Some(json))
    } else {
        if json_allowed
            && !forms::urlencoded(request.headers())
            && !forms::has_media_type(request.headers(), "multipart/form-data")
        {
            return Err(Box::new(
                AccountError::detail(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Use application/json or multipart/form-data",
                )
                .into_response(),
            ));
        }
        let (parts, form) = Form::from_catalog_request(request)
            .await
            .map_err(|error| Box::new(error.into_response()))?;
        (parts, form, None)
    };
    csrf(settings, &parts, &form, false).map_err(|error| Box::new(error.into_response()))?;
    if sessions::bearer_token(settings, &parts.headers).is_none()
        && !browser_request(&parts.headers)
    {
        return Err(Box::new((
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({"detail":"Cookie authentication not allowed for API requests. Use Authorization header."})),
        ).into_response()));
    }
    let team = sessions::request_team(&parts.uri, &principal);
    let role = target
        .or(team.as_deref())
        .map_or(RoleContext::AnyTeam, RoleContext::Team);
    if !accounts
        .access
        .allows(&principal, permission, role, false)
        .await
        .map_err(|error| Box::new(AccountError::from(error).into_response()))?
    {
        return Err(Box::new(
            AccountError::detail(StatusCode::FORBIDDEN, "Permission denied").into_response(),
        ));
    }
    Ok(AuthorizedForm {
        principal,
        parts,
        form,
        json,
    })
}

pub(super) async fn with_usage(
    accounts: &Accounts,
    principal: &Principal,
    parts: &Parts,
    peer: IpAddr,
    response: impl Future<Output = Response>,
) -> Response {
    let started = Instant::now();
    let address = peer.to_string();
    let reservation = match accounts
        .access
        .reserve_usage(
            Some(principal),
            TokenRequest {
                endpoint: parts.uri.path(),
                method: parts.method.as_str(),
                peer: Some(&address),
                agent: forms::header_text(&parts.headers, header::USER_AGENT),
            },
        )
        .await
    {
        Ok(reservation) => reservation,
        Err(error) => return error.into_response(),
    };
    let response = response.await;
    accounts
        .access
        .finish_usage(reservation, response.status(), started)
        .await;
    response
}

async fn allows(
    accounts: &Accounts,
    principal: &Principal,
    kind: ManagedCatalog,
    operation: &str,
    team: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let role = team.map_or(RoleContext::AnyTeam, RoleContext::Team);
    accounts
        .access
        .allows(
            principal,
            &format!("{}.{operation}", kind.name()),
            role,
            false,
        )
        .await
}

fn read_query(uri: &Uri) -> Result<AdminListQuery, CatalogApiError> {
    Query::try_from_uri(uri)
        .map(|Query(query)| query)
        .map_err(|_| {
            CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, "Invalid pagination")
        })
}

#[derive(Serialize)]
pub(super) struct Dashboard {
    navigation: Vec<Link>,
    sections: Vec<Section>,
    include_inactive: bool,
    team: Option<String>,
    selected: Option<String>,
    pub(super) tokens: Option<super::token::Panel>,
    pub(super) users: Option<super::users::Panel>,
    pub(super) teams: Option<super::team::Panel>,
    error: Option<&'static str>,
    message: Option<&'static str>,
}

#[derive(Serialize)]
struct Link {
    label: &'static str,
    href: String,
    selected: bool,
}

#[derive(Serialize)]
struct Section {
    name: &'static str,
    fragment: &'static str,
    label: &'static str,
    rows: Vec<Row>,
    actions: bool,
    create: bool,
    purge_metrics: bool,
    total: i64,
    page: i64,
    pages: i64,
    previous: Option<String>,
    next: Option<String>,
}

#[derive(Serialize)]
struct Row {
    id: String,
    name: String,
    description: Option<String>,
    enabled: bool,
    visibility: Option<String>,
    update: bool,
    delete: bool,
    refresh: bool,
    oauth: Option<&'static str>,
}

async fn rows(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    kind: ManagedCatalog,
    data: &[Value],
) -> Result<Vec<Row>, sqlx::Error> {
    let mut permissions = HashMap::new();
    let mut rows = Vec::with_capacity(data.len());
    let global_admin = principal.is_global_admin();
    let oauth = if matches!(kind, ManagedCatalog::Gateways) {
        let ids = data
            .iter()
            .filter(|row| row["oauthConfig"]["grant_type"] == "authorization_code")
            .filter_map(|row| row["id"].as_str().map(str::to_owned))
            .collect::<Vec<_>>();
        service.oauth_dashboard_statuses(principal, &ids).await
    } else {
        HashMap::new()
    };
    for value in data {
        let team = value["teamId"].as_str();
        if let Entry::Vacant(entry) = permissions.entry(team) {
            let (update, delete) = tokio::try_join!(
                allows(accounts, principal, kind, "update", team),
                allows(accounts, principal, kind, "delete", team),
            )?;
            let team_owner = if let Some(team) = team
                && !global_admin
                && (update || delete)
            {
                accounts.database.team_owner(&principal.email, team).await?
            } else {
                false
            };
            entry.insert((update, delete, team_owner));
        }
        let (update, delete, team_owner) = permissions[&team];
        let owned = global_admin
            || value["ownerEmail"].as_str() == Some(&principal.email)
            || (value["visibility"].as_str() == Some("team") && team_owner);
        let field = |name: &str| value[name].as_str().map(str::to_owned);
        let id = field("id").unwrap_or_default();
        let enabled = value["enabled"].as_bool().unwrap_or(false);
        rows.push(Row {
            oauth: oauth.get(&id).copied(),
            id,
            name: field("name").unwrap_or_default(),
            description: field("description").filter(|text| !text.is_empty()),
            enabled,
            visibility: field("visibility"),
            update: update && owned,
            delete: delete && owned,
            refresh: matches!(kind, ManagedCatalog::Gateways)
                && enabled
                && value["status"] == "active"
                && update
                && owned,
        });
    }
    Ok(rows)
}

pub(super) async fn dashboard(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    uri: &Uri,
    team: Option<&str>,
) -> Result<Dashboard, CatalogApiError> {
    let mut query = read_query(uri)?;
    let include_inactive = query.include_inactive()?;
    let mut permitted = Vec::new();
    for kind in ManagedCatalog::ALL {
        if allows(accounts, principal, kind, "read", team).await? {
            permitted.push(kind);
        }
    }
    let tokens_visible = super::token::visible(accounts, principal, team).await?;
    let users_visible = super::users::visible(accounts, principal).await?;
    let teams_visible = super::team::visible(accounts, principal).await?;
    let parameters = forms::query(uri);
    let selected = parameters
        .get("section")
        .map(String::as_str)
        .filter(|name| {
            (*name == "tokens" && tokens_visible)
                || (*name == "users" && users_visible)
                || (*name == "teams" && teams_visible)
                || permitted.iter().any(|kind| kind.name() == *name)
        });
    if selected.is_none() {
        query.page = None;
    }
    let base = format!("{}/admin/", settings_for(accounts).root);
    let href = |name, page| catalogue_link(&base, name, page, include_inactive, team);
    let mut navigation = Vec::with_capacity(permitted.len() + 4);
    if !permitted.is_empty() || tokens_visible || users_visible || teams_visible {
        navigation.push(Link {
            label: "All sections",
            href: href(None, None),
            selected: selected.is_none(),
        });
    }
    for kind in &permitted {
        navigation.push(Link {
            label: label(*kind),
            href: href(Some(kind.name()), None),
            selected: selected == Some(kind.name()),
        });
    }
    if tokens_visible {
        navigation.push(Link {
            label: "API Tokens",
            href: href(Some("tokens"), None),
            selected: selected == Some("tokens"),
        });
    }
    if users_visible {
        navigation.push(Link {
            label: "Users",
            href: href(Some("users"), None),
            selected: selected == Some("users"),
        });
    }
    if teams_visible {
        navigation.push(Link {
            label: "Teams",
            href: href(Some("teams"), None),
            selected: selected == Some("teams"),
        });
    }
    let tokens = if selected == Some("tokens") {
        Some(super::token::panel(accounts, service, principal, uri).await?)
    } else {
        None
    };
    let users = if selected == Some("users") {
        Some(super::users::panel(accounts, service, principal, uri).await?)
    } else {
        None
    };
    let teams = if selected == Some("teams") || selected.is_none() && teams_visible {
        let team_query = (selected == Some("teams")).then_some(uri);
        Some(super::team::panel(accounts, service, principal, team_query, include_inactive).await?)
    } else {
        None
    };
    let sections = futures_util::future::try_join_all(
        permitted
            .into_iter()
            .filter(|kind| selected.is_none_or(|name| name == kind.name()))
            .map(|kind| {
                let query = &query;
                async move {
                    let CatalogListing {
                        data, pagination, ..
                    } = service.admin_catalog(kind, principal, query, team).await?;
                    let page_link =
                        |page| href(Some(kind.name()), Some((page, pagination.per_page)));
                    let rows = rows(accounts, service, principal, kind, &data).await?;
                    let create = allows(accounts, principal, kind, "create", team).await?;

                    Ok::<_, CatalogApiError>(Section {
                        name: kind.name(),
                        fragment: fragment(kind),
                        label: label(kind),
                        actions: rows
                            .iter()
                            .any(|row| row.update || row.delete || row.oauth.is_some()),
                        rows,
                        create,
                        purge_metrics: !matches!(kind, ManagedCatalog::Gateways),
                        total: pagination.total_items,
                        page: pagination.page,
                        pages: pagination.total_pages,
                        previous: pagination.has_prev.then(|| page_link(pagination.page - 1)),
                        next: pagination.has_next.then(|| page_link(pagination.page + 1)),
                    })
                }
            }),
    )
    .await?;
    Ok(Dashboard {
        navigation,
        sections,
        include_inactive,
        team: team.map(str::to_owned),
        selected: selected.map(str::to_owned),
        tokens,
        users,
        teams,
        error: match parameters.get("error").map(String::as_str) {
            Some("conflict") => Some("This entry changed. Check its current state and try again."),
            Some("delete_failed") => Some("Could not delete the entry."),
            Some("name_conflict") => Some("A tool name conflicts with an existing tool."),
            Some("permission_denied") => Some("You don’t have permission to change this entry."),
            Some("state_change_failed") => Some("Could not change the state of the entry."),
            Some("gateway_refresh_failed") => Some("Could not refresh the MCP server tools."),
            _ => None,
        },
        message: match parameters.get("message").map(String::as_str) {
            Some("gateway_delete_pending") => Some("MCP server deletion is pending."),
            Some("gateway_write_pending") => Some("MCP server initialization is pending."),
            Some("gateway_refreshed") => Some("MCP server tools refreshed."),
            _ => None,
        },
    })
}

fn fragment(kind: ManagedCatalog) -> &'static str {
    match kind {
        ManagedCatalog::Servers => "catalog",
        _ => kind.name(),
    }
}

fn label(kind: ManagedCatalog) -> &'static str {
    match kind {
        ManagedCatalog::Tools => "Tools",
        ManagedCatalog::Servers => "Virtual servers",
        ManagedCatalog::Resources => "Resources",
        ManagedCatalog::Prompts => "Prompts",
        ManagedCatalog::Gateways => "MCP servers",
    }
}

fn catalogue_link(
    base: &str,
    section: Option<&str>,
    page: Option<(i64, i64)>,
    include_inactive: bool,
    team: Option<&str>,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.extend_pairs(section.map(|value| ("section", value)));
    query.extend_pairs(team.map(|value| ("team_id", value)));
    if let Some((page, per_page)) = page {
        query
            .append_pair("page", &page.to_string())
            .append_pair("per_page", &per_page.to_string());
    }
    if include_inactive {
        query.append_pair("include_inactive", "true");
    }
    let query = query.finish();
    if query.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{query}")
    }
}
