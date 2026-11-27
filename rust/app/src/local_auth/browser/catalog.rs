// SPDX-License-Identifier: Apache-2.0

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

#[derive(Clone, Copy)]
pub(super) enum Action {
    State,
    Delete,
}

impl Action {
    pub(super) fn path(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Delete => "delete",
        }
    }

    fn permission(self) -> &'static str {
        match self {
            Self::State => "update",
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
    let settings = settings_for(&accounts);
    let Session { principal, .. } =
        match access(&accounts, request.headers(), request.uri(), peer.ip()).await {
            Ok(session) => session,
            Err(denial) => return Ok(denial.response(settings, request.headers())),
        };
    if password_change_pending(&accounts, &principal).await? {
        return Ok(settings.redirect(CHANGE));
    }
    let (parts, form) = Form::from_catalog_request(request).await?;
    csrf(settings, &parts, &form, false)?;
    if sessions::bearer_token(settings, &parts.headers).is_none()
        && !browser_request(&parts.headers)
    {
        return Ok((
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({"detail":"Cookie authentication not allowed for API requests. Use Authorization header."})),
        ).into_response());
    }
    let team = sessions::request_team(&parts.uri, &principal);
    if !allows(
        &accounts,
        &principal,
        kind,
        action.permission(),
        team.as_deref(),
    )
    .await?
    {
        return Err(AccountError::detail(
            StatusCode::FORBIDDEN,
            "Permission denied",
        ));
    }
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
        };
        let result = service
            .mutate_admin_catalog(kind, &principal, id, mutation)
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
}

async fn rows(
    accounts: &Accounts,
    principal: &Principal,
    kind: ManagedCatalog,
    data: &[Value],
) -> Result<Vec<Row>, sqlx::Error> {
    let mut permissions = HashMap::new();
    let mut rows = Vec::with_capacity(data.len());
    let global_admin = principal.is_global_admin();
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
        rows.push(Row {
            id: field("id").unwrap_or_default(),
            name: field("name").unwrap_or_default(),
            description: field("description").filter(|text| !text.is_empty()),
            enabled: value["enabled"].as_bool().unwrap_or(false),
            visibility: field("visibility"),
            update: update && owned,
            delete: delete && owned,
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
    let parameters = forms::query(uri);
    let selected = parameters
        .get("section")
        .map(String::as_str)
        .filter(|name| permitted.iter().any(|kind| kind.name() == *name));
    if selected.is_none() {
        query.page = None;
    }
    let base = format!("{}/admin/", settings_for(accounts).root);
    let href = |name, page| catalogue_link(&base, name, page, include_inactive, team);
    let mut navigation = Vec::with_capacity(permitted.len() + 1);
    if !permitted.is_empty() {
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
                    let rows = rows(accounts, principal, kind, &data).await?;
                    Ok::<_, CatalogApiError>(Section {
                        name: kind.name(),
                        fragment: fragment(kind),
                        label: label(kind),
                        actions: rows.iter().any(|row| row.update || row.delete),
                        rows,
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
        error: match parameters.get("error").map(String::as_str) {
            Some("conflict") => Some("This entry changed. Check its current state and try again."),
            Some("delete_failed") => Some("Could not delete the entry."),
            Some("name_conflict") => Some("A tool name conflicts with an existing tool."),
            Some("permission_denied") => Some("You don’t have permission to change this entry."),
            Some("state_change_failed") => Some("Could not change the state of the entry."),
            _ => None,
        },
        message: (parameters.get("message").map(String::as_str) == Some("gateway_delete_pending"))
            .then_some("MCP server deletion is pending."),
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
