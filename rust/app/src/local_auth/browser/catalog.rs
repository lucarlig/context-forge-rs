// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, net::IpAddr};

use axum::http::{Uri, request::Parts};

use super::*;
use crate::{
    gateway::{AdminListQuery, CatalogApiError, CatalogListing},
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
    if !can_read(&accounts, &principal, kind, team.as_deref()).await? {
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

async fn can_read(
    accounts: &Accounts,
    principal: &Principal,
    kind: ManagedCatalog,
    team: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let permission = match kind {
        ManagedCatalog::Tools => "tools.read",
        ManagedCatalog::Servers => "servers.read",
        ManagedCatalog::Resources => "resources.read",
        ManagedCatalog::Prompts => "prompts.read",
        ManagedCatalog::Gateways => "gateways.read",
    };
    let role = team.map_or(RoleContext::AnyTeam, RoleContext::Team);
    accounts
        .access
        .allows(principal, permission, role, false)
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
    label: &'static str,
    rows: Vec<Row>,
    total: i64,
    page: i64,
    pages: i64,
    previous: Option<String>,
    next: Option<String>,
}

#[derive(Serialize)]
struct Row {
    name: String,
    description: Option<String>,
    enabled: bool,
    visibility: Option<String>,
}

impl From<Value> for Row {
    fn from(value: Value) -> Self {
        let field = |name: &str| value[name].as_str().map(str::to_owned);
        Self {
            name: field("name").unwrap_or_default(),
            description: field("description").filter(|text| !text.is_empty()),
            enabled: value["enabled"].as_bool().unwrap_or(false),
            visibility: field("visibility"),
        }
    }
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
        if can_read(accounts, principal, kind, team).await? {
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
                    Ok::<_, CatalogApiError>(Section {
                        name: kind.name(),
                        label: label(kind),
                        rows: data.into_iter().map(Row::from).collect(),
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
    })
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
