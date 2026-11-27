// SPDX-License-Identifier: Apache-2.0

use axum::http::{Uri, request::Parts};

use super::{catalog::AuthorizedForm, *};
use crate::{
    gateway::{AdminTokenPage, AdminTokenQuery, CatalogApiError},
    tokens::ApiTokenRecord,
};

const READ: &str = "tokens.read";
const CREATE: &str = "tokens.create";
const REVOKE: &str = "tokens.revoke";

pub(super) async fn visible(
    accounts: &Accounts,
    principal: &Principal,
    team: Option<&str>,
) -> Result<bool, sqlx::Error> {
    if principal.token_use != TokenUse::Session {
        return Ok(false);
    }
    allowed(accounts, principal, READ, team).await
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

fn read_query(uri: &Uri) -> Result<AdminTokenQuery, CatalogApiError> {
    Query::try_from_uri(uri)
        .map(|Query(query)| query)
        .map_err(|_| {
            CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, "Invalid token query")
        })
}

#[derive(Serialize)]
pub(super) struct Panel {
    rows: Vec<Row>,
    team: Option<String>,
    search: Option<String>,
    include_inactive: bool,
    create: bool,
    require_expiry: bool,
    page: i64,
    pages: i64,
    total: i64,
    previous: Option<String>,
    next: Option<String>,
}

#[derive(Serialize)]
struct Row {
    token: ApiTokenRecord,
    status: &'static str,
    revoke: bool,
    usage: bool,
    permissions: Vec<String>,
    ips: Vec<String>,
    time_restrictions: Option<String>,
    usage_limits: Option<String>,
}

pub(super) async fn panel(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    uri: &Uri,
) -> Result<Panel, CatalogApiError> {
    let query = read_query(uri)?;
    let team = query.team()?;
    let include_inactive = query.include_inactive()?;
    let AdminTokenPage { tokens, pagination } =
        service.admin_token_page(principal, &query, false).await?;
    let can_create = allowed(accounts, principal, CREATE, team.as_deref()).await?;
    let mut rows = Vec::with_capacity(tokens.len());
    let mut revocation = std::collections::HashMap::new();
    let now = Timestamp::now();
    for token in tokens {
        let owned = token.user_email == principal.email;
        let status = if token.is_revoked {
            "Revoked"
        } else if expired(token.expires_at.as_deref(), now) {
            "Expired"
        } else if token.is_active {
            "Active"
        } else {
            "Inactive"
        };
        let revoke = if owned && token.is_active && !token.is_revoked {
            let team = token.team_id.clone();
            if let std::collections::hash_map::Entry::Vacant(entry) = revocation.entry(team.clone())
            {
                let allowed = allowed(accounts, principal, REVOKE, team.as_deref()).await?;
                entry.insert(allowed);
            }
            revocation[&team]
        } else {
            false
        };
        let permissions = strings(token.resource_scopes.as_deref());
        let ips = strings(token.ip_restrictions.as_deref());
        let time_restrictions = nonempty_rules(token.time_restrictions.as_deref());
        let usage_limits = nonempty_rules(token.usage_limits.as_deref());
        rows.push(Row {
            token,
            status,
            revoke,
            usage: owned,
            permissions,
            ips,
            time_restrictions,
            usage_limits,
        });
    }
    let page_link = |page| {
        links(
            &settings_for(accounts).root,
            team.as_deref(),
            query.q.as_deref(),
            include_inactive,
            Some((page, pagination.per_page)),
        )
    };
    Ok(Panel {
        rows,
        create: can_create,
        require_expiry: accounts.access.requires_token_expiration(),
        include_inactive,
        page: pagination.page,
        pages: pagination.total_pages,
        total: pagination.total_items,
        previous: pagination.has_prev.then(|| page_link(pagination.page - 1)),
        next: pagination.has_next.then(|| page_link(pagination.page + 1)),
        team,
        search: query.q,
    })
}

fn strings(raw: Option<&str>) -> Vec<String> {
    raw.and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_default()
}

fn nonempty_rules(raw: Option<&str>) -> Option<String> {
    let rules: serde_json::Map<String, Value> = serde_json::from_str(raw?).ok()?;
    (!rules.is_empty()).then(|| Value::Object(rules).to_string())
}

fn expired(date: Option<&str>, now: Timestamp) -> bool {
    date.and_then(|date| {
        date.parse::<Timestamp>()
            .ok()
            .or_else(|| format!("{date}Z").parse().ok())
    })
    .is_some_and(|expiry| expiry <= now)
}

fn links(
    root: &str,
    team: Option<&str>,
    search: Option<&str>,
    include_inactive: bool,
    page: Option<(i64, i64)>,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("section", "tokens");
    query.extend_pairs(team.map(|team| ("team_id", team)));
    query.extend_pairs(search.filter(|q| !q.is_empty()).map(|q| ("q", q)));
    if include_inactive {
        query.append_pair("include_inactive", "true");
    }
    if let Some((page, size)) = page {
        query
            .append_pair("page", &page.to_string())
            .append_pair("per_page", &size.to_string());
    }
    format!("{root}/admin/?{}#tokens", query.finish())
}

async fn authorize_read(
    accounts: &Accounts,
    peer: SocketAddr,
    request: Request,
) -> Result<(Principal, Parts, String), Box<Response>> {
    let settings = settings_for(accounts);
    let Session { principal, token } =
        access(accounts, request.headers(), request.uri(), peer.ip())
            .await
            .map_err(|denial| Box::new(denial.response(settings, request.headers())))?;
    if password_change_pending(accounts, &principal)
        .await
        .map_err(|error| Box::new(error.into_response()))?
    {
        return Err(Box::new(settings.redirect(CHANGE)));
    }
    let team = sessions::request_team(request.uri(), &principal);
    if !visible(accounts, &principal, team.as_deref())
        .await
        .map_err(|error| Box::new(AccountError::from(error).into_response()))?
    {
        return Err(Box::new(
            AccountError::detail(StatusCode::FORBIDDEN, "Permission denied").into_response(),
        ));
    }
    let proof = sessions::proof(accounts, request.headers(), &principal, token)
        .map_err(|error| Box::new(error.into_response()))?;
    let (parts, _) = request.into_parts();
    Ok((principal, parts, proof))
}

pub(super) async fn partial(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let (principal, parts, proof) = match authorize_read(&accounts, peer, request).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let settings = settings_for(&accounts);
    let response = async {
        let query = match read_query(&parts.uri) {
            Ok(query) => query,
            Err(error) => return error.into_response(),
        };
        let controls = match query.render.as_deref() {
            Some("controls") => true,
            None | Some("") => false,
            Some(_) => {
                return AccountError::detail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid token render mode",
                )
                .into_response();
            }
        };
        let tokens = match panel(&accounts, &service, &principal, &parts.uri).await {
            Ok(panel) => panel,
            Err(error) => return error.into_response(),
        };
        forms::render_template("tokens.html", context!{
            tokens => tokens, root => settings.root, proof => proof, partial => true, controls => controls,
        }).and_then(|mut response| {
            sessions::set_proof(&mut response, settings, accounts.settings.token_seconds, &proof)?;
            Ok(response)
        }).unwrap_or_else(IntoResponse::into_response)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

pub(super) async fn search(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let (principal, parts, _) = match authorize_read(&accounts, peer, request).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let query = match read_query(&parts.uri) {
            Ok(query) => query,
            Err(error) => return error.into_response(),
        };
        service
            .admin_token_page(&principal, &query, true)
            .await
            .map(|page| Json(page.search_rows()).into_response())
            .unwrap_or_else(IntoResponse::into_response)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

pub(super) async fn create(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form(&accounts, CREATE, request, peer.ip(), false).await {
        Ok(form) => form,
        Err(response) => return *response,
    };
    let response = async {
        let settings = settings_for(&accounts);
        let team = match form_team(&form) {
            Ok(team) => team,
            Err(error) => return error.into_response(),
        };
        let context = team
            .as_deref()
            .map_or(RoleContext::AnyTeam, RoleContext::Team);
        match accounts
            .access
            .allows(&principal, CREATE, context, false)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return AccountError::detail(StatusCode::FORBIDDEN, "Permission denied")
                    .into_response();
            }
            Err(error) => return AccountError::from(error).into_response(),
        }
        let back = links(&settings.root, team.as_deref(), None, false, None);
        let result = match create_fields(&form, team.as_deref()) {
            Ok(fields) => service.issue_admin_token(&principal, fields).await,
            Err(error) => Err(error),
        };
        match result {
            Ok(issued) => {
                let mut reply = render(context! {
                    page => "token-issued",
                    title => "API token created",
                    name => issued.token.name,
                    secret => issued.secret.as_str(),
                    warnings => issued.warnings,
                    back => back,
                })
                .unwrap_or_else(IntoResponse::into_response);
                if reply.status().is_success() {
                    *reply.status_mut() = StatusCode::CREATED;
                }
                reply.headers_mut().insert(
                    header::REFERRER_POLICY,
                    axum::http::HeaderValue::from_static("no-referrer"),
                );
                reply
            }
            Err(error) => {
                let mut reply = render(context! {
                    page => "token-create-error",
                    title => "Token creation failed",
                    error => error.form_message(),
                    back => back,
                })
                .unwrap_or_else(IntoResponse::into_response);
                if reply.status().is_success() {
                    *reply.status_mut() = error.into_response().status();
                }
                reply
            }
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

fn form_team(form: &Form) -> Result<Option<String>, CatalogApiError> {
    AdminTokenQuery {
        team_id: form.value("team_id").map(str::trim).map(str::to_owned),
        ..AdminTokenQuery::default()
    }
    .team()
}

fn create_fields(form: &Form, team: Option<&str>) -> Result<Value, CatalogApiError> {
    let meaningful = |name| {
        form.value(name)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let csv = |name| {
        form.get(name)
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
    };
    let expiry = meaningful("expires_in_days")
        .map(|value| {
            value.parse::<i64>().map_err(|_| {
                CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, "Invalid token expiry")
            })
        })
        .transpose()?;
    Ok(json!({
        "name":form.get("name"),
        "description":meaningful("description"),
        "expires_in_days":expiry,
        "scope":{
            "server_id":meaningful("server_id"),
            "ip_restrictions":csv("ip_restrictions"),
            "permissions":csv("permissions"),
        },
        "team_id":team,
    }))
}

pub(super) async fn revoke(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form(&accounts, REVOKE, request, peer.ip(), false).await {
        Ok(form) => form,
        Err(response) => return *response,
    };
    let response = async {
        match service.revoke_admin_token(&principal, &id).await {
            Ok(status) if parts.method == Method::DELETE => status.into_response(),
            Ok(_) => {
                let team = form_team(&form).ok().flatten();
                let path = links(
                    "",
                    team.as_deref(),
                    form.value("q"),
                    form.get("include_inactive") == "true",
                    None,
                );
                settings_for(&accounts).redirect(&path)
            }
            Err(error) => error.into_response(),
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

pub(super) async fn usage(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let (principal, parts, _) = match authorize_read(&accounts, peer, request).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let query = forms::query(&parts.uri);
        let days = match query.get("days").map(|value| value.parse()).transpose() {
            Ok(days) => days.unwrap_or(30),
            Err(_) => {
                return AccountError::detail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid token usage period",
                )
                .into_response();
            }
        };
        match service.admin_token_usage(&principal, &id, days).await {
            Ok((name, usage)) => render(context! {
                page => "token-usage",
                title => "API token usage",
                name => name,
                usage => usage,
                back => links(&settings_for(&accounts).root, None, None, false, None),
            })
            .unwrap_or_else(IntoResponse::into_response),
            Err(error) => error.into_response(),
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}
