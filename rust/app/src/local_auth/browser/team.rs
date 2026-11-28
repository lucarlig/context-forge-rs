// SPDX-License-Identifier: Apache-2.0

mod members;
mod requests;

use axum::http::{Uri, request::Parts};
use axum::routing::delete;

use super::{
    catalog::AuthorizedForm, forms::render_with_proof as render_form,
    sessions::authorized_read as authorize, *,
};
use crate::gateway::{CatalogApiError, PaginationMeta};
use crate::local_auth::teams::dashboard::{self, DirectoryQuery, View};

pub(super) fn routes(router: Router<Arc<Accounts>>, base: &str) -> Router<Arc<Accounts>> {
    let prefix = format!("{base}/teams");
    let item = format!("{prefix}/{{id}}");
    let mut router = router
        .route(
            &prefix,
            get(directory).layer(Extension(View::List)).post(create),
        )
        .route(
            &format!("{prefix}/partial"),
            get(directory).layer(Extension(View::Explore)),
        )
        .route(
            &format!("{prefix}/search"),
            get(directory).layer(Extension(View::Search)),
        )
        .route(
            &format!("{prefix}/ids"),
            get(directory).layer(Extension(View::Ids)),
        )
        .route(&format!("{item}/edit"), get(edit))
        .route(
            &format!("{item}/update"),
            post(mutate).layer(Extension(Action::Update)),
        )
        .route(
            &format!("{item}/delete"),
            post(mutate).layer(Extension(Action::Delete)),
        )
        .route(&item, delete(mutate).layer(Extension(Action::Delete)));
    router = members::routes(router, &item);
    requests::routes(router, &item)
}

pub(super) async fn visible(
    accounts: &Accounts,
    principal: &Principal,
) -> Result<bool, sqlx::Error> {
    dashboard::allowed(accounts, principal, dashboard::READ, None).await
}

pub(super) async fn panel(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    uri: Option<&Uri>,
    include_inactive: bool,
) -> Result<Panel, CatalogApiError> {
    let mut query: DirectoryQuery = uri.map(parse_query).transpose()?.unwrap_or_default();
    query.include_inactive = include_inactive;
    let view = if query.relationship.as_deref() == Some("public") {
        View::Discover
    } else {
        View::Explore
    };
    team_panel(accounts, service, principal, &query, view, true).await
}

fn parse_query<T: serde::de::DeserializeOwned>(uri: &Uri) -> Result<T, CatalogApiError> {
    Query::try_from_uri(uri)
        .map(|Query(query)| query)
        .map_err(|_| {
            CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, "Invalid team query")
        })
}

fn as_catalog_error(error: AccountError) -> CatalogApiError {
    CatalogApiError::detail(
        error.0,
        error.1["detail"].as_str().unwrap_or("Team request failed"),
    )
}

#[derive(Serialize)]
pub(super) struct Panel {
    rows: Vec<dashboard::Row>,
    pagination: PaginationMeta,
    previous: Option<String>,
    next: Option<String>,
    can_create: bool,
    search: Option<String>,
    visibility: Option<String>,
    relationship: Option<String>,
}

async fn team_panel(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    query: &DirectoryQuery,
    view: View,
    home: bool,
) -> Result<Panel, CatalogApiError> {
    query.validate().map_err(as_catalog_error)?;
    let (page, size) = service.admin_page_params(query.page, query.per_page)?;
    let all = dashboard::directory(accounts, principal, query, view)
        .await
        .map_err(as_catalog_error)?;
    let pagination = PaginationMeta::new(page, size, all.len() as i64);
    let mut rows = Vec::new();
    for team in all
        .into_iter()
        .skip(service.admin_page_offset(&pagination) as usize)
        .take(size as usize)
    {
        rows.push(dashboard::row(accounts, principal, team).await?);
    }
    let settings = settings_for(accounts);
    let page_link = |page: i64| {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        let path = if home {
            params.append_pair("section", "teams");
            "/admin/"
        } else {
            "/admin/teams/partial"
        };
        for (name, value) in [
            ("q", query.q.as_deref()),
            ("visibility", query.visibility.as_deref()),
            ("relationship", query.relationship.as_deref()),
            ("render", query.render.as_deref()),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                params.append_pair(name, value);
            }
        }
        if query.include_inactive {
            params.append_pair("include_inactive", "true");
        }
        params
            .append_pair("page", &page.to_string())
            .append_pair("per_page", &size.to_string());
        format!("{}{path}?{}", settings.root, params.finish())
    };
    Ok(Panel {
        rows,
        previous: pagination.has_prev.then(|| page_link(pagination.page - 1)),
        next: pagination.has_next.then(|| page_link(pagination.page + 1)),
        pagination,
        can_create: dashboard::can_create(accounts, principal).await?,
        search: query.q.clone(),
        visibility: query.visibility.clone(),
        relationship: query.relationship.clone(),
    })
}

async fn directory(
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
        if !visible(&accounts, &principal).await? {
            return Err(CatalogApiError::detail(
                StatusCode::FORBIDDEN,
                "Permission denied",
            ));
        }
        let query: DirectoryQuery = parse_query(&parts.uri)?;
        query.validate().map_err(as_catalog_error)?;
        if matches!(view, View::Search | View::Ids) {
            return filtered_json(&accounts, &principal, &query, view)
                .await
                .map(IntoResponse::into_response);
        }
        let mode = query.render.as_deref().unwrap_or_default();
        if !matches!(mode, "" | "controls" | "selector") {
            return Err(CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid team render mode",
            ));
        }
        let view = if view == View::List && query.unified {
            View::Unified
        } else {
            view
        };
        let teams = team_panel(&accounts, &service, &principal, &query, view, false).await?;
        render_form(
            &accounts,
            "teams.html",
            context! {
                teams, proof, mode, root => &settings_for(&accounts).root,
            },
            &proof,
        )
        .map_err(as_catalog_error)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), async {
        response.await.into_response()
    })
    .await
}

async fn filtered_json(
    accounts: &Accounts,
    principal: &Principal,
    query: &DirectoryQuery,
    view: View,
) -> Result<Json<Value>, CatalogApiError> {
    let limit = query
        .limit
        .unwrap_or(i64::from(accounts.settings.page_size));
    if view == View::Search && !(1..=i64::from(accounts.settings.max_page_size)).contains(&limit) {
        return Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid team search limit",
        ));
    }
    let teams = dashboard::directory(accounts, principal, query, view)
        .await
        .map_err(as_catalog_error)?;
    if view == View::Search {
        Ok(Json(json!(
            teams.into_iter().take(limit as usize).collect::<Vec<_>>()
        )))
    } else {
        let ids: Vec<_> = teams
            .iter()
            .filter_map(|team| team["id"].as_str())
            .collect();
        Ok(Json(json!({"team_ids":ids,"count":ids.len()})))
    }
}

fn team_id(raw: &str) -> Result<String, AccountError> {
    Uuid::parse_str(raw)
        .map(|id| id.simple().to_string())
        .map_err(|_| AccountError::bad_request("Invalid team ID"))
}

async fn edit(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let (principal, parts, proof) = match authorize(&accounts, request, peer).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let team = dashboard::editable(&accounts, &principal, &team_id(&id)?).await?;
        render_form(
            &accounts,
            "browser.html",
            context! {
                page => "team-edit", title => "Edit team", root => &settings_for(&accounts).root,
                team, proof, from_directory => forms::query(&parts.uri).contains_key("directory"),
            },
            &proof,
        )
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), async {
        response.await.into_response()
    })
    .await
}

struct TeamFields {
    name: String,
    description: Option<String>,
    visibility: Option<String>,
    capacity: Option<i32>,
}

impl TeamFields {
    fn parse(form: &Form) -> Result<Self, AccountError> {
        let capacity = match form.get("max_members").trim() {
            "" => None,
            value => Some(
                value
                    .parse::<i32>()
                    .map_err(|_| AccountError::bad_request("Invalid member limit"))?,
            ),
        };
        Ok(Self {
            name: form.get("name").to_owned(),
            description: form.value("description").map(str::to_owned),
            visibility: form.value("visibility").map(str::to_owned),
            capacity,
        })
    }
}

async fn create(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form(&accounts, dashboard::CREATE, request, peer.ip(), false)
        .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let result = async {
            let fields = TeamFields::parse(&form)?;
            dashboard::create(
                &accounts,
                &principal,
                fields.name,
                fields.description,
                fields.visibility,
                fields.capacity,
            )
            .await
        }
        .await;
        match result {
            Ok(()) if forms::query(&parts.uri).contains_key("directory") => {
                teams_redirect(&accounts)
            }
            Ok(()) => (StatusCode::CREATED, Html("")).into_response(),
            Err(error) => error_page(&accounts, error),
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

#[derive(Clone, Copy)]
enum Action {
    Update,
    Delete,
}

async fn mutate(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Extension(action): Extension<Action>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let id = match team_id(&id) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let permission = match action {
        Action::Update => dashboard::UPDATE,
        Action::Delete => dashboard::DELETE,
    };
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form_for_team(
        &accounts,
        permission,
        request,
        peer.ip(),
        false,
        Some(&id),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let result = match action {
            Action::Update => update_team(&accounts, &principal, &id, &form).await,
            Action::Delete => dashboard::delete(&accounts, &principal, &id).await,
        };
        if let Err(error) = result {
            return error_page(&accounts, error);
        }
        if forms::query(&parts.uri).contains_key("directory") {
            return teams_redirect(&accounts);
        }
        match action {
            Action::Update if !htmx(&parts) => settings_for(&accounts).redirect("/admin/#teams"),
            Action::Update => (
                [("HX-Trigger", r#"{"adminTeamAction":{"closeTeamEditModal":true,"refreshUnifiedTeamsList":true,"delayMs":1500}}"#)],
                Html("<p>Team updated successfully</p>"),
            ).into_response(),
            Action::Delete => (
                [("HX-Trigger", r#"{"adminTeamAction":{"refreshUnifiedTeamsList":true,"delayMs":1000}}"#)],
                Html("<p>Team deleted successfully</p>"),
            ).into_response(),
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

async fn update_team(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    form: &Form,
) -> Result<(), AccountError> {
    let fields = TeamFields::parse(form)?;
    let capacity = if form
        .value("use_default_max_members")
        .is_some_and(|value| !value.is_empty())
    {
        Some(None)
    } else {
        fields.capacity.map(Some)
    };
    dashboard::update(
        accounts,
        principal,
        id,
        fields.name,
        fields.description,
        fields.visibility,
        capacity,
    )
    .await
}

fn teams_redirect(accounts: &Accounts) -> Response {
    settings_for(accounts).redirect("/admin/?section=teams#teams")
}

fn htmx(parts: &Parts) -> bool {
    parts
        .headers
        .get("HX-Request")
        .is_some_and(|value| value == "true")
}

fn error_page(accounts: &Accounts, error: AccountError) -> Response {
    let detail = error.1["detail"].as_str().unwrap_or("Team request failed");
    let content = render(context! {
        page => "team-error", title => "Team request failed", error => detail,
        root => &settings_for(accounts).root,
    });
    match content {
        Ok(mut response) => {
            *response.status_mut() = match error.0 {
                StatusCode::UNPROCESSABLE_ENTITY => StatusCode::BAD_REQUEST,
                status => status,
            };
            response
        }
        Err(error) => error.into_response(),
    }
}
