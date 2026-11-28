// SPDX-License-Identifier: Apache-2.0

use axum::http::Uri;
use serde_json::Map;

use super::{catalog::AuthorizedForm, forms::render_with_proof, sessions::authorized_read, *};
use crate::gateway::{
    CatalogApiError, GrpcBrowserAction, GrpcBrowserPage, GrpcPageQuery, catalog_query_flag,
};

const MANAGE: &str = "admin.grpc";

pub(super) fn routes(router: Router<Arc<Accounts>>, base: &str) -> Router<Arc<Accounts>> {
    let path = format!("{base}/grpc");
    let item = format!("{path}/{{id}}");
    router
        .route(&format!("{path}/new"), get(show).post(save))
        .route(&format!("{item}/edit"), get(show).post(save))
        .route(&format!("{item}/inspect"), get(inspect))
        .route(&format!("{item}/manage"), post(change))
}

pub(super) async fn visible(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    team: Option<&str>,
) -> Result<bool, sqlx::Error> {
    Ok(service.grpc_dashboard_enabled()
        && accounts
            .access
            .allows(
                principal,
                MANAGE,
                team.map_or(RoleContext::AnyTeam, RoleContext::Team),
                false,
            )
            .await?)
}

#[derive(Serialize)]
pub(super) struct Panel {
    page: GrpcBrowserPage,
    previous: Option<String>,
    next: Option<String>,
    filters: String,
}

pub(super) async fn panel(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    uri: &Uri,
) -> Result<Panel, CatalogApiError> {
    let query = read_query(uri)?;
    let page = service.grpc_dashboard_page(principal, &query).await?;
    let pagination = &page.pagination;
    let filters = filter_query(page.team.as_deref(), page.include_inactive);
    let root = &settings_for(accounts).root;
    let link = |page: i64| {
        format!(
            "{root}/admin/?section=grpc{filters}&page={page}&per_page={}",
            pagination.per_page,
        )
    };
    Ok(Panel {
        previous: pagination.has_prev.then(|| link(pagination.page - 1)),
        next: pagination.has_next.then(|| link(pagination.page + 1)),
        page,
        filters: form_suffix(&filters),
    })
}

fn form_suffix(filters: &str) -> String {
    filters
        .strip_prefix('&')
        .map_or_else(String::new, |query| format!("?{query}"))
}

fn read_query(uri: &Uri) -> Result<GrpcPageQuery, CatalogApiError> {
    Query::try_from_uri(uri)
        .map(|Query(query)| query)
        .map_err(|_| {
            CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, "Invalid gRPC query")
        })
}

fn filter_query(team: Option<&str>, include_inactive: bool) -> String {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    if let Some(team) = team.filter(|id| Uuid::parse_str(id).is_ok()) {
        params.append_pair("team_id", team);
    }
    if include_inactive {
        params.append_pair("include_inactive", "true");
    }
    let params = params.finish();
    if params.is_empty() {
        params
    } else {
        format!("&{params}")
    }
}

fn return_link(accounts: &Accounts, uri: &Uri) -> String {
    let query = forms::query(uri);
    let active = query
        .get("include_inactive")
        .is_some_and(|value| value == "true");
    let filters = filter_query(query.get("team_id").map(String::as_str), active);
    format!(
        "{}/admin/?section=grpc{filters}#grpc-services",
        settings_for(accounts).root
    )
}

async fn show(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Option<Path<String>>,
    request: Request,
) -> Response {
    let (principal, parts, proof) = match authorized_read(&accounts, request, peer).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let id = path.map(|Path(id)| id);
        let data = service
            .grpc_dashboard_editor(&principal, id.as_deref())
            .await?;
        let query = read_query(&parts.uri)?;
        let filters = filter_query(
            query.team_id.as_deref(),
            catalog_query_flag(query.include_inactive.as_deref())?,
        );
        let team = data["team_id"]
            .as_str()
            .map(str::to_owned)
            .or(query.team_id);
        render_with_proof(
            &accounts,
            "browser.html",
            context! {
                title => if id.is_some() {"Edit gRPC service"} else {"Register gRPC service"},
                page => "grpc-edit", data, id, proof, team,
                root => &settings_for(&accounts).root,
                filters => form_suffix(&filters),
                back => return_link(&accounts, &parts.uri),
            },
            &proof,
        )
        .map_err(grpc_render_error)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), async {
        response.await.into_response()
    })
    .await
}

async fn inspect(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let (principal, parts, _) = match authorized_read(&accounts, request, peer).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let (service, methods) = service.grpc_dashboard_methods(&principal, &id).await?;
        render(context! {
            title => "gRPC methods", page => "grpc-methods",
            service, methods, back => return_link(&accounts,&parts.uri),
        })
        .map_err(grpc_render_error)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), async {
        response.await.into_response()
    })
    .await
}

fn grpc_render_error(error: AccountError) -> CatalogApiError {
    CatalogApiError::detail(error.0, "Could not render the gRPC page")
}

fn input(form: &Form) -> Result<Map<String, Value>, CatalogApiError> {
    let mut fields = Map::new();
    for name in ["name", "target", "description", "visibility"] {
        if let Some(value) = form.value(name) {
            fields.insert(name.to_owned(), value.into());
        }
    }
    for name in ["tls_enabled", "reflection_enabled"] {
        fields.insert(
            name.to_owned(),
            catalog_query_flag(form.value(name))?.into(),
        );
    }
    for name in ["tls_cert_path", "tls_key_path", "team_id"] {
        if let Some(value) = form.value(name) {
            let path = value.trim();
            fields.insert(name.to_owned(), json!((!path.is_empty()).then_some(path)));
        }
    }
    catalog::editor::json_field(form, &mut fields, "grpc_metadata")?;
    Ok(fields)
}

async fn save(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Option<Path<String>>,
    request: Request,
) -> Response {
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form(&accounts, MANAGE, request, peer.ip(), false).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let id = path.map(|Path(id)| id);
        let result = async {
            let fields = input(&form)?;
            service
                .save_grpc_dashboard_service(
                    &principal,
                    id.as_deref(),
                    fields,
                    &parts.headers,
                    peer,
                )
                .await
        }
        .await;
        action_response(&accounts, &parts.uri, result)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

async fn change(
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
    } = match catalog::authorized_form(&accounts, MANAGE, request, peer.ip(), false).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let action = match form.get("action") {
            "enable" => GrpcBrowserAction::State(true),
            "disable" => GrpcBrowserAction::State(false),
            "reflect" => GrpcBrowserAction::Reflect,
            "delete" => GrpcBrowserAction::Delete,
            _ => return AccountError::bad_request("Unknown gRPC service action").into_response(),
        };
        let result = service
            .mutate_grpc_dashboard_service(&principal, &id, action)
            .await;
        action_response(&accounts, &parts.uri, result)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

fn action_response(
    accounts: &Accounts,
    uri: &Uri,
    result: Result<(), CatalogApiError>,
) -> Response {
    let back = return_link(accounts, uri);
    match result {
        Ok(()) => axum::response::Redirect::to(&back).into_response(),
        Err(error) => {
            let message = error.form_message().to_owned();
            let status = error.into_response().status();
            render(context! {
                page => "grpc-error", title => "gRPC request failed", error => message, back,
            })
            .map(|mut response| {
                *response.status_mut() = status;
                response
            })
            .into_response()
        }
    }
}
