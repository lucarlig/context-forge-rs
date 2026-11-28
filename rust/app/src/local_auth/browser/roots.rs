// SPDX-License-Identifier: Apache-2.0

use axum::http::{HeaderValue, Uri};
use percent_encoding::NON_ALPHANUMERIC;

use super::{catalog::AuthorizedForm, forms::render_with_proof, sessions::authorized_read, *};
use crate::gateway::{CatalogApiError, ROOTS_ADMIN_PERMISSION, Root, RootError};

#[derive(Clone, Copy)]
enum View {
    Search,
    Export,
    Item,
}

pub(super) fn routes(router: Router<Arc<Accounts>>, base: &str) -> Router<Arc<Accounts>> {
    let path = format!("{base}/roots");
    router
        .route(&path, post(mutate))
        .route(
            &format!("{path}/search"),
            get(read).layer(Extension(View::Search)),
        )
        .route(
            &format!("{path}/export"),
            get(read).layer(Extension(View::Export)),
        )
        .route(
            &format!("{path}/{{*uri}}"),
            get(read).layer(Extension(View::Item)).post(mutate),
        )
}

#[derive(Serialize)]
pub(super) struct Panel {
    rows: Vec<Row>,
    query: String,
    error: Option<&'static str>,
}

#[derive(Serialize)]
struct Row {
    root: Root,
    encoded_uri: String,
}

impl From<Root> for Row {
    fn from(root: Root) -> Self {
        let encoded_uri = utf8_percent_encode(&root.uri, NON_ALPHANUMERIC).to_string();
        Self { root, encoded_uri }
    }
}

pub(super) async fn panel(
    service: &GatewayService,
    principal: &Principal,
    query: Option<&str>,
    error: Option<&str>,
) -> Result<Panel, CatalogApiError> {
    let registry = service.admin_roots(principal).await.map_err(panel_error)?;
    let query = query.unwrap_or_default();
    let matched = normalize_query(query).map_err(panel_error)?;
    let rows = registry
        .search(principal, &matched, usize::MAX)
        .into_iter()
        .map(Row::from)
        .collect();
    let error = match error {
        Some("invalid_input") => Some("Enter a root URI."),
        Some("invalid_uri") => {
            Some("The root already exists or the URI or name failed validation.")
        }
        _ => None,
    };
    Ok(Panel {
        rows,
        query: query.to_owned(),
        error,
    })
}

fn panel_error(error: RootError) -> CatalogApiError {
    let status = error.into_response().status();
    CatalogApiError::detail(status, "Could not list roots")
}

async fn read(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Extension(view): Extension<View>,
    path: Option<Path<String>>,
    request: Request,
) -> Response {
    let (principal, parts, proof) = match authorized_read(&accounts, request, peer).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let registry = service.admin_roots(&principal).await?;
        let response = match view {
            View::Search => {
                let Search { q, limit } = query(&parts.uri)?;
                let q = normalize_query(&q)?;
                let limit = service.root_search_limit(limit)?;
                let roots = registry
                    .search(&principal, &q, limit)
                    .into_iter()
                    .map(|root| {
                        let name = if root.name.is_empty() {
                            &root.uri
                        } else {
                            &root.name
                        };
                        json!({"id":root.uri,"uri":root.uri,"name":name})
                    })
                    .collect::<Vec<_>>();
                Json(
                    json!({"roots":roots,"items":roots,"count":roots.len(),"entity_type":"roots",
                    "query":q,"filters_applied":{"q":q,"tags":"","tag_groups":[]}}),
                )
                .into_response()
            }
            View::Export => {
                let Export { uri } = query(&parts.uri)?;
                let root = registry.find(&uri)?;
                download(&root, &uri, &principal.email)
            }
            View::Item => {
                let Path(uri) = path.ok_or(RootError::Policy("empty_uri"))?;
                let root = registry.find(&uri)?;
                if forms::query(&parts.uri)
                    .get("view")
                    .is_some_and(|view| view == "html")
                {
                    render_with_proof(
                        &accounts,
                        "browser.html",
                        context! {
                            page => "root-detail", title => "Root details",
                            entry => Row::from(root), root => &settings_for(&accounts).root, proof,
                        },
                        &proof,
                    )
                    .map_err(|error| {
                        RootError::Detail(error.0, "Could not render the root".into())
                    })?
                } else {
                    Json(root).into_response()
                }
            }
        };
        Ok::<Response, RootError>(response)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), async {
        response.await.into_response()
    })
    .await
}

#[derive(Deserialize)]
struct Search {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct Export {
    uri: String,
}

fn query<T: serde::de::DeserializeOwned>(uri: &Uri) -> Result<T, RootError> {
    Query::try_from_uri(uri)
        .map(|Query(query)| query)
        .map_err(|_| {
            RootError::Detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid root query".into(),
            )
        })
}

fn normalize_query(query: &str) -> Result<String, RootError> {
    if query.chars().count() > 500 {
        return Err(RootError::Detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Root search query is too long".into(),
        ));
    }
    Ok(query.trim().to_lowercase())
}

fn download(root: &Root, uri: &str, email: &str) -> Response {
    let now = jiff::Timestamp::now();
    let stamp = now.strftime("%Y%m%d-%H%M%S");
    let safe: String = uri
        .replace("://", "_")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '%' | ':')
            {
                character
            } else {
                '_'
            }
        })
        .collect();
    let disposition = HeaderValue::from_str(&format!(
        "attachment; filename=\"root-export-{safe}-{stamp}.json\""
    ))
    .expect("root export filename contains only safe ASCII");
    (
        [(header::CONTENT_DISPOSITION, disposition)],
        Json(root.export_payload(email, now)),
    )
        .into_response()
}

async fn mutate(
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
    } = match catalog::authorized_form(&accounts, ROOTS_ADMIN_PERMISSION, request, peer.ip(), false)
        .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let registry = match service.admin_roots(&principal).await {
            Ok(registry) => registry,
            Err(error) => return error.into_response(),
        };
        let (result, update, inactive) = if let Some(Path(path)) = path {
            let inactive = form.get("is_inactive_checked").eq_ignore_ascii_case("true");
            match path.rsplit_once('/') {
                Some((uri, "update")) => (
                    registry
                        .rename(uri, form.value("name").map(str::to_owned))
                        .map(|_| ()),
                    true,
                    inactive,
                ),
                Some((uri, "delete")) => (registry.remove(uri), false, inactive),
                _ => return StatusCode::NOT_FOUND.into_response(),
            }
        } else {
            let uri = form.get("uri");
            if uri.is_empty() {
                return redirect(&accounts, Some("invalid_input"), false, form.get("team_id"));
            }
            let name = form
                .value("name")
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
            (registry.add(uri, name).map(|_| ()), false, false)
        };
        match result {
            Ok(()) => redirect(&accounts, None, inactive, form.get("team_id")),
            Err(RootError::Policy(_)) if update => {
                redirect(&accounts, Some("invalid_uri"), false, "")
            }
            Err(RootError::Policy(_) | RootError::Detail(StatusCode::CONFLICT, _)) => redirect(
                &accounts,
                Some("invalid_uri"),
                inactive,
                form.get("team_id"),
            ),
            Err(error) => error.into_response(),
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

fn redirect(accounts: &Accounts, error: Option<&str>, inactive: bool, team: &str) -> Response {
    let mut parameters = url::form_urlencoded::Serializer::new(String::new());
    if let Some(error) = error {
        parameters.append_pair("error", error);
    }
    if inactive {
        parameters.append_pair("include_inactive", "true");
    }
    if let Ok(team) = Uuid::parse_str(team) {
        parameters.append_pair("team_id", &team.simple().to_string());
    }
    let parameters = parameters.finish();
    let suffix = if parameters.is_empty() {
        String::new()
    } else {
        format!("/?{parameters}")
    };
    settings_for(accounts).redirect(&format!("/admin{suffix}#roots"))
}
