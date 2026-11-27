// SPDX-License-Identifier: Apache-2.0

use std::{convert::Infallible, path::Path as FilePath};

use axum::{
    extract::{Path, Query},
    response::{Sse, sse::Event},
};
use futures_util::stream;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use url::{ParseError, Url};

use super::*;
use super::{
    catalog_api::CatalogApiError,
    import_api::{Outcome, Strategy},
};

const PATH_ENCODING: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Default)]
pub struct RootSettings {
    pub network_schemes: HashSet<String>,
    pub file_enabled: bool,
    pub file_prefixes: HashSet<String>,
    pub defaults: Vec<String>,
}

pub(super) struct RootRegistry {
    settings: RootSettings,
    roots: Mutex<Vec<Root>>,
    events: broadcast::Sender<Value>,
    shutdown: CancellationToken,
}

impl Default for RootRegistry {
    fn default() -> Self {
        Self::new(RootSettings::default(), CancellationToken::new())
            .expect("default root settings are valid")
    }
}

#[derive(Clone, Serialize)]
struct Root {
    uri: String,
    name: String,
    #[serde(rename = "_meta")]
    meta: Option<()>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid root configuration: {0}")]
pub struct RootSetupError(&'static str);

impl RootRegistry {
    pub(super) fn new(
        mut settings: RootSettings,
        shutdown: CancellationToken,
    ) -> Result<Self, RootSetupError> {
        settings.network_schemes = settings
            .network_schemes
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        if settings
            .network_schemes
            .iter()
            .any(|value| !matches!(value.as_str(), "http" | "https" | "ws" | "wss"))
        {
            return Err(RootSetupError("invalid ROOT_ALLOWED_SCHEMES"));
        }
        if settings.file_enabled && settings.file_prefixes.is_empty() {
            return Err(RootSetupError(
                "ROOT_ALLOW_FILE_SCHEME requires ROOT_ALLOWED_FILE_PREFIXES",
            ));
        }
        if settings.file_prefixes.iter().any(|prefix| {
            !prefix.starts_with('/')
                || prefix.starts_with("//")
                || has_control(prefix)
                || prefix.contains(['?', '#', '\\'])
                || prefix.split('/').any(|part| part == "..")
        }) {
            return Err(RootSetupError("invalid ROOT_ALLOWED_FILE_PREFIXES"));
        }
        let defaults = std::mem::take(&mut settings.defaults);
        let mut roots = Vec::new();
        for uri in defaults {
            let uri = canonical_uri(&settings, &uri).map_err(RootSetupError)?;
            if roots.iter().any(|entry: &Root| entry.uri == uri) {
                return Err(RootSetupError("duplicate default root"));
            }
            roots.push(root_from_uri(uri, None));
        }
        Ok(Self {
            settings,
            roots: Mutex::new(roots),
            events: broadcast::channel(128).0,
            shutdown,
        })
    }

    fn items(&self) -> std::sync::MutexGuard<'_, Vec<Root>> {
        self.roots.lock().expect("root catalog")
    }

    pub(super) fn export_configuration(&self, selected: Option<&[String]>) -> Vec<Value> {
        self.items()
            .iter()
            .filter(|root| selected.is_none_or(|uris| uris.contains(&root.uri)))
            .map(|root| json!({"uri":root.uri,"name":root.name}))
            .collect()
    }

    fn canonical(&self, uri: &str) -> Result<String, RootError> {
        canonical_uri(&self.settings, uri).map_err(RootError::Policy)
    }

    pub(super) fn valid_import_root(&self, uri: &str, name: &str) -> bool {
        self.canonical(uri).is_ok() && validate_name(Some(name)).is_ok()
    }

    pub(super) fn import_root(
        &self,
        uri: &str,
        name: Option<&str>,
        strategy: Strategy,
    ) -> Result<Outcome, CatalogApiError> {
        let uri = self
            .canonical(uri)
            .map_err(|_| CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid root URI"))?;
        let mut roots = self.items();
        if roots.iter().any(|root| root.uri == uri) {
            if strategy == Strategy::Skip {
                return Ok(Outcome::Skipped);
            }
            return Err(CatalogApiError::detail(
                StatusCode::CONFLICT,
                "Root already exists",
            ));
        }
        self.insert(&mut roots, root_from_uri(uri, name.map(str::to_owned)));
        Ok(Outcome::Created)
    }

    fn insert(&self, roots: &mut Vec<Root>, root: Root) -> Root {
        roots.push(root.clone());
        let _ = self.events.send(json!({
            "type":"root_added","data":{"uri":root.uri,"name":root.name}
        }));
        root
    }

    fn find(&self, uri: &str) -> Result<Root, RootError> {
        let canonical = self.canonical(uri)?;
        self.items()
            .iter()
            .find(|root| root.uri == canonical)
            .cloned()
            .ok_or_else(|| not_found(uri))
    }
}

pub(super) fn router() -> Router<Arc<GatewayService>> {
    let mut routes = Router::new();
    for base in ["/roots", "/v1/roots"] {
        routes = routes
            .route(base, get(list).post(add))
            .route(&format!("{base}/"), get(list).post(add))
            .route(&format!("{base}/export"), get(export))
            .route(&format!("{base}/changes"), get(changes))
            .route(
                &format!("{base}/{{*uri}}"),
                get(detail).put(update).delete(remove),
            );
    }
    routes
}

async fn require_admin(service: &GatewayService, principal: &Principal) -> Result<(), RootError> {
    if !principal.is_global_admin()
        || !service
            .access
            .allows(principal, "admin.system_config", RoleContext::Global, true)
            .await?
    {
        return Err(RootError::Detail(
            StatusCode::FORBIDDEN,
            "Access denied".into(),
        ));
    }
    Ok(())
}

async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Vec<Root>>, RootError> {
    require_admin(&service, &principal).await?;
    Ok(Json(service.roots.items().clone()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootCreate {
    uri: String,
    name: Option<String>,
}

async fn add(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Json(input): Json<RootCreate>,
) -> Result<Json<Root>, RootError> {
    require_admin(&service, &principal).await?;
    let uri = service.roots.canonical(&input.uri)?;
    validate_name(input.name.as_deref())?;
    let mut roots = service.roots.items();
    if roots.iter().any(|root| root.uri == uri) {
        return Err(RootError::Detail(
            StatusCode::CONFLICT,
            "Root already exists".into(),
        ));
    }
    Ok(Json(
        service
            .roots
            .insert(&mut roots, root_from_uri(uri, input.name)),
    ))
}

async fn detail(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(uri): Path<String>,
) -> Result<Json<Root>, RootError> {
    require_admin(&service, &principal).await?;
    Ok(Json(service.roots.find(&uri)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootUpdate {
    name: Option<String>,
}

async fn update(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(uri): Path<String>,
    Json(input): Json<RootUpdate>,
) -> Result<Json<Root>, RootError> {
    require_admin(&service, &principal).await?;
    let canonical = service.roots.canonical(&uri)?;
    let mut roots = service.roots.items();
    let root = roots
        .iter_mut()
        .find(|root| root.uri == canonical)
        .ok_or_else(|| not_found(&uri))?;
    if let Some(name) = input.name {
        validate_name(Some(&name))?;
        root.name = name;
    }
    let _ = service.roots.events.send(json!({
        "type":"root_updated","data":{"uri":root.uri,"name":root.name}
    }));
    Ok(Json(root.clone()))
}

async fn remove(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(uri): Path<String>,
) -> Result<Json<Value>, RootError> {
    require_admin(&service, &principal).await?;
    let canonical = service.roots.canonical(&uri)?;
    let mut roots = service.roots.items();
    let index = roots
        .iter()
        .position(|root| root.uri == canonical)
        .ok_or_else(|| RootError::Detail(StatusCode::NOT_FOUND, "Root not found".into()))?;
    roots.remove(index);
    let _ = service
        .roots
        .events
        .send(json!({"type":"root_removed","data":{"uri":canonical}}));
    Ok(Json(json!({"status":"success","message":"Root removed"})))
}

#[derive(Deserialize)]
struct RootQuery {
    uri: String,
}

async fn export(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<RootQuery>,
) -> Result<Json<Value>, RootError> {
    require_admin(&service, &principal).await?;
    let root = service.roots.find(&query.uri)?;
    Ok(Json(json!({
        "exported_at": Timestamp::now().to_string().trim_end_matches('Z'),
        "exported_by": principal.email,
        "export_type":"root","version":"1.0","root":{"uri":root.uri,"name":root.name}
    })))
}

async fn changes(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
) -> Result<Response, RootError> {
    require_admin(&service, &principal).await?;
    let subscription = (
        service.roots.events.subscribe(),
        service.roots.shutdown.clone(),
    );
    let events = stream::unfold(subscription, |(mut receiver, shutdown)| async move {
        let event = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return None,
            event = receiver.recv() => event.ok()?,
        };
        Some((
            Ok::<_, Infallible>(Event::default().data(event.to_string())),
            (receiver, shutdown),
        ))
    });
    Ok(Sse::new(events).into_response())
}

fn root_from_uri(uri: String, name: Option<String>) -> Root {
    let name = name.filter(|name| !name.is_empty()).unwrap_or_else(|| {
        let path = uri
            .split_once("://")
            .and_then(|(_, remainder)| remainder.split_once('/'))
            .map_or("", |(_, path)| path);
        let basename = path.rsplit('/').next().unwrap_or_default();
        if basename.is_empty() {
            uri.clone()
        } else {
            basename.to_owned()
        }
    });
    Root {
        uri,
        name,
        meta: None,
    }
}

fn validate_name(name: Option<&str>) -> Result<(), RootError> {
    if let Some(name) = name {
        if name.chars().count() > 255 {
            return Err(RootError::Policy("name_too_long"));
        }
        if has_control(name) {
            return Err(RootError::Policy("control_character"));
        }
    }
    Ok(())
}

fn canonical_uri(settings: &RootSettings, uri: &str) -> Result<String, &'static str> {
    if uri.is_empty() {
        return Err("empty_uri");
    }
    if uri.chars().count() > 2048 {
        return Err("uri_too_long");
    }
    if uri.trim() != uri || has_control(uri) {
        return Err("control_character");
    }
    if uri.bytes().enumerate().any(|(index, byte)| {
        byte == b'%'
            && !uri
                .as_bytes()
                .get(index + 1..index + 3)
                .is_some_and(|bytes| bytes.iter().all(u8::is_ascii_hexdigit))
    }) {
        return Err("invalid_percent_encoding");
    }
    let (scheme, rest) = uri.split_once(':').ok_or("scheme_missing")?;
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return Err("scheme_missing");
    }
    let scheme = scheme.to_ascii_lowercase();
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    if !query.is_empty() {
        return Err("query_not_allowed");
    }
    if !fragment.is_empty() {
        return Err("fragment_not_allowed");
    }
    let authority = path
        .strip_prefix("//")
        .map(|rest| rest.split('/').next().unwrap_or_default());
    if authority.is_some_and(|host| host.contains('@')) {
        return Err("userinfo_not_allowed");
    }
    if scheme == "file" {
        return canonical_file_uri(settings, path, authority);
    }
    if !settings.network_schemes.contains(&scheme) {
        return Err("scheme_not_allowed");
    }
    if authority.is_none_or(str::is_empty) {
        return Err("network_host_missing");
    }
    let canonical = Url::parse(&format!("{scheme}:{path}")).map_err(|error| match error {
        ParseError::InvalidPort => "network_port_invalid",
        ParseError::EmptyHost => "network_host_missing",
        _ => "scheme_not_allowed",
    })?;
    Ok(canonical.to_string())
}

fn canonical_file_uri(
    settings: &RootSettings,
    path: &str,
    authority: Option<&str>,
) -> Result<String, &'static str> {
    if !settings.file_enabled {
        return Err("file_disabled");
    }
    if authority.is_some_and(|authority| !authority.is_empty()) {
        return Err("file_authority_not_allowed");
    }
    let path = path.strip_prefix("//").unwrap_or(path);
    if !path.starts_with('/') {
        return Err("file_path_not_absolute");
    }
    let lowercase = path.to_ascii_lowercase();
    if lowercase.contains("%2f") || lowercase.contains("%5c") {
        return Err("file_path_unsafe_encoding");
    }
    let decoded = percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| "file_path_unsafe_encoding")?;
    if has_control(&decoded)
        || decoded.contains('\\')
        || decoded
            .as_bytes()
            .get(1..3)
            .is_some_and(|tail| tail[0].is_ascii_alphabetic() && tail[1] == b':')
    {
        return Err("file_path_unsupported");
    }
    if percent_decode_str(&decoded)
        .decode_utf8()
        .map_or(true, |again| again != decoded)
    {
        return Err("file_path_unsafe_encoding");
    }
    if decoded.split('/').any(|part| part == "..") {
        return Err("file_path_traversal");
    }
    let components = decoded
        .split('/')
        .filter(|part| !matches!(*part, "" | "."))
        .collect::<Vec<_>>();
    let canonical = format!("/{}", components.join("/"));
    if !settings
        .file_prefixes
        .iter()
        .any(|prefix| FilePath::new(&canonical).starts_with(prefix))
    {
        return Err("file_path_outside_allowed_prefix");
    }
    Ok(format!(
        "file://{}",
        utf8_percent_encode(&canonical, PATH_ENCODING)
    ))
}

fn has_control(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_control())
}

fn not_found(uri: &str) -> RootError {
    RootError::Detail(StatusCode::NOT_FOUND, format!("Root not found: {uri}"))
}

enum RootError {
    Detail(StatusCode, String),
    Policy(&'static str),
    Database,
}

impl From<sqlx::Error> for RootError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "could not verify root management permissions");
        Self::Database
    }
}

impl IntoResponse for RootError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::Detail(status, detail) => (status, json!(detail)),
            Self::Policy(reason) => (
                StatusCode::BAD_REQUEST,
                json!({
                    "message":"Root URI rejected by policy","reason_code":reason
                }),
            ),
            Self::Database => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!("Root service unavailable"),
            ),
        };
        (status, Json(json!({"detail":detail}))).into_response()
    }
}
