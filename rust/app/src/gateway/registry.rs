// SPDX-License-Identifier: Apache-2.0

mod registration;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::ErrorKind,
    time::Instant,
};

use axum::extract::{OriginalUri, Path, RawQuery};
use tokio::{io::AsyncReadExt, sync::Mutex};

use super::{
    catalog_api::{CatalogApiError, query_boolean, require_catalog_permission},
    *,
};

const DEFAULT_FILE: &str = "mcp-catalog.yml";
const MAX_CATALOG_BYTES: u64 = 1_048_576;

pub(super) struct CatalogRegistry {
    file: String,
    ttl: Duration,
    page_size: i64,
    allow_public_team: bool,
    cache: Mutex<Option<(Instant, Arc<[Entry]>)>>,
}

impl CatalogRegistry {
    pub(super) fn new(
        file: String,
        ttl: Duration,
        page_size: i64,
        allow_public_team: bool,
    ) -> Self {
        Self {
            file,
            ttl,
            page_size,
            allow_public_team,
            cache: Mutex::new(None),
        }
    }

    async fn entries(&self) -> Arc<[Entry]> {
        let mut cache = self.cache.lock().await;
        if let Some((loaded, entries)) = cache.as_ref()
            && loaded.elapsed() < self.ttl
        {
            return entries.clone();
        }
        match self.read().await {
            Ok(entries) => {
                let entries: Arc<[Entry]> = entries.into();
                *cache = Some((Instant::now(), entries.clone()));
                entries
            }
            Err(error) => {
                tracing::warn!(%error, "MCP registry file could not be read");
                Arc::from([])
            }
        }
    }

    async fn read(&self) -> Result<Vec<Entry>, Box<dyn std::error::Error + Send + Sync>> {
        let input = match tokio::fs::metadata(&self.file).await {
            Ok(metadata) if metadata.is_file() && metadata.len() <= MAX_CATALOG_BYTES => {
                let file = tokio::fs::File::open(&self.file).await?;
                let mut bytes = Vec::new();
                file.take(MAX_CATALOG_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .await?;
                if bytes.len() as u64 > MAX_CATALOG_BYTES {
                    return Err("catalog file exceeds its size limit".into());
                }
                String::from_utf8(bytes)?
            }
            Ok(_) => return Err("catalog path must be a regular file within the size limit".into()),
            Err(error) if error.kind() == ErrorKind::NotFound && self.file == DEFAULT_FILE => {
                include_str!("mcp-catalog.yml").to_owned()
            }
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let document =
            tokio::task::spawn_blocking(move || serde_saphyr::from_str::<Document>(&input))
                .await?
                .map_err(|_| "catalog YAML is invalid")?;
        Ok(document.catalog_servers)
    }
}

#[derive(Deserialize)]
struct Document {
    #[serde(default)]
    catalog_servers: Vec<Entry>,
}

#[derive(Deserialize, Serialize)]
struct Entry {
    id: String,
    name: String,
    description: String,
    auth_type: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    requires_api_key: bool,
    #[serde(default)]
    secure: bool,
    #[serde(default)]
    tags: Vec<Tag>,
    transport: Option<String>,
    logo_url: Option<String>,
    documentation_url: Option<String>,
    oauth: Option<OAuthMetadata>,
    #[serde(skip_serializing)]
    is_available: Option<bool>,
}

impl Entry {
    fn matches(&self, text: &str) -> bool {
        self.name.to_lowercase().contains(text) || self.description.to_lowercase().contains(text)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum Tag {
    Label(String),
    Metadata(BTreeMap<String, String>),
}

impl Tag {
    fn id(&self) -> Option<&str> {
        match self {
            Self::Label(label) => Some(label),
            Self::Metadata(data) => data.get("id").map(String::as_str),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OAuthMetadata {
    issuer: Option<String>,
    authorization_url: Option<String>,
    token_url: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    supports_dcr: bool,
    resource: Option<String>,
}

#[derive(Serialize)]
struct CatalogList<'a> {
    servers: Vec<CatalogRow<'a>>,
    total: usize,
    categories: BTreeSet<&'a str>,
    auth_types: BTreeSet<&'a str>,
    providers: BTreeSet<&'a str>,
    all_tags: BTreeSet<&'a str>,
}

#[derive(Serialize)]
struct CatalogRow<'a> {
    #[serde(flatten)]
    entry: &'a Entry,
    is_registered: bool,
    gateway_id: Option<&'a str>,
    is_available: bool,
    requires_oauth_config: bool,
}

struct Filters {
    category: String,
    auth_type: String,
    provider: String,
    search: String,
    tags: Vec<String>,
    registered_only: bool,
    available_only: bool,
    limit: i64,
    offset: i64,
    page: i64,
}

impl Default for Filters {
    fn default() -> Self {
        Self {
            category: String::new(),
            auth_type: String::new(),
            provider: String::new(),
            search: String::new(),
            tags: Vec::new(),
            registered_only: false,
            available_only: true,
            limit: 100,
            offset: 0,
            page: 1,
        }
    }
}

impl Filters {
    fn from_query(query: Option<&str>) -> Result<Self, CatalogApiError> {
        let mut filters = Self::default();
        let number = |name: &str, value: &str| {
            value.parse().map_err(|_| {
                CatalogApiError(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    json!({"detail":[{
                        "type":"int_parsing","loc":["query",name],
                        "msg":"Input should be a valid integer, unable to parse string as an integer",
                        "input":value
                    }]}),
                )
            })
        };
        for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            match name.as_ref() {
                "category" => filters.category = value.into_owned(),
                "auth_type" => filters.auth_type = value.into_owned(),
                "provider" => filters.provider = value.into_owned(),
                "search" => filters.search = value.to_lowercase(),
                "tags" => filters.tags.push(value.into_owned()),
                "show_registered_only" => {
                    filters.registered_only = query_boolean(&name, Some(&value), false)?
                }
                "show_available_only" => {
                    filters.available_only = query_boolean(&name, Some(&value), true)?
                }
                "limit" => filters.limit = number(&name, &value)?,
                "offset" => filters.offset = number(&name, &value)?,
                "page" => filters.page = number(&name, &value)?,
                _ => {}
            }
        }
        Ok(filters)
    }

    fn matches(&self, row: &CatalogRow<'_>) -> bool {
        let entry = row.entry;
        (self.category.is_empty() || self.category == entry.category)
            && (self.auth_type.is_empty() || self.auth_type == entry.auth_type)
            && (self.provider.is_empty() || self.provider == entry.provider)
            && (self.search.is_empty() || entry.matches(&self.search))
            && (self.tags.is_empty()
                || entry
                    .tags
                    .iter()
                    .filter_map(Tag::id)
                    .any(|tag| self.tags.iter().any(|item| item == tag)))
            && (!self.registered_only || row.is_registered)
            && (!self.available_only || row.is_available)
    }

    fn page_bounds(&self, count: usize) -> std::ops::Range<usize> {
        let count = count as i64;
        let index = |value: i64| {
            (if value < 0 {
                count.saturating_add(value)
            } else {
                value
            })
            .clamp(0, count) as usize
        };
        let start = index(self.offset);
        let end = index(self.offset.saturating_add(self.limit));
        start..end.max(start)
    }
}

pub(super) fn router() -> Router<Arc<GatewayService>> {
    registration::routes(Router::new().route("/v1/catalog", get(list)))
}

pub(super) fn admin_router() -> Router<Arc<GatewayService>> {
    let mut router = Router::new();
    for base in ["/admin/mcp-registry", "/v1/admin/mcp-registry"] {
        router = router
            .route(&format!("{base}/servers"), get(admin_list))
            .route(&format!("{base}/{{id}}/status"), get(status))
            .route(&format!("{base}/partial"), get(partial));
        router = registration::admin_routes(router, base);
    }
    router
}

fn enabled(service: &GatewayService) -> Result<&CatalogRegistry, CatalogApiError> {
    service.search.registry.as_ref().ok_or_else(|| {
        CatalogApiError::detail(StatusCode::NOT_FOUND, "Catalog feature is disabled")
    })
}

async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "servers.read", true).await?;
    directory(&service, &principal, query.as_deref())
        .await
        .map(Json)
}

async fn admin_list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "servers.read", false).await?;
    directory(&service, &principal, query.as_deref())
        .await
        .map(Json)
}

async fn directory(
    service: &GatewayService,
    principal: &Principal,
    query: Option<&str>,
) -> Result<Value, CatalogApiError> {
    let registry = enabled(service)?;
    let filters = Filters::from_query(query)?;
    let entries = registry.entries().await;
    let matches = gateway_matches(service, principal, &entries).await?;
    serde_json::to_value(build_list(&entries, &matches, &filters))
        .map_err(|_| CatalogApiError::unavailable())
}

async fn gateway_matches(
    service: &GatewayService,
    principal: &Principal,
    entries: &[Entry],
) -> Result<HashMap<String, crate::gateway_records::RegistryGateway>, sqlx::Error> {
    let urls = entries
        .iter()
        .map(|entry| entry.url.as_str())
        .collect::<Vec<_>>();
    if urls.is_empty() {
        return Ok(HashMap::new());
    }
    let mut matches = HashMap::new();
    for gateway in service
        .database
        .registry_gateways(&urls, &principal.email, &principal.visibility)
        .await?
    {
        matches.entry(gateway.url.clone()).or_insert(gateway);
    }
    Ok(matches)
}

fn build_list<'a>(
    entries: &'a [Entry],
    matches: &'a HashMap<String, crate::gateway_records::RegistryGateway>,
    filters: &Filters,
) -> CatalogList<'a> {
    let mut result = CatalogList {
        servers: Vec::new(),
        total: 0,
        categories: BTreeSet::new(),
        auth_types: BTreeSet::new(),
        providers: BTreeSet::new(),
        all_tags: BTreeSet::new(),
    };
    let mut rows = Vec::new();
    for entry in entries {
        result.categories.insert(entry.category.as_str());
        result.auth_types.insert(entry.auth_type.as_str());
        result.providers.insert(entry.provider.as_str());
        result
            .all_tags
            .extend(entry.tags.iter().filter_map(Tag::id));
        let gateway = matches.get(&entry.url);
        let row = CatalogRow {
            entry,
            is_registered: gateway.is_some(),
            gateway_id: gateway.map(|row| row.id.as_str()),
            is_available: gateway.is_some() || entry.is_available.unwrap_or(true),
            requires_oauth_config: gateway
                .is_some_and(|row| !row.enabled && row.auth_type.as_deref() == Some("oauth")),
        };
        if filters.matches(&row) {
            rows.push(row);
        }
    }
    result.total = rows.len();
    result.servers = rows.drain(filters.page_bounds(result.total)).collect();
    result
}

async fn status(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "servers.read", false).await?;
    let entries = enabled(&service)?.entries().await;
    let Some(entry) = entries.iter().find(|entry| entry.id == id) else {
        return Ok(Json(json!({
            "server_id":id,"is_available":false,"is_registered":false,
            "last_checked":null,"response_time_ms":null,"error":"Server not found in catalog"
        })));
    };
    let started = Instant::now();
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        let (client, url) = service
            .upstream
            .pinned_client(&entry.url, None, None)
            .await?;
        Ok::<_, UpstreamError>(client.get(url).send().await?.status().as_u16() < 500)
    })
    .await;
    let (available, error) = match response {
        Ok(Ok(available)) => (available, None),
        Ok(Err(UpstreamError::InvalidUrl | UpstreamError::BlockedDestination)) => {
            (false, Some("Catalog server URL is invalid or disallowed"))
        }
        Ok(Err(_)) => (false, Some("Catalog server could not be reached")),
        Err(_) => (false, Some("Catalog server health check timed out")),
    };
    Ok(Json(json!({
        "server_id":id,"is_available":available,"is_registered":false,
        "last_checked":Timestamp::now().to_string(),"response_time_ms":started.elapsed().as_secs_f64()*1000.0,
        "error":error
    })))
}

impl GatewayService {
    pub(crate) fn registry_enabled(&self) -> bool {
        self.search.registry.is_some()
    }

    pub(super) async fn registry_search(
        &self,
        principal: &Principal,
        query: &str,
        limit: i64,
    ) -> Result<Vec<Value>, CatalogApiError> {
        let Some(registry) = &self.search.registry else {
            return Ok(Vec::new());
        };
        let entries = registry.entries().await;
        let matches = gateway_matches(self, principal, &entries).await?;
        let filters = Filters {
            search: query.to_owned(),
            auth_type: "Open".to_owned(),
            limit,
            ..Filters::default()
        };
        Ok(build_list(&entries, &matches, &filters)
            .servers
            .into_iter()
            .map(|row| json!({"id":row.entry.id,"name":row.entry.name,"description":row.entry.description}))
            .collect())
    }

    pub(crate) async fn registry_panel(
        &self,
        principal: &Principal,
        query: Option<&str>,
        base: &str,
        section: bool,
    ) -> Result<Value, CatalogApiError> {
        let registry = enabled(self)?;
        let entries = registry.entries().await;
        let matches = gateway_matches(self, principal, &entries).await?;
        let mut filters = Filters::from_query(query)?;
        filters.available_only = false;
        filters.limit = registry.page_size;
        let page = filters.page.max(1);
        filters.offset = (page - 1).saturating_mul(filters.limit);
        let data = build_list(&entries, &matches, &filters);
        let pages = 1 + (data.total as i64).saturating_sub(1) / filters.limit;
        let can_register = section && registration::can_register(self, principal, None).await?;
        let form_ids: BTreeMap<_, _> = data
            .servers
            .iter()
            .map(|row| {
                let id = row.entry.id.as_str();
                let encoded =
                    percent_encoding::utf8_percent_encode(id, percent_encoding::NON_ALPHANUMERIC);
                (id, encoded.to_string())
            })
            .collect();
        let link = |page: i64| {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            if section {
                query.append_pair("section", "registry");
            }
            for (name, value) in [
                ("category", &filters.category),
                ("auth_type", &filters.auth_type),
                ("search", &filters.search),
            ] {
                if !value.is_empty() {
                    query.append_pair(name, value);
                }
            }
            query.append_pair("page", &page.to_string());
            format!("{base}?{}", query.finish())
        };
        Ok(json!({
            "data":data, "page":page, "pages":pages, "can_register":can_register, "form_ids":form_ids,
            "public_only":principal.visibility == TeamVisibility::Public,
            "category":filters.category, "auth_type":filters.auth_type, "search":filters.search,
            "previous":(page > 1).then(|| link(page - 1)),
            "next":(page < pages).then(|| link(page + 1))
        }))
    }
}

async fn partial(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, CatalogApiError> {
    require_catalog_permission(&service, &principal, "servers.read", false).await?;
    let panel = service
        .registry_panel(&principal, uri.query(), uri.path(), false)
        .await?;
    Ok(crate::local_auth::browser::registry_partial(panel))
}
