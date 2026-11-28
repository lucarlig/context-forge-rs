// SPDX-License-Identifier: Apache-2.0

use axum::extract::Query;

use super::{
    catalog_api::{CatalogApiError, flag},
    *,
};
use crate::catalog::{SearchFilters, SearchKind, parse_tag_groups};

#[derive(Default)]
pub struct SearchSettings {
    pub(super) admin: bool,
    pub(super) registry: Option<registry::CatalogRegistry>,
}

impl SearchSettings {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use crate::config::{flag, parse, value};
        let enabled = flag("MCPGATEWAY_CATALOG_ENABLED")?.unwrap_or(true);
        let registry = if enabled {
            Some(registry::CatalogRegistry::new(
                value("MCPGATEWAY_CATALOG_FILE", "mcp-catalog.yml")?,
                Duration::from_secs(parse("MCPGATEWAY_CATALOG_CACHE_TTL", 3600)?),
                parse::<i64>("MCPGATEWAY_CATALOG_PAGE_SIZE", 100)?.max(1),
                flag("ALLOW_PUBLIC_VISIBILITY")?.unwrap_or(true),
            ))
        } else {
            None
        };
        Ok(Self {
            admin: flag("MCPGATEWAY_ADMIN_API_ENABLED")?.unwrap_or(false),
            registry,
        })
    }
}

pub(super) fn router(service: &Arc<GatewayService>) -> Router {
    let mut routes = Router::new()
        .route("/search", get(public))
        .route("/v1/search", get(public));
    if service.search.admin {
        routes = routes
            .route("/admin/search", get(admin))
            .route("/v1/admin/search", get(admin));
    }
    routes.with_state(service.clone())
}

impl GatewayService {
    pub(crate) async fn dashboard_search(
        &self,
        principal: &Principal,
        uri: &axum::http::Uri,
    ) -> Result<Value, CatalogApiError> {
        let Query(query) =
            Query::<SearchQuery>::try_from_uri(uri).map_err(|_| invalid("Invalid search query"))?;
        search(self, principal, query).await
    }
}

async fn public(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    search(&service, &principal, query).await.map(Json)
}

async fn admin(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    if !service
        .access
        .allows(&principal, "admin.dashboard", RoleContext::Global, false)
        .await?
    {
        return Err(denied());
    }
    search(&service, &principal, query).await.map(Json)
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
    tags: Option<String>,
    entity_types: Option<String>,
    include_inactive: Option<String>,
    limit: Option<i64>,
    limit_per_type: Option<i64>,
    gateway_id: Option<String>,
    mcp_server_id: Option<String>,
    team_id: Option<String>,
}

const DEFAULT_TYPES: &[&str] = &[
    "servers",
    "gateways",
    "tools",
    "resources",
    "prompts",
    "agents",
    "teams",
    "roots",
];

fn selected_types(query: &str) -> Result<Vec<&str>, CatalogApiError> {
    if query.len() > 200
        || !query
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || byte == b',')
    {
        return Err(invalid("Invalid entity_types"));
    }
    if query.is_empty() {
        return Ok(DEFAULT_TYPES.to_vec());
    }
    let mut types = Vec::new();
    for entity in query.split(',') {
        if let Some(entity) = DEFAULT_TYPES
            .iter()
            .chain([&"users", &"catalog"])
            .copied()
            .find(|candidate| entity.eq_ignore_ascii_case(candidate))
            && !types.contains(&entity)
        {
            types.push(entity);
        }
    }
    if types.is_empty() {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "No valid entity_types requested",
        ));
    }
    Ok(types)
}

fn gateway_filter(query: &SearchQuery) -> Result<(Vec<String>, bool), CatalogApiError> {
    for gateway in [&query.gateway_id, &query.mcp_server_id]
        .into_iter()
        .flatten()
    {
        if gateway.len() > 1000
            || !gateway
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b',' | b'-' | b'_'))
        {
            return Err(invalid("Invalid gateway filter"));
        }
    }
    if let (Some(old), Some(new)) = (&query.gateway_id, &query.mcp_server_id)
        && old != new
    {
        return Err(invalid("gateway_id and mcp_server_id conflict"));
    }
    let mut local = false;
    let mut ids = Vec::new();
    let expression = query
        .gateway_id
        .as_deref()
        .or(query.mcp_server_id.as_deref())
        .unwrap_or_default();
    for id in expression.split(',').filter(|id| !id.is_empty()) {
        if id.eq_ignore_ascii_case("null") {
            local = true;
        } else {
            ids.push(id.to_owned());
        }
    }
    Ok((ids, local))
}

async fn search(
    service: &GatewayService,
    principal: &Principal,
    query: SearchQuery,
) -> Result<Value, CatalogApiError> {
    let q = query.q.as_deref().unwrap_or_default();
    let tags = query.tags.as_deref().unwrap_or_default();
    if q.chars().count() > 500
        || tags.len() > 500
        || !tags
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_,+ .-".contains(&byte))
    {
        return Err(invalid("Invalid search text or tags"));
    }
    let q = q.trim().to_lowercase();
    let tags = tags.trim();
    let tag_groups = parse_tag_groups(tags);
    let mut entities = selected_types(query.entity_types.as_deref().unwrap_or_default())?;
    let (gateways, local) = gateway_filter(&query)?;
    let limit = query.limit.unwrap_or(8);
    let size = query.limit_per_type.unwrap_or(limit);
    let max = i64::from(service.management_max_page_size);
    if !(1..=max).contains(&limit) || !(1..=max).contains(&size) {
        return Err(invalid("Invalid search limit"));
    }
    let inactive = flag(query.include_inactive.as_deref())?;
    let selected_team = query
        .team_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid team ID"))?;
    if entities.contains(&"users")
        && !principal.is_admin()
        && !service
            .access
            .allows(
                principal,
                "admin.user_management",
                RoleContext::Global,
                false,
            )
            .await?
    {
        entities.retain(|entity| *entity != "users");
        if entities.is_empty() {
            return Err(denied());
        }
    }

    let mut results = serde_json::Map::new();
    let mut groups = Vec::new();
    let mut flat = Vec::new();
    if q.is_empty() && tag_groups.is_empty() {
        for entity in &entities {
            results.insert((*entity).to_owned(), json!([]));
        }
    } else {
        let team_ids = match &principal.visibility {
            TeamVisibility::Admin => service.database.memberships(&principal.email).await?,
            TeamVisibility::Teams(ids) => ids.clone(),
            TeamVisibility::Public => Vec::new(),
        };
        let team = selected_team.and_then(|selected| {
            team_ids
                .iter()
                .find(|id| Uuid::parse_str(id).ok() == Some(selected))
        });
        let filter = SearchFilters {
            email: &principal.email,
            unrestricted: principal.is_global_admin(),
            team_ids: &team_ids,
            team: team.map(String::as_str),
            text: &q,
            tags: &tag_groups,
            gateways: &gateways,
            local,
            include_inactive: inactive,
            limit: size,
        };
        for entity in &entities {
            let items = search_items(
                service,
                principal,
                entity,
                &filter,
                selected_team.is_some() && team.is_none(),
            )
            .await?;
            for item in &items {
                let mut enriched = item.clone();
                enriched["entity_type"] = json!(entity);
                flat.push(enriched);
            }
            groups.push(json!({"entity_type":entity,"count":items.len(),"items":items}));
            results.insert((*entity).to_owned(), json!(items));
        }
    }
    Ok(
        json!({"query":q,"tags":tags,"entity_types":entities,"limit_per_type":size,
        "filters_applied":{"q":q,"tags":tags,"tag_groups":tag_groups},
        "results":results,"groups":groups,"items":flat,"count":flat.len()}),
    )
}

async fn search_items(
    service: &GatewayService,
    principal: &Principal,
    entity: &str,
    filter: &SearchFilters<'_>,
    inaccessible_team: bool,
) -> Result<Vec<Value>, CatalogApiError> {
    let kind = match entity {
        "servers" => SearchKind::Servers,
        "gateways" => SearchKind::Gateways,
        "tools" => SearchKind::Tools,
        "resources" => SearchKind::Resources,
        "prompts" => SearchKind::Prompts,
        "agents" if service.a2a_enabled => SearchKind::Agents,
        _ => return supplementary_items(service, principal, entity, filter).await,
    };
    let role = filter.team.map_or(RoleContext::AnyTeam, RoleContext::Team);
    if inaccessible_team
        || !service
            .access
            .allows(principal, kind.permission(), role, false)
            .await?
    {
        return Ok(Vec::new());
    }
    Ok(service.database.search_catalog(kind, filter).await?)
}

async fn supplementary_items(
    service: &GatewayService,
    principal: &Principal,
    entity: &str,
    filter: &SearchFilters<'_>,
) -> Result<Vec<Value>, CatalogApiError> {
    if filter.text.is_empty() {
        return Ok(Vec::new());
    }
    let items = match entity {
        "teams"
            if service.email_auth_enabled
                && service
                    .access
                    .allows(principal, "teams.read", RoleContext::AnyTeam, false)
                    .await? =>
        {
            service.database.search_team_items(filter).await?
        }
        "users"
            if service.email_auth_enabled
                && (!principal.is_admin() || principal.is_global_admin())
                && service
                    .access
                    .allows(
                        principal,
                        "admin.user_management",
                        RoleContext::Global,
                        false,
                    )
                    .await? =>
        {
            service
                .database
                .search_user_items(filter.text, filter.limit)
                .await?
        }
        "roots" if service.can_administer_roots(principal).await? => service
            .roots
            .search(principal, filter.text, filter.limit as usize)
            .into_iter()
            .map(|root| {
                let name = if root.name.is_empty() {
                    &root.uri
                } else {
                    &root.name
                };
                json!({"id":root.uri,"name":name,"uri":root.uri})
            })
            .collect(),
        "catalog"
            if service
                .access
                .allows(principal, "servers.read", RoleContext::AnyTeam, false)
                .await? =>
        {
            service
                .registry_search(principal, filter.text, filter.limit)
                .await?
        }
        _ => Vec::new(),
    };
    Ok(items)
}

fn invalid(detail: &str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, detail)
}

fn denied() -> CatalogApiError {
    CatalogApiError::detail(StatusCode::FORBIDDEN, "Access denied")
}
