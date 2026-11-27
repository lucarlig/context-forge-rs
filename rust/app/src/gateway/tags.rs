// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use axum::extract::{Path, Query};

use super::*;
use crate::catalog::{CatalogScope, visible_team_ids};

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum EntityKind {
    Tool,
    Resource,
    Prompt,
    Server,
    Gateway,
}

impl EntityKind {
    const ALL: [Self; 5] = [
        Self::Tool,
        Self::Resource,
        Self::Prompt,
        Self::Server,
        Self::Gateway,
    ];

    fn table(self) -> &'static str {
        match self {
            Self::Tool => "tools",
            Self::Resource => "resources",
            Self::Prompt => "prompts",
            Self::Server => "servers",
            Self::Gateway => "gateways",
        }
    }
}

#[derive(Clone, Serialize)]
struct TaggedEntity {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: EntityKind,
    description: Option<String>,
}

#[derive(Default, Serialize)]
struct TagStats {
    tools: usize,
    resources: usize,
    prompts: usize,
    servers: usize,
    gateways: usize,
    total: usize,
}

impl TagStats {
    fn record(&mut self, kind: EntityKind) {
        let count = match kind {
            EntityKind::Tool => &mut self.tools,
            EntityKind::Resource => &mut self.resources,
            EntityKind::Prompt => &mut self.prompts,
            EntityKind::Server => &mut self.servers,
            EntityKind::Gateway => &mut self.gateways,
        };
        *count += 1;
        self.total += 1;
    }
}

#[derive(Serialize)]
struct TagInfo {
    name: String,
    stats: TagStats,
    entities: Vec<TaggedEntity>,
}

#[derive(Deserialize)]
struct TagQuery {
    entity_types: Option<String>,
    include_entities: Option<String>,
}

impl TagQuery {
    fn include_entities(&self) -> Result<bool, TagError> {
        match self
            .include_entities
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("false" | "f" | "no" | "n" | "off" | "0") => Ok(false),
            Some("true" | "t" | "yes" | "y" | "on" | "1") => Ok(true),
            _ => Err(TagError::InvalidIncludeEntities),
        }
    }

    fn kinds(&self) -> Vec<EntityKind> {
        let Some(kinds) = self
            .entity_types
            .as_deref()
            .filter(|value| !value.is_empty())
        else {
            return EntityKind::ALL.to_vec();
        };
        kinds
            .split(',')
            .filter_map(|value| {
                EntityKind::ALL
                    .into_iter()
                    .find(|kind| kind.table().eq_ignore_ascii_case(value.trim()))
            })
            .collect()
    }
}

pub(super) fn router() -> Router<Arc<GatewayService>> {
    let mut routes = Router::new();
    for base in ["/tags", "/v1/tags"] {
        routes = routes
            .route(base, get(list))
            .route(&format!("{base}/"), get(list))
            .route(&format!("{base}/{{tag}}/entities"), get(entities));
    }
    routes
}

async fn tag_scope<'a>(
    service: &GatewayService,
    principal: &'a Principal,
) -> Result<CatalogScope<'a>, TagError> {
    if !service
        .access
        .allows(principal, "tags.read", RoleContext::AnyTeam, true)
        .await?
    {
        return Err(TagError::Denied);
    }
    Ok(access::catalog_scope(Some(principal)))
}

async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<TagQuery>,
) -> Result<Json<Vec<TagInfo>>, TagError> {
    let scope = tag_scope(&service, &principal).await?;
    let include_entities = query.include_entities()?;
    let mut tags = BTreeMap::new();
    for kind in query.kinds() {
        for stored in service.database.tagged_entities(scope, kind).await? {
            let ids = tag_ids(&stored.tags);
            let entity = include_entities.then(|| stored.entity(kind));
            for id in ids {
                let info = tags.entry(id.clone()).or_insert_with(|| TagInfo {
                    name: id,
                    stats: TagStats::default(),
                    entities: Vec::new(),
                });
                info.stats.record(kind);
                if let Some(entity) = &entity {
                    info.entities.push(entity.clone());
                }
            }
        }
    }
    Ok(Json(tags.into_values().collect()))
}

async fn entities(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(tag): Path<String>,
    Query(query): Query<TagQuery>,
) -> Result<Json<Vec<TaggedEntity>>, TagError> {
    let scope = tag_scope(&service, &principal).await?;
    let mut matches = Vec::new();
    for kind in query.kinds() {
        for stored in service.database.tagged_entities(scope, kind).await? {
            if tag_ids(&stored.tags).iter().any(|id| id == &tag) {
                matches.push(stored.entity(kind));
            }
        }
    }
    Ok(Json(matches))
}

fn tag_ids(raw: &str) -> Vec<String> {
    let Ok(Value::Array(tags)) = serde_json::from_str(raw) else {
        return Vec::new();
    };
    tags.into_iter()
        .map(|tag| match tag {
            Value::String(label) => label,
            other => other["id"]
                .as_str()
                .filter(|value| !value.is_empty())
                .or_else(|| other["label"].as_str().filter(|value| !value.is_empty()))
                .map_or_else(|| other.to_string(), str::to_owned),
        })
        .collect()
}

#[derive(sqlx::FromRow)]
struct StoredTaggedEntity {
    id: String,
    name: String,
    description: Option<String>,
    tags: String,
}

impl StoredTaggedEntity {
    fn entity(self, kind: EntityKind) -> TaggedEntity {
        TaggedEntity {
            id: self.id,
            name: self.name,
            description: self.description,
            kind,
        }
    }
}

impl Database {
    async fn tagged_entities(
        &self,
        scope: CatalogScope<'_>,
        kind: EntityKind,
    ) -> Result<Vec<StoredTaggedEntity>, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        macro_rules! select {
            ($teams:literal, $table:literal) => {
                concat!("WITH visible_team_ids(id) AS (", $teams, ")
                    SELECT id, name, description, CAST(tags AS TEXT) AS tags FROM ", $table, "
                    WHERE CAST(tags AS TEXT) NOT IN ('null', '[]', '{}') AND
                      (visibility = 'public'
                       OR (visibility = 'team' AND ($2 OR team_id IN (SELECT id FROM visible_team_ids)))
                       OR (visibility = 'private' AND $3 AND owner_email = $4))
                    ORDER BY id")
            };
        }
        macro_rules! fetch {
            ($pool:ident, $teams:literal) => {{
                let query = match kind {
                    EntityKind::Tool => select!($teams, "tools"),
                    EntityKind::Resource => select!($teams, "resources"),
                    EntityKind::Prompt => select!($teams, "prompts"),
                    EntityKind::Server => select!($teams, "servers"),
                    EntityKind::Gateway => select!($teams, "gateways"),
                };
                sqlx::query_as::<_, StoredTaggedEntity>(query)
                    .bind(teams)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(scope.email)
                    .fetch_all($pool)
                    .await
            }};
        }
        match self {
            Self::Sqlite(pool) => fetch!(pool, "SELECT value FROM json_each($1)"),
            Self::Postgres(pool) => {
                fetch!(pool, "SELECT json_array_elements_text(CAST($1 AS JSON))")
            }
        }
    }
}

enum TagError {
    Denied,
    InvalidIncludeEntities,
    Database,
}

impl From<sqlx::Error> for TagError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "tag registry query failed");
        Self::Database
    }
}

impl IntoResponse for TagError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::Denied => (StatusCode::FORBIDDEN, json!("Access denied")),
            Self::InvalidIncludeEntities => (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!([{
                    "loc":["query","include_entities"],"type":"bool_parsing",
                    "msg":"Input should be a valid boolean, unable to interpret input"
                }]),
            ),
            Self::Database => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!("Failed to retrieve tags"),
            ),
        };
        (status, Json(json!({"detail":detail}))).into_response()
    }
}
