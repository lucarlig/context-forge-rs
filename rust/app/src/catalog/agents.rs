// SPDX-License-Identifier: Apache-2.0

use super::entry_filters::fetch_catalog_entries;
use super::*;
use crate::uaid::GeneratedUaid;
use sqlx::types::Json as DbJson;

mod admin;
mod lifecycle;
mod metrics;
pub(crate) use admin::AdminAgentFilters;
pub(crate) use cards::NewAgentCard;
pub(crate) use metrics::AgentInteraction;

#[derive(Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) description: Option<String>,
    pub(crate) endpoint_url: String,
    pub(crate) agent_type: String,
    pub(crate) protocol_binding: Option<String>,
    pub(crate) protocol_version: String,
    pub(crate) capabilities: DbJson<Value>,
    pub(crate) skills: Option<DbJson<Value>>,
    pub(crate) config: DbJson<Value>,
    pub(crate) passthrough_headers: Option<DbJson<Vec<String>>>,
    pub(crate) tags: DbJson<Value>,
    pub(crate) auth_type: Option<String>,
    #[serde(skip)]
    pub(crate) auth_value: Option<String>,
    #[serde(skip)]
    pub(crate) auth_query_params: Option<String>,
    pub(crate) enabled: bool,
    pub(crate) reachable: bool,
    pub(crate) team_id: Option<String>,
    pub(crate) team: Option<String>,
    pub(crate) owner_email: Option<String>,
    pub(crate) visibility: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) created_by: Option<String>,
    pub(crate) created_from_ip: Option<String>,
    pub(crate) created_via: Option<String>,
    pub(crate) created_user_agent: Option<String>,
    pub(crate) modified_by: Option<String>,
    pub(crate) modified_from_ip: Option<String>,
    pub(crate) modified_via: Option<String>,
    pub(crate) modified_user_agent: Option<String>,
    pub(crate) import_batch_id: Option<String>,
    pub(crate) federation_source: Option<String>,
    pub(crate) last_interaction: Option<String>,
    pub(crate) version: i32,
    pub(crate) uaid: Option<String>,
    pub(crate) uaid_registry: Option<String>,
    pub(crate) uaid_proto: Option<String>,
    pub(crate) uaid_native_id: Option<String>,
    #[serde(skip)]
    pub(crate) tenant: Option<String>,
    #[serde(skip)]
    pub(crate) icon_url: Option<String>,
    #[serde(skip)]
    pub(crate) oauth_config: Option<DbJson<Value>>,
}

impl AgentRecord {
    pub(crate) fn published_skills(&self) -> impl Iterator<Item = &Value> {
        self.skills
            .as_ref()
            .and_then(|skills| skills.0.as_array())
            .or_else(|| self.capabilities.0["skills"].as_array())
            .into_iter()
            .flatten()
            .filter(|skill| skill.is_object())
    }

    pub(crate) fn set_uaid(&mut self, generated: GeneratedUaid) {
        self.uaid = Some(generated.identifier);
        self.uaid_registry = Some(generated.registry);
        self.uaid_proto = Some(generated.protocol);
        self.uaid_native_id = Some(generated.source);
    }

    pub(crate) fn stored_headers(&self) -> Option<std::borrow::Cow<'_, str>> {
        self.auth_value.as_deref().map(|stored| {
            if stored.starts_with(['"', '{']) {
                std::borrow::Cow::Borrowed(stored)
            } else {
                std::borrow::Cow::Owned(json!(stored).to_string())
            }
        })
    }

    pub(crate) fn visible(&self, scope: CatalogScope<'_>) -> bool {
        scope.visible(
            &self.visibility,
            self.team_id.as_deref(),
            self.owner_email.as_deref(),
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AgentLookup<'a> {
    Id(&'a str),
    Name(&'a str),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AgentWriteError {
    #[error("agent name is in use")]
    Duplicate { id: String, enabled: bool },
    #[error("the associated MCP tool name is in use")]
    ToolConflict,
    #[error("agent changed during the request")]
    Changed,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

macro_rules! projection {
    () => {
        "SELECT r.id, r.name, r.slug, r.description, r.endpoint_url, r.agent_type, r.protocol_binding,
            r.protocol_version, COALESCE(r.capabilities, '{}') AS capabilities, r.skills,
            COALESCE(r.config, '{}') AS config,
            CASE WHEN CAST(r.passthrough_headers AS TEXT) = 'null' THEN NULL
                ELSE r.passthrough_headers END AS passthrough_headers,
            r.tags, r.auth_type,
            r.auth_value, CAST(r.auth_query_params AS TEXT) AS auth_query_params, r.enabled, r.reachable,
            r.team_id, t.name AS team, r.owner_email, r.visibility,
            CAST(r.created_at AS TEXT) AS created_at, CAST(r.updated_at AS TEXT) AS updated_at,
            r.created_by, r.created_from_ip, r.created_via, r.created_user_agent, r.modified_by,
            r.modified_from_ip, r.modified_via, r.modified_user_agent, r.import_batch_id,
            r.federation_source, CAST(r.last_interaction AS TEXT) AS last_interaction, r.version,
            r.uaid, r.uaid_registry, r.uaid_proto, r.uaid_native_id, r.tenant, r.icon_url, r.oauth_config
         FROM (SELECT a.*, NULL AS gateway_id FROM a2a_agents a) r
         LEFT JOIN email_teams t ON t.id = r.team_id AND t.is_active = TRUE"
    };
}
use projection;
const BY_ID: &str = concat!(projection!(), " WHERE r.id = $1");
const BY_UAID: &str = concat!(projection!(), " WHERE r.id = $1 OR r.uaid = $1 LIMIT 2");
const BY_NAME: &str = concat!(
    projection!(),
    " WHERE r.name = $1 ORDER BY r.created_at DESC, r.id DESC"
);

mod cards;

const DUPLICATE: &str = "
    SELECT id, enabled FROM a2a_agents WHERE slug = $1 AND visibility = $2
       AND ($2 = 'public'
          OR ($2 = 'team' AND team_id = $3)
          OR ($2 = 'private' AND owner_email = $4 AND team_id IS NOT DISTINCT FROM $3))
       AND id <> $5
    LIMIT 1";

const INSERT_AGENT: &str = "
    INSERT INTO a2a_agents (id, name, slug, description, endpoint_url, agent_type, protocol_binding,
        protocol_version, capabilities, skills, config, passthrough_headers, tags, auth_type,
        auth_value, auth_query_params, team_id, owner_email, visibility, enabled, reachable,
        created_at, updated_at, created_by, created_from_ip, created_via, created_user_agent, version,
        tool_id, oauth_config, uaid, uaid_registry, uaid_proto, uaid_native_id)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
            $19, TRUE, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $18, $20, $28, $21, 1, $22, $23,
            $24, $25, $26, $27)";

const INSERT_TOOL: &str = "
    INSERT INTO tools (id, name, original_name, custom_name_slug, custom_name, url,
        description, original_description, integration_type, request_type, input_schema,
        annotations, tags, enabled, reachable, deprecated, expose_passthrough, jsonpath_filter,
        created_at, updated_at, created_by, created_via, version, team_id, owner_email, visibility, display_name)
    VALUES ($1,$2,$3,$2,$3,$4,$5,$5,'A2A','POST',$6,$7,$8,TRUE,TRUE,FALSE,TRUE,'',
        CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$9,$12,1,$10,$9,$11,$13)";

impl Database {
    pub(crate) async fn local_uaid_agents(
        &self,
        identifier: &str,
    ) -> Result<Vec<AgentRecord>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(BY_UAID)
                    .bind(identifier)
                    .fetch_all(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(BY_UAID)
                    .bind(identifier)
                    .fetch_all(pool)
                    .await
            }
        }
    }

    pub(crate) async fn agent_has_enforced_binding(
        &self,
        agent: &AgentRecord,
    ) -> Result<bool, sqlx::Error> {
        let Some(team) = agent.team_id.as_deref() else {
            return Ok(false);
        };
        const BINDINGS: &str = "
            SELECT EXISTS (
                SELECT 1 FROM a2a_agent_plugin_bindings b
                WHERE b.team_id = $1 AND b.mode = 'enforce'
                  AND (b.agent_name = $2 OR (b.agent_name = '*' AND NOT EXISTS (
                      SELECT 1 FROM a2a_agent_plugin_bindings specific
                      WHERE specific.team_id = b.team_id AND specific.plugin_id = b.plugin_id
                        AND specific.agent_name = $2)))
            )";
        macro_rules! check {
            ($pool:expr, $exists:literal) => {{
                if !sqlx::query_scalar::<_, bool>($exists)
                    .fetch_one($pool)
                    .await?
                {
                    return Ok(false);
                }
                sqlx::query_scalar(BINDINGS)
                    .bind(team)
                    .bind(&agent.name)
                    .fetch_one($pool)
                    .await
            }};
        }
        match self {
            Self::Sqlite(pool) => check!(
                pool,
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                WHERE type = 'table' AND name = 'a2a_agent_plugin_bindings')"
            ),
            Self::Postgres(pool) => check!(
                pool,
                "SELECT to_regclass('a2a_agent_plugin_bindings') IS NOT NULL"
            ),
        }
    }

    pub(crate) async fn list_agents(
        &self,
        scope: CatalogScope<'_>,
        filter: CatalogEntryFilters<'_>,
    ) -> Result<Vec<AgentRecord>, sqlx::Error> {
        fetch_catalog_entries!(self, AgentRecord, scope, filter, projection!(), "TRUE")
    }

    pub(crate) async fn find_agent(
        &self,
        scope: CatalogScope<'_>,
        lookup: AgentLookup<'_>,
    ) -> Result<Option<AgentRecord>, sqlx::Error> {
        macro_rules! select {
            ($pool:expr) => {
                match lookup {
                    AgentLookup::Id(id) => sqlx::query_as::<_, AgentRecord>(BY_ID)
                        .bind(id)
                        .fetch_optional($pool)
                        .await?
                        .filter(|agent| agent.visible(scope)),
                    AgentLookup::Name(name) => {
                        sqlx::query_as::<_, AgentRecord>(BY_NAME)
                            .bind(name)
                            .fetch($pool)
                            .try_filter(|agent| std::future::ready(agent.visible(scope)))
                            .try_next()
                            .await?
                    }
                }
            };
        }
        Ok(match self {
            Self::Sqlite(pool) => select!(pool),
            Self::Postgres(pool) => select!(pool),
        })
    }

    pub(crate) async fn insert_agent(
        &self,
        agent: &AgentRecord,
        auth_query: Option<&Value>,
        cards: &[NewAgentCard<'_>],
    ) -> Result<AgentRecord, AgentWriteError> {
        let original_name = format!("a2a_{}", agent.slug);
        let tool_id = (original_name.chars().count() <= 255)
            .then(|| uuid::Uuid::new_v4().simple().to_string());
        let tool_name = slugify(&original_name);
        let description = tool_description(agent);
        let input_schema = json!({
            "type":"object",
            "properties":{"query":{"type":"string","description":"User query","default":"Hello from ContextForge Admin UI test!"}},
            "required":["query"],
        });
        let annotations = json!({"title":format!("A2A Agent: {}", agent.name)});
        let tags = tool_tags(agent);
        macro_rules! insert {
            ($tx:ident) => {{
                if let Some((id, enabled)) = sqlx::query_as::<_, (String, bool)>(DUPLICATE)
                    .bind(&agent.slug)
                    .bind(&agent.visibility)
                    .bind(&agent.team_id)
                    .bind(&agent.owner_email)
                    .bind(&agent.id)
                    .fetch_optional(&mut *$tx)
                    .await?
                {
                    return Err(AgentWriteError::Duplicate { id, enabled });
                }
                if let Some(tool_id) = &tool_id {
                    sqlx::query(INSERT_TOOL)
                        .bind(tool_id)
                        .bind(&tool_name)
                        .bind(&original_name)
                        .bind(&agent.endpoint_url)
                        .bind(&description)
                        .bind(DbJson(&input_schema))
                        .bind(DbJson(&annotations))
                        .bind(DbJson(&tags))
                        .bind(&agent.owner_email)
                        .bind(&agent.team_id)
                        .bind(&agent.visibility)
                        .bind(agent.created_via.as_deref().unwrap_or("api"))
                        .bind(display_name(&agent.name))
                        .execute(&mut *$tx)
                        .await?;
                }
                sqlx::query(INSERT_AGENT)
                    .bind(&agent.id)
                    .bind(&agent.name)
                    .bind(&agent.slug)
                    .bind(&agent.description)
                    .bind(&agent.endpoint_url)
                    .bind(&agent.agent_type)
                    .bind(&agent.protocol_binding)
                    .bind(&agent.protocol_version)
                    .bind(&agent.capabilities)
                    .bind(&agent.skills)
                    .bind(&agent.config)
                    .bind(&agent.passthrough_headers)
                    .bind(&agent.tags)
                    .bind(&agent.auth_type)
                    .bind(&agent.auth_value)
                    .bind(auth_query.map(DbJson))
                    .bind(&agent.team_id)
                    .bind(&agent.owner_email)
                    .bind(&agent.visibility)
                    .bind(&agent.created_from_ip)
                    .bind(&agent.created_user_agent)
                    .bind(&tool_id)
                    .bind(&agent.oauth_config)
                    .bind(&agent.uaid)
                    .bind(&agent.uaid_registry)
                    .bind(&agent.uaid_proto)
                    .bind(&agent.uaid_native_id)
                    .bind(agent.created_via.as_deref().unwrap_or("api"))
                    .execute(&mut *$tx)
                    .await?;
                cards::insert_cards!($tx, &agent.id, cards);
                let result = sqlx::query_as(BY_ID)
                    .bind(&agent.id)
                    .fetch_one(&mut *$tx)
                    .await?;
                $tx.commit().await?;
                Ok(result)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                insert!(tx)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                insert!(tx)
            }
        }
    }
}

fn tool_description(agent: &AgentRecord) -> String {
    let description = agent
        .description
        .as_deref()
        .filter(|description| !description.is_empty())
        .unwrap_or(&agent.name);
    format!("A2A Agent: {description}")
}

fn tool_tags(agent: &AgentRecord) -> Vec<Value> {
    let mut tags = agent.tags.0.as_array().cloned().unwrap_or_default();
    for label in ["a2a", "agent"] {
        if !tags.iter().any(|tag| tag["id"] == label) {
            tags.push(json!({"id":label,"label":label}));
        }
    }
    tags
}
