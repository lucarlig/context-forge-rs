// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use super::entry_filters::fetch_catalog_entries;
use super::*;

#[derive(Clone, Default, Serialize, sqlx::FromRow)]
pub(crate) struct ServerRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) icon: Option<String>,
    pub(crate) enabled: bool,
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
    pub(crate) version: Option<i32>,
    pub(crate) team_id: Option<String>,
    pub(crate) team: Option<String>,
    pub(crate) owner_email: Option<String>,
    pub(crate) visibility: String,
    pub(crate) oauth_enabled: bool,
    pub(crate) oauth_config_approved: bool,
    #[serde(skip)]
    pub(crate) oauth_config: Option<String>,
    #[serde(skip)]
    pub(crate) oauth_config_generation: Option<String>,
    pub(crate) instructions: Option<String>,
    #[serde(skip)]
    pub(crate) tags: String,
}

impl ServerRecord {
    pub(crate) fn is_visible(&self, scope: CatalogScope<'_>) -> bool {
        scope.visible(
            &self.visibility,
            self.team_id.as_deref(),
            self.owner_email.as_deref(),
        )
    }
}

#[derive(Default)]
pub(crate) struct ServerLinks {
    pub(crate) tools: Vec<(String, String)>,
    pub(crate) resources: Vec<String>,
    pub(crate) prompts: Vec<String>,
    pub(crate) agents: Vec<String>,
    pub(crate) interfaces: Vec<ServerInterface>,
}

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct ServerInterface {
    pub(crate) id: String,
    pub(crate) server_id: String,
    pub(crate) protocol: String,
    pub(crate) binding: String,
    pub(crate) version: Option<String>,
    pub(crate) tenant: Option<String>,
    pub(crate) enabled: bool,
    #[serde(skip)]
    pub(crate) config: Option<String>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

macro_rules! server_select {
    () => {
        "SELECT r.id,r.name,r.description,r.icon,r.enabled,
            CAST(r.created_at AS TEXT) AS created_at,CAST(r.updated_at AS TEXT) AS updated_at,
            r.created_by,r.created_from_ip,r.created_via,r.created_user_agent,
            r.modified_by,r.modified_from_ip,r.modified_via,r.modified_user_agent,
            r.import_batch_id,r.federation_source,r.version,r.team_id,e.name AS team,r.owner_email,r.visibility,
            r.oauth_enabled,r.oauth_config_approved,CAST(r.oauth_config AS TEXT) AS oauth_config,
            r.oauth_config_generation,r.instructions,COALESCE(CAST(r.tags AS TEXT),'[]') AS tags
         FROM (SELECT servers.*, CAST(NULL AS TEXT) AS gateway_id FROM servers) r
            LEFT JOIN email_teams e ON e.id=r.team_id AND e.is_active"
    };
}

const SERVER_BY_ID: &str = concat!(server_select!(), " WHERE r.id=$1");

macro_rules! server_links {
    ($ids:literal, $teams:literal) => {
        concat!(
            "WITH ids(id) AS (", $ids, "), teams(id) AS (", $teams, ")
             SELECT server_id, kind, id, name FROM (
                SELECT a.server_id,'tool' AS kind,c.id,c.name,c.visibility,c.team_id,c.owner_email
                  FROM server_tool_association a JOIN tools c ON c.id=a.tool_id WHERE c.enabled
                UNION ALL
                SELECT a.server_id,'resource',c.id,c.name,c.visibility,c.team_id,c.owner_email
                  FROM server_resource_association a JOIN resources c ON c.id=a.resource_id WHERE c.enabled
                UNION ALL
                SELECT a.server_id,'prompt',c.id,c.name,c.visibility,c.team_id,c.owner_email
                  FROM server_prompt_association a JOIN prompts c ON c.id=a.prompt_id WHERE c.enabled
             ) visible
             WHERE server_id IN (SELECT id FROM ids) AND (
                visibility='public' OR (visibility='team' AND ($3 OR team_id IN (SELECT id FROM teams)))
                  OR (visibility='private' AND $4 AND owner_email=$5))
             ORDER BY server_id,kind,id"
        )
    };
}

macro_rules! server_interfaces {
    ($ids:literal) => {
        concat!(
            "SELECT id,server_id,protocol,binding,version,tenant,enabled,CAST(config AS TEXT) AS config,
                CAST(created_at AS TEXT) AS created_at,CAST(updated_at AS TEXT) AS updated_at
             FROM server_interfaces WHERE server_id IN (", $ids, ") ORDER BY server_id,id"
        )
    };
}

macro_rules! server_agents {
    ($ids:literal, $teams:literal) => {
        concat!(
            "WITH ids(id) AS (", $ids, "), teams(id) AS (", $teams, ")
             SELECT a.server_id,c.id FROM server_a2a_association a
             JOIN a2a_agents c ON c.id=a.a2a_agent_id
             WHERE c.enabled AND a.server_id IN (SELECT id FROM ids)
                AND (c.visibility='public' OR (c.visibility='team' AND ($3 OR c.team_id IN (SELECT id FROM teams)))
                     OR (c.visibility='private' AND $4 AND c.owner_email=$5))
             ORDER BY a.server_id,c.id"
        )
    };
}

impl Database {
    pub(crate) async fn managed_server(
        &self,
        id: &str,
    ) -> Result<Option<ServerRecord>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(SERVER_BY_ID)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(SERVER_BY_ID)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
        }
    }

    pub(crate) async fn managed_servers(
        &self,
        scope: CatalogScope<'_>,
        filter: CatalogEntryFilters<'_>,
    ) -> Result<Vec<ServerRecord>, sqlx::Error> {
        fetch_catalog_entries!(self, ServerRecord, scope, filter, server_select!(), "TRUE")
    }

    pub(crate) async fn managed_server_links(
        &self,
        ids: &[&str],
        scope: CatalogScope<'_>,
    ) -> Result<HashMap<String, ServerLinks>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let ids =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        let teams = visible_team_ids(scope)?;
        macro_rules! read {
            ($pool:ident, $ids:literal, $teams:literal) => {
                tokio::try_join!(
                    sqlx::query_as::<_, (String, String, String, String)>(server_links!(
                        $ids, $teams
                    ))
                    .bind(&ids)
                    .bind(&teams)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(scope.email)
                    .fetch_all($pool),
                    sqlx::query_as::<_, ServerInterface>(server_interfaces!($ids))
                        .bind(&ids)
                        .fetch_all($pool),
                )?
            };
        }
        let (rows, interfaces) = match self {
            Self::Sqlite(pool) => read!(
                pool,
                "SELECT value FROM json_each($1)",
                "SELECT value FROM json_each($2)"
            ),
            Self::Postgres(pool) => read!(
                pool,
                "SELECT json_array_elements_text(CAST($1 AS JSON))",
                "SELECT json_array_elements_text(CAST($2 AS JSON))"
            ),
        };
        let mut links: HashMap<String, ServerLinks> = HashMap::new();
        for (server, kind, id, name) in rows {
            let links = links.entry(server).or_default();
            match kind.as_str() {
                "tool" => links.tools.push((id, name)),
                "resource" => links.resources.push(id),
                "prompt" => links.prompts.push(id),
                _ => unreachable!("link type from catalog query"),
            }
        }
        for interface in interfaces {
            links
                .entry(interface.server_id.clone())
                .or_default()
                .interfaces
                .push(interface);
        }
        macro_rules! agents {
            ($pool:ident, $exists:literal, $ids:literal, $teams:literal) => {{
                if sqlx::query_scalar::<_, bool>($exists)
                    .bind("server_a2a_association")
                    .fetch_one($pool)
                    .await?
                {
                    sqlx::query_as::<_, (String, String)>(server_agents!($ids, $teams))
                        .bind(&ids)
                        .bind(&teams)
                        .bind(scope.visibility == &TeamVisibility::Admin)
                        .bind(scope.can_own())
                        .bind(scope.email)
                        .fetch_all($pool)
                        .await?
                } else {
                    Vec::new()
                }
            }};
        }
        let agents = match self {
            Self::Sqlite(pool) => agents!(
                pool,
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=$1)",
                "SELECT value FROM json_each($1)",
                "SELECT value FROM json_each($2)"
            ),
            Self::Postgres(pool) => agents!(
                pool,
                "SELECT to_regclass(CAST($1 AS TEXT)) IS NOT NULL",
                "SELECT json_array_elements_text(CAST($1 AS JSON))",
                "SELECT json_array_elements_text(CAST($2 AS JSON))"
            ),
        };
        for (server, agent) in agents {
            links.entry(server).or_default().agents.push(agent);
        }
        Ok(links)
    }
}

mod write;
pub(crate) use write::{ServerInterfaceInput, ServerLinkUpdate, ServerWriteError};
