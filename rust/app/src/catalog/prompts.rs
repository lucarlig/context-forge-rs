// SPDX-License-Identifier: Apache-2.0

use super::entry_filters::fetch_catalog_entries;
use super::*;

#[derive(Clone, Default, Serialize, sqlx::FromRow)]
pub(crate) struct PromptRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) original_name: String,
    pub(crate) custom_name: String,
    pub(crate) custom_name_slug: String,
    pub(crate) display_name: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) template: Option<String>,
    #[serde(skip)]
    pub(crate) argument_schema: Option<String>,
    #[serde(skip)]
    pub(crate) tags: String,
    pub(crate) enabled: bool,
    pub(crate) gateway_id: Option<String>,
    pub(crate) gateway_slug: Option<String>,
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
    pub(crate) version: Option<i32>,
}

macro_rules! prompt_select {
    () => {
        "SELECT r.id, r.name, r.original_name, r.custom_name, r.custom_name_slug, r.display_name,
            r.title, r.description, r.template, CAST(r.argument_schema AS TEXT) AS argument_schema,
            CAST(r.tags AS TEXT) AS tags, COALESCE(r.enabled, FALSE) AS enabled,
            r.gateway_id, g.slug AS gateway_slug, r.team_id, e.name AS team, r.owner_email, r.visibility,
            CAST(r.created_at AS TEXT) AS created_at, CAST(r.updated_at AS TEXT) AS updated_at,
            r.created_by, r.created_from_ip, r.created_via, r.created_user_agent,
            r.modified_by, r.modified_from_ip, r.modified_via, r.modified_user_agent,
            r.import_batch_id, r.federation_source, r.version
         FROM prompts r LEFT JOIN email_teams e ON e.id = r.team_id AND e.is_active
            LEFT JOIN gateways g ON g.id = r.gateway_id"
    };
}

impl Database {
    pub(crate) async fn managed_prompts(
        &self,
        scope: CatalogScope<'_>,
        filter: CatalogEntryFilters<'_>,
    ) -> Result<Vec<PromptRecord>, sqlx::Error> {
        fetch_catalog_entries!(self, PromptRecord, scope, filter, prompt_select!(), "TRUE")
    }

    pub(crate) async fn inactive_prompt_exists(
        &self,
        scope: CatalogScope<'_>,
        id: &str,
        server: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        macro_rules! read {
            ($pool:ident, $teams:literal) => {
                sqlx::query_scalar(concat!(
                    "WITH visible_teams(id) AS (", $teams, ") SELECT EXISTS (
                       SELECT 1 FROM prompts p WHERE (p.id = $1 OR p.name = $1) AND NOT p.enabled
                         AND (p.visibility = 'public' OR (p.visibility = 'private' AND $2 AND p.owner_email = $3)
                              OR (p.visibility = 'team' AND ($4 OR p.team_id IN (SELECT id FROM visible_teams))))
                         AND (CAST($6 AS TEXT) IS NULL OR EXISTS (
                              SELECT 1 FROM server_prompt_association a JOIN servers s ON s.id = a.server_id
                              WHERE a.prompt_id = p.id AND s.id = $6 AND s.enabled
                                AND (s.visibility = 'public' OR (s.visibility = 'private' AND $2 AND s.owner_email = $3)
                                     OR (s.visibility = 'team' AND ($4 OR s.team_id IN (SELECT id FROM visible_teams))))))
                     )"
                ))
                    .bind(id)
                    .bind(scope.can_own())
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(teams)
                    .bind(server)
                    .fetch_one($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => read!(pool, "SELECT value FROM json_each($5)"),
            Self::Postgres(pool) => {
                read!(pool, "SELECT json_array_elements_text(CAST($5 AS JSON))")
            }
        }
    }
}
