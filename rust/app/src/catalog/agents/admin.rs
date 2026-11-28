// SPDX-License-Identifier: Apache-2.0

use super::{projection, *};

pub(crate) struct AdminAgentFilters<'a> {
    pub(crate) include_inactive: bool,
    pub(crate) team: Option<&'a str>,
    pub(crate) text: &'a str,
    pub(crate) tag_groups: &'a [Vec<String>],
}

macro_rules! agent_predicate {
    ($teams:literal, $groups:literal, $terms:literal, $tags:literal, $term:literal, $tag:literal) => {
        concat!(
            " WHERE ($1 OR r.enabled)
              AND (CAST($2 AS TEXT) IS NULL OR r.team_id = $2) AND ",
            managed_visibility!("r", "$3", "$4", "$5", $teams),
            "
              AND ($7='' OR LOWER(r.id) LIKE '%' || $7 || '%' ESCAPE '\\'
                   OR LOWER(r.name) LIKE '%' || $7 || '%' ESCAPE '\\'
                   OR LOWER(r.endpoint_url) LIKE '%' || $7 || '%' ESCAPE '\\'
                   OR LOWER(r.description) LIKE '%' || $7 || '%' ESCAPE '\\')
              AND (CAST($8 AS TEXT)='[]' OR EXISTS (SELECT 1 FROM ",
            $groups,
            " WHERE NOT EXISTS (SELECT 1 FROM ",
            $terms,
            " WHERE NOT EXISTS (SELECT 1 FROM ",
            $tags,
            " WHERE ",
            $tag,
            " = ",
            $term,
            "))))"
        )
    };
}

macro_rules! sql_query {
    ($selector:expr, $order:expr, sqlite) => {
        concat!(
            $selector,
            agent_predicate!(
                "(SELECT value AS id FROM json_each($6))",
                "json_each($8) AS matched_group",
                "json_each(matched_group.value) AS term",
                "json_each(CASE WHEN json_valid(r.tags) THEN r.tags ELSE '[]' END) AS tag",
                "term.value",
                "CASE WHEN tag.type = 'object' THEN json_extract(tag.value, '$.id')
                  WHEN tag.type = 'text' THEN tag.value END"
            ),
            $order
        )
    };
    ($selector:expr, $order:expr, postgres) => {
        concat!(
            $selector,
            agent_predicate!(
                "json_array_elements_text(CAST($6 AS JSON)) AS visible_teams(id)",
                "json_array_elements(CAST($8 AS JSON)) AS matched_group(value)",
                "json_array_elements_text(matched_group.value) AS term(value)",
                "json_array_elements(CASE WHEN json_typeof(CAST(r.tags AS JSON)) = 'array'
                THEN CAST(r.tags AS JSON) ELSE '[]'::JSON END) AS tag(value)",
                "term.value",
                "CASE WHEN json_typeof(tag.value) = 'object' THEN tag.value ->> 'id'
                  WHEN json_typeof(tag.value) = 'string' THEN tag.value #>> '{}' END"
            ),
            $order
        )
    };
}

macro_rules! read_agents {
    ($db:expr, $query:ident, $selector:expr, $order:expr, $scope:expr, $filter:expr,
     $fetch:ident $(, $binding:expr)*) => {{
        let scope = $scope;
        let filter = $filter;
        let teams = visible_team_ids(scope)?;
        let groups = serde_json::to_string(filter.tag_groups)
            .map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        let text = filter.text.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        macro_rules! read {
            ($pool:ident, $backend:ident) => {
                sqlx::$query(sql_query!($selector, $order, $backend))
                    .bind(filter.include_inactive)
                    .bind(filter.team)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(scope.email)
                    .bind(&teams)
                    .bind(&text)
                    .bind(&groups)
                    $(.bind($binding))*
                    .$fetch($pool).await
            };
        }
        match $db {
            Database::Sqlite(pool) => read!(pool, sqlite),
            Database::Postgres(pool) => read!(pool, postgres),
        }
    }};
}

impl Database {
    pub(crate) async fn admin_agent_count(
        &self,
        scope: CatalogScope<'_>,
        filters: &AdminAgentFilters<'_>,
    ) -> Result<i64, sqlx::Error> {
        read_agents!(
            self,
            query_scalar,
            "SELECT COUNT(*) FROM a2a_agents r",
            "",
            scope,
            filters,
            fetch_one
        )
    }

    pub(crate) async fn admin_agents(
        &self,
        scope: CatalogScope<'_>,
        filters: &AdminAgentFilters<'_>,
        size: i64,
        offset: i64,
        ranked: bool,
    ) -> Result<Vec<AgentRecord>, sqlx::Error> {
        read_agents!(
            self, query_as, projection!(),
            " ORDER BY CASE WHEN $9 THEN CASE
                   WHEN LOWER(r.name) LIKE $7 || '%' ESCAPE '\\'
                       OR LOWER(r.endpoint_url) LIKE $7 || '%' ESCAPE '\\' THEN 0 ELSE 1 END END,
               CASE WHEN $9 THEN LOWER(r.name) END, r.created_at DESC,r.id DESC LIMIT $10 OFFSET $11",
            scope, filters, fetch_all, ranked, size, offset
        )
    }

    pub(crate) async fn admin_agent_ids(
        &self,
        scope: CatalogScope<'_>,
        filters: &AdminAgentFilters<'_>,
    ) -> Result<Vec<String>, sqlx::Error> {
        read_agents!(
            self,
            query_scalar,
            "SELECT r.id FROM a2a_agents r",
            " ORDER BY r.id",
            scope,
            filters,
            fetch_all
        )
    }
}
