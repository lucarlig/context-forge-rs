// SPDX-License-Identifier: Apache-2.0

use super::{CatalogScope, Database, TeamVisibility, visible_team_ids};
use crate::database::observed;

pub(crate) struct CatalogEntryFilters<'a> {
    pub(crate) include_inactive: bool,
    pub(crate) visibility: Option<&'a str>,
    pub(crate) team: Option<&'a str>,
    pub(crate) gateway: Option<&'a str>,
    pub(crate) after: Option<(&'a str, &'a str)>,
    pub(crate) limit: i64,
    pub(crate) offset: i64,
    pub(crate) tags: &'a [String],
}

impl CatalogEntryFilters<'_> {
    pub(crate) fn associated(include_inactive: bool) -> Self {
        Self {
            include_inactive,
            visibility: None,
            team: None,
            gateway: None,
            after: None,
            limit: i64::MAX,
            offset: 0,
            tags: &[],
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ManagedCatalog {
    Tools,
    Servers,
    Resources,
    Prompts,
    Gateways,
}

impl ManagedCatalog {
    pub(crate) const ALL: [Self; 5] = [
        Self::Tools,
        Self::Servers,
        Self::Resources,
        Self::Prompts,
        Self::Gateways,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Tools => "tools",
            Self::Servers => "servers",
            Self::Resources => "resources",
            Self::Prompts => "prompts",
            Self::Gateways => "gateways",
        }
    }
}

macro_rules! managed_visibility {
    ($alias:literal, $admin:literal, $owns:literal, $email:literal, $teams:literal) => {
        concat!(
            "(",
            $alias,
            ".visibility = 'public'
                OR (",
            $alias,
            ".visibility = 'team' AND (",
            $admin,
            " OR ",
            $alias,
            ".team_id IN (SELECT id FROM ",
            $teams,
            ")))
                OR (",
            $alias,
            ".visibility = 'private' AND ",
            $owns,
            " AND ",
            $alias,
            ".owner_email = ",
            $email,
            "))"
        )
    };
}

impl Database {
    pub(crate) async fn managed_catalog_count(
        &self,
        kind: ManagedCatalog,
        scope: CatalogScope<'_>,
        inactive: bool,
        team: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        macro_rules! count_query {
            ($table:literal, $teams:literal) => {
                concat!(
                    "WITH visible_teams(id) AS (",
                    $teams,
                    ")
                     SELECT COUNT(*) FROM ",
                    $table,
                    " r WHERE ($1 OR r.enabled)
                        AND (CAST($2 AS TEXT) IS NULL OR r.team_id = $2) AND ",
                    managed_visibility!("r", "$3", "$4", "$5", "visible_teams"),
                )
            };
        }
        macro_rules! read {
            ($pool:ident, $teams:literal) => {{
                let sql = match kind {
                    ManagedCatalog::Tools => count_query!("tools", $teams),
                    ManagedCatalog::Servers => count_query!("servers", $teams),
                    ManagedCatalog::Resources => count_query!("resources", $teams),
                    ManagedCatalog::Prompts => count_query!("prompts", $teams),
                    ManagedCatalog::Gateways => count_query!("gateways", $teams),
                };
                sqlx::query_scalar(sql)
                    .bind(inactive)
                    .bind(team)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(scope.email)
                    .bind(teams)
                    .fetch_one(observed($pool))
                    .await
            }};
        }
        match self {
            Self::Sqlite(pool) => read!(pool, "SELECT value FROM json_each($6)"),
            Self::Postgres(pool) => {
                read!(pool, "SELECT json_array_elements_text(CAST($6 AS JSON))")
            }
        }
    }
}

macro_rules! scoped_catalog_entries {
    ($select:expr, $predicate:literal, $teams:literal, $date:literal, $tag_filter:literal, $tags:literal, $entity_tag:literal) => {
        concat!(
            "WITH visible_teams(id) AS (",
            $teams,
            "), requested_tags(id) AS (",
            $tag_filter,
            ") ",
            $select,
            " WHERE ",
            $predicate,
            "
                AND ($1 OR r.enabled)
                AND (CAST($2 AS TEXT) IS NULL OR r.visibility = $2)
                AND (CAST($3 AS TEXT) IS NULL OR r.team_id = $3)
                AND (CAST($4 AS TEXT) IS NULL OR r.gateway_id = $4
                     OR (LOWER($4) = 'null' AND r.gateway_id IS NULL))
                AND (CAST($5 AS TEXT) IS NULL OR r.created_at < ",
            $date,
            " OR (r.created_at = ",
            $date,
            " AND r.id < $6))
                AND ",
            managed_visibility!("r", "$9", "$10", "$8", "visible_teams"),
            "
                AND (NOT EXISTS (SELECT 1 FROM requested_tags) OR EXISTS (
                    SELECT 1 FROM ",
            $tags,
            " WHERE (",
            $entity_tag,
            ") IN (SELECT id FROM requested_tags)
                ))
              ORDER BY r.created_at DESC, r.id DESC LIMIT $7 OFFSET $13"
        )
    };
}

macro_rules! fetch_catalog_entries {
    ($db:expr, $row:ty, $scope:expr, $filter:expr, $select:expr, $predicate:literal $(, $additional_binding:expr)*) => {{
        use super::entry_filters::{managed_visibility, scoped_catalog_entries};
        let scope = $scope;
        let filter = $filter;
        let teams = visible_team_ids(scope)?;
        let tags = serde_json::to_string(filter.tags).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        let (after_time, after_id) = filter.after.unzip();
        macro_rules! read {
            ($pool:ident, $query:expr) => {
                sqlx::query_as::<_, $row>($query)
                    .bind(filter.include_inactive).bind(filter.visibility).bind(filter.team).bind(filter.gateway)
                    .bind(after_time).bind(after_id).bind(filter.limit).bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin).bind(scope.can_own())
                    .bind(teams).bind(tags)
                    .bind(filter.offset)
                    $(.bind($additional_binding))*
                    .fetch_all(observed($pool)).await
            };
        }
        match $db {
            Database::Sqlite(pool) => read!(pool, scoped_catalog_entries!(
                $select, $predicate,
                "SELECT value FROM json_each($11)", "$5", "SELECT value FROM json_each($12)",
                "json_each(CASE WHEN json_valid(r.tags) THEN r.tags ELSE '[]' END) AS tag",
                "CASE WHEN tag.type = 'object' THEN json_extract(tag.value, '$.id')
                      WHEN tag.type = 'text' THEN tag.value END"
            )),
            Database::Postgres(pool) => read!(pool, scoped_catalog_entries!(
                $select, $predicate,
                "SELECT json_array_elements_text(CAST($11 AS JSON))", "CAST(CAST($5 AS TEXT) AS TIMESTAMPTZ)",
                "SELECT json_array_elements_text(CAST($12 AS JSON))",
                "json_array_elements(CASE WHEN json_typeof(CAST(r.tags AS JSON)) = 'array'
                    THEN CAST(r.tags AS JSON) ELSE '[]'::JSON END) AS tag(value)",
                "CASE WHEN json_typeof(tag.value) = 'object' THEN tag.value ->> 'id'
                      WHEN json_typeof(tag.value) = 'string' THEN tag.value #>> '{}' END"
            )),
        }
    }};
}

pub(crate) use managed_visibility;
pub(super) use {fetch_catalog_entries, scoped_catalog_entries};
