// SPDX-License-Identifier: Apache-2.0

pub(crate) struct CatalogEntryFilters<'a> {
    pub(crate) include_inactive: bool,
    pub(crate) visibility: Option<&'a str>,
    pub(crate) team: Option<&'a str>,
    pub(crate) gateway: Option<&'a str>,
    pub(crate) after: Option<(&'a str, &'a str)>,
    pub(crate) limit: i64,
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
            tags: &[],
        }
    }
}

macro_rules! scoped_catalog_entries {
    ($select:expr, $predicate:literal, $teams:literal, $date:literal, $tag_filter:literal, $tags:literal, $entity_tag:literal) => {
        concat!(
            "WITH visible_teams(id) AS (", $teams, "), requested_tags(id) AS (", $tag_filter, ") ",
            $select,
            " WHERE ", $predicate, "
                AND ($1 OR r.enabled)
                AND (CAST($2 AS TEXT) IS NULL OR r.visibility = $2)
                AND (CAST($3 AS TEXT) IS NULL OR r.team_id = $3)
                AND (CAST($4 AS TEXT) IS NULL OR r.gateway_id = $4
                     OR (LOWER($4) = 'null' AND r.gateway_id IS NULL))
                AND (CAST($5 AS TEXT) IS NULL OR r.created_at < ", $date,
                " OR (r.created_at = ", $date, " AND r.id < $6))
                AND (r.visibility = 'public'
                  OR (r.visibility = 'team' AND ($9 OR r.team_id IN (SELECT id FROM visible_teams)))
                  OR (r.visibility = 'private' AND $10 AND r.owner_email = $8))
                AND (NOT EXISTS (SELECT 1 FROM requested_tags) OR EXISTS (
                    SELECT 1 FROM ", $tags, " WHERE (", $entity_tag, ") IN (SELECT id FROM requested_tags)
                ))
              ORDER BY r.created_at DESC, r.id DESC LIMIT $7"
        )
    };
}

macro_rules! fetch_catalog_entries {
    ($db:expr, $row:ty, $scope:expr, $filter:expr, $select:expr, $predicate:literal $(, $additional_binding:expr)*) => {{
        use super::entry_filters::scoped_catalog_entries;
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
                    $(.bind($additional_binding))*
                    .fetch_all($pool).await
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

pub(super) use {fetch_catalog_entries, scoped_catalog_entries};
