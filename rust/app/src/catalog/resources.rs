// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Clone, Default, Serialize, sqlx::FromRow)]
pub(crate) struct ResourceRecord {
    pub(crate) id: String,
    pub(crate) uri: String,
    pub(crate) name: String,
    pub(crate) original_name: Option<String>,
    pub(crate) custom_name_slug: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) mime_type: Option<String>,
    pub(crate) uri_template: Option<String>,
    pub(crate) gateway_id: Option<String>,
    pub(crate) size: Option<i32>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) enabled: bool,
    #[serde(skip)]
    pub(crate) tags: String,
    #[serde(skip)]
    pub(crate) extension_metadata: Option<String>,
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
}

pub(crate) struct ResourceFilters<'a> {
    pub(crate) templates: bool,
    pub(crate) include_inactive: bool,
    pub(crate) visibility: Option<&'a str>,
    pub(crate) team: Option<&'a str>,
    pub(crate) gateway: Option<&'a str>,
    pub(crate) after: Option<(&'a str, &'a str)>,
    pub(crate) limit: i64,
    pub(crate) tags: &'a [String],
}

macro_rules! resource_select {
    () => {
        "SELECT r.id, r.uri, r.name, r.original_name, r.custom_name_slug, r.description,
            r.title, r.mime_type, r.uri_template, r.gateway_id, r.size,
            CAST(r.created_at AS TEXT) AS created_at, CAST(r.updated_at AS TEXT) AS updated_at,
            COALESCE(r.enabled, FALSE) AS enabled, CAST(r.tags AS TEXT) AS tags,
            CAST(r.extension_metadata AS TEXT) AS extension_metadata,
            r.created_by, r.created_from_ip, r.created_via, r.created_user_agent,
            r.modified_by, r.modified_from_ip, r.modified_via, r.modified_user_agent,
            r.import_batch_id, r.federation_source, r.version, r.team_id, e.name AS team,
            r.owner_email, r.visibility
         FROM resources r LEFT JOIN email_teams e ON e.id = r.team_id"
    };
}

macro_rules! list_resources {
    ($teams:literal, $date:literal, $tag_filter:literal, $tags:literal, $entity_tag:literal) => {
        concat!(
            "WITH visible_teams(id) AS (", $teams, "), requested_tags(id) AS (", $tag_filter, ") ",
            resource_select!(),
            " WHERE (r.uri_template IS NOT NULL) = $13
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

const RESOURCE_BY_ID: &str = concat!(resource_select!(), " WHERE r.id = $1");

mod write;
pub(crate) use write::ResourceWriteError;

impl Database {
    pub(crate) async fn managed_resource(
        &self,
        id: &str,
    ) -> Result<Option<ResourceRecord>, sqlx::Error> {
        macro_rules! read {
            ($pool:ident) => {
                sqlx::query_as::<_, ResourceRecord>(RESOURCE_BY_ID)
                    .bind(id)
                    .fetch_optional($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => read!(pool),
            Self::Postgres(pool) => read!(pool),
        }
    }

    pub(crate) async fn managed_resources(
        &self,
        scope: CatalogScope<'_>,
        filter: ResourceFilters<'_>,
    ) -> Result<Vec<ResourceRecord>, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        let tags = serde_json::to_string(filter.tags)
            .map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        let (after_time, after_id) = filter.after.unzip();
        macro_rules! read {
            ($pool:ident, $query:expr) => {
                sqlx::query_as::<_, ResourceRecord>($query)
                    .bind(filter.include_inactive)
                    .bind(filter.visibility)
                    .bind(filter.team)
                    .bind(filter.gateway)
                    .bind(after_time)
                    .bind(after_id)
                    .bind(filter.limit)
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(teams)
                    .bind(tags)
                    .bind(filter.templates)
                    .fetch_all($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => read!(
                pool,
                list_resources!(
                    "SELECT value FROM json_each($11)",
                    "$5",
                    "SELECT value FROM json_each($12)",
                    "json_each(CASE WHEN json_valid(r.tags) THEN r.tags ELSE '[]' END) AS tag",
                    "CASE WHEN tag.type = 'object' THEN json_extract(tag.value, '$.id')
                      WHEN tag.type = 'text' THEN tag.value END"
                )
            ),
            Self::Postgres(pool) => read!(
                pool,
                list_resources!(
                    "SELECT json_array_elements_text(CAST($11 AS JSON))",
                    "CAST(CAST($5 AS TEXT) AS TIMESTAMPTZ)",
                    "SELECT json_array_elements_text(CAST($12 AS JSON))",
                    "json_array_elements(CASE WHEN json_typeof(CAST(r.tags AS JSON)) = 'array'
                    THEN CAST(r.tags AS JSON) ELSE '[]'::JSON END) AS tag(value)",
                    "CASE WHEN json_typeof(tag.value) = 'object' THEN tag.value ->> 'id'
                      WHEN json_typeof(tag.value) = 'string' THEN tag.value #>> '{}' END"
                )
            ),
        }
    }
}
