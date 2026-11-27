// SPDX-License-Identifier: Apache-2.0

use super::entry_filters::fetch_catalog_entries;
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
        filter: CatalogEntryFilters<'_>,
        templates: Option<bool>,
    ) -> Result<Vec<ResourceRecord>, sqlx::Error> {
        fetch_catalog_entries!(
            self,
            ResourceRecord,
            scope,
            filter,
            resource_select!(),
            "(CAST($14 AS BOOLEAN) IS NULL OR (r.uri_template IS NOT NULL) = $14)",
            templates
        )
    }

    pub(crate) async fn managed_server_resources(
        &self,
        scope: CatalogScope<'_>,
        server: &str,
        inactive: bool,
    ) -> Result<Vec<ResourceRecord>, sqlx::Error> {
        fetch_catalog_entries!(
            self,
            ResourceRecord,
            scope,
            CatalogEntryFilters::associated(inactive),
            resource_select!(),
            "EXISTS(SELECT 1 FROM server_resource_association a WHERE a.server_id=$14 AND a.resource_id=r.id)",
            server
        )
    }
}
