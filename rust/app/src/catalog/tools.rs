// SPDX-License-Identifier: Apache-2.0

use super::entry_filters::fetch_catalog_entries;
use super::*;

#[derive(Clone, Default, Serialize, sqlx::FromRow)]
pub(crate) struct ToolRecord {
    pub(crate) id: String,
    pub(crate) original_name: String,
    pub(crate) original_description: Option<String>,
    pub(crate) custom_name: String,
    pub(crate) custom_name_slug: String,
    #[serde(rename = "displayName")]
    pub(crate) display_name: Option<String>,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) integration_type: String,
    pub(crate) request_type: String,
    pub(crate) jsonpath_filter: String,
    pub(crate) gateway_id: Option<String>,
    pub(crate) gateway_slug: String,
    #[serde(skip)]
    pub(crate) gateway_name: Option<String>,
    pub(crate) grpc_service_id: Option<String>,
    pub(crate) enabled: bool,
    pub(crate) reachable: bool,
    pub(crate) deprecated: bool,
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
    pub(crate) base_url: Option<String>,
    pub(crate) path_template: Option<String>,
    pub(crate) timeout_ms: Option<i32>,
    pub(crate) expose_passthrough: bool,
    pub(crate) tool_validation_policy: Option<String>,
    pub(crate) validation_refusal: Option<String>,
    #[serde(skip)]
    pub(crate) tags: String,
    #[serde(skip)]
    pub(crate) headers: Option<String>,
    #[serde(skip)]
    pub(crate) input_schema: String,
    #[serde(skip)]
    pub(crate) output_schema: Option<String>,
    #[serde(skip)]
    pub(crate) annotations: Option<String>,
    #[serde(skip)]
    pub(crate) extension_metadata: Option<String>,
    #[serde(skip)]
    pub(crate) allowlist: Option<String>,
    #[serde(skip)]
    pub(crate) query_mapping: Option<String>,
    #[serde(skip)]
    pub(crate) header_mapping: Option<String>,
    #[serde(skip)]
    pub(crate) plugin_chain_pre: Option<String>,
    #[serde(skip)]
    pub(crate) plugin_chain_post: Option<String>,
    #[serde(skip)]
    pub(crate) sigv4_config: Option<String>,
    #[serde(skip)]
    pub(crate) auth_type: Option<String>,
    #[serde(skip)]
    pub(crate) auth_value: Option<String>,
}

macro_rules! tool_select {
    () => {
        "SELECT r.id, r.original_name, r.original_description, r.custom_name, r.custom_name_slug,
            r.display_name,r.name,r.description,r.title,r.url,r.integration_type,r.request_type,r.jsonpath_filter,
            r.gateway_id, COALESCE(g.slug,'') AS gateway_slug, g.name AS gateway_name,
            r.grpc_service_id, r.enabled, r.reachable, r.deprecated,
            CAST(r.created_at AS TEXT) AS created_at, CAST(r.updated_at AS TEXT) AS updated_at,
            r.created_by,r.created_from_ip,r.created_via,r.created_user_agent,r.modified_by,
            r.modified_from_ip,r.modified_via,r.modified_user_agent,r.import_batch_id,r.federation_source,
            r.version,r.team_id,e.name AS team,r.owner_email,r.visibility,r.base_url,r.path_template,r.timeout_ms,
            r.expose_passthrough,r.tool_validation_policy,r.validation_refusal,
            COALESCE(CAST(r.tags AS TEXT),'[]') AS tags, CAST(r.headers AS TEXT) AS headers,
            CAST(r.input_schema AS TEXT) AS input_schema, CAST(r.output_schema AS TEXT) AS output_schema,
            CAST(r.annotations AS TEXT) AS annotations, CAST(r.extension_metadata AS TEXT) AS extension_metadata,
            CAST(r.allowlist AS TEXT) AS allowlist, CAST(r.query_mapping AS TEXT) AS query_mapping,
            CAST(r.header_mapping AS TEXT) AS header_mapping, CAST(r.plugin_chain_pre AS TEXT) AS plugin_chain_pre,
            CAST(r.plugin_chain_post AS TEXT) AS plugin_chain_post, CAST(r.sigv4_config AS TEXT) AS sigv4_config,
            r.auth_type,r.auth_value
         FROM tools r LEFT JOIN gateways g ON g.id = r.gateway_id
            LEFT JOIN email_teams e ON e.id = r.team_id AND e.is_active"
    };
}

const TOOL_BY_ID: &str = concat!(tool_select!(), " WHERE r.id=$1");

impl Database {
    pub(crate) async fn managed_tool(&self, id: &str) -> Result<Option<ToolRecord>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(TOOL_BY_ID)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(TOOL_BY_ID)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
        }
    }

    pub(crate) async fn managed_tools(
        &self,
        scope: CatalogScope<'_>,
        filter: CatalogEntryFilters<'_>,
    ) -> Result<Vec<ToolRecord>, sqlx::Error> {
        fetch_catalog_entries!(self, ToolRecord, scope, filter, tool_select!(), "TRUE")
    }

    pub(crate) async fn managed_server_tools(
        &self,
        scope: CatalogScope<'_>,
        server: &str,
        inactive: bool,
    ) -> Result<Vec<ToolRecord>, sqlx::Error> {
        fetch_catalog_entries!(
            self,
            ToolRecord,
            scope,
            CatalogEntryFilters::associated(inactive),
            tool_select!(),
            "EXISTS(SELECT 1 FROM server_tool_association a WHERE a.server_id=$14 AND a.tool_id=r.id)",
            server
        )
    }

    pub(crate) async fn tool_preview_candidates(
        &self,
        scope: CatalogScope<'_>,
        name: &str,
        server: Option<&str>,
    ) -> Result<Vec<ToolRecord>, sqlx::Error> {
        fetch_catalog_entries!(
            self,
            ToolRecord,
            scope,
            CatalogEntryFilters {
                include_inactive: false,
                visibility: None,
                team: None,
                gateway: None,
                after: None,
                limit: 2,
                offset: 0,
                tags: &[],
            },
            tool_select!(),
            "r.name=$14 AND (CAST($15 AS TEXT) IS NULL OR EXISTS (
                SELECT 1 FROM server_tool_association a WHERE a.tool_id=r.id AND a.server_id=$15
            )) AND (r.gateway_id IS NULL OR (g.enabled AND g.status='active' AND
                (g.visibility='public'
                 OR (g.visibility='team' AND ($9 OR g.team_id IN (SELECT id FROM visible_teams)))
                 OR (g.visibility='private' AND $10 AND g.owner_email=$8))))",
            name,
            server
        )
    }
}

mod write;
pub(crate) use write::ToolWriteError;
