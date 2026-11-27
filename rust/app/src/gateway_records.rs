// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::{
    auth::TeamVisibility,
    catalog::{CatalogScope, visible_team_ids},
    database::Database,
};

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GatewayRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) url: String,
    pub(crate) description: Option<String>,
    pub(crate) tool_validation_policy: Option<String>,
    pub(crate) transport: String,
    #[serde(skip)]
    pub(crate) capabilities: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) enabled: bool,
    pub(crate) last_seen: Option<String>,
    pub(crate) reachable: bool,
    pub(crate) status: String,
    pub(crate) status_message: Option<String>,
    pub(crate) registration_attempts: i32,
    pub(crate) next_retry_at: Option<String>,
    pub(crate) last_error: Option<String>,
    pub(crate) lifecycle_claimed_by: Option<String>,
    pub(crate) lifecycle_claimed_at: Option<String>,
    pub(crate) lifecycle_claim_expires_at: Option<String>,
    pub(crate) auth_type: Option<String>,
    #[serde(skip)]
    pub(crate) auth_value: Option<String>,
    #[serde(skip)]
    pub(crate) auth_query_params: Option<String>,
    #[serde(skip)]
    pub(crate) oauth_config: Option<String>,
    #[serde(skip)]
    pub(crate) sigv4_config: Option<String>,
    #[serde(skip)]
    pub(crate) passthrough_headers: Option<String>,
    #[serde(skip)]
    pub(crate) tags: String,
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
    pub(crate) version: i32,
    pub(crate) team_id: Option<String>,
    pub(crate) team: Option<String>,
    pub(crate) owner_email: Option<String>,
    pub(crate) visibility: String,
    pub(crate) ca_certificate: Option<String>,
    pub(crate) ca_certificate_sig: Option<String>,
    pub(crate) signing_algorithm: Option<String>,
    pub(crate) client_cert: Option<String>,
    #[serde(skip)]
    pub(crate) has_client_key: bool,
    pub(crate) refresh_interval_seconds: Option<i32>,
    pub(crate) last_refresh_at: Option<String>,
    pub(crate) gateway_mode: String,
    #[serde(skip)]
    pub(crate) identity_propagation: Option<String>,
    pub(crate) tool_count: i64,
    pub(crate) resource_count: i64,
    pub(crate) prompt_count: i64,
}

pub(crate) struct GatewayList<'a> {
    pub(crate) include_inactive: bool,
    pub(crate) visibility: Option<&'a str>,
    pub(crate) team: Option<&'a str>,
    pub(crate) after: Option<(&'a str, &'a str)>,
    pub(crate) limit: i64,
}

macro_rules! gateway_select {
    () => {
        "SELECT g.id, g.name, g.slug, g.url, g.description, g.tool_validation_policy, g.transport,
           CAST(g.capabilities AS TEXT) AS capabilities, CAST(g.created_at AS TEXT) AS created_at,
           CAST(g.updated_at AS TEXT) AS updated_at, g.enabled, CAST(g.last_seen AS TEXT) AS last_seen,
           g.reachable, g.status, g.status_message, g.registration_attempts,
           CAST(g.next_retry_at AS TEXT) AS next_retry_at, g.last_error, g.lifecycle_claimed_by,
           CAST(g.lifecycle_claimed_at AS TEXT) AS lifecycle_claimed_at,
           CAST(g.lifecycle_claim_expires_at AS TEXT) AS lifecycle_claim_expires_at, g.auth_type,
           CAST(g.auth_value AS TEXT) AS auth_value, CAST(g.auth_query_params AS TEXT) AS auth_query_params,
           CAST(g.oauth_config AS TEXT) AS oauth_config, CAST(g.sigv4_config AS TEXT) AS sigv4_config,
           CAST(g.passthrough_headers AS TEXT) AS passthrough_headers, CAST(g.tags AS TEXT) AS tags,
           g.created_by, g.created_from_ip, g.created_via, g.created_user_agent, g.modified_by,
           g.modified_from_ip, g.modified_via, g.modified_user_agent, g.import_batch_id, g.federation_source,
           g.version, g.team_id, (SELECT name FROM email_teams WHERE id = g.team_id) AS team, g.owner_email,
           g.visibility, g.ca_certificate, g.ca_certificate_sig, g.signing_algorithm, g.client_cert,
           (COALESCE(g.client_key, '') <> '') AS has_client_key,
           g.refresh_interval_seconds, CAST(g.last_refresh_at AS TEXT) AS last_refresh_at,
           g.gateway_mode, CAST(g.identity_propagation AS TEXT) AS identity_propagation,
           (SELECT COUNT(*) FROM tools t WHERE t.gateway_id = g.id) AS tool_count,
           (SELECT COUNT(*) FROM resources r WHERE r.gateway_id = g.id) AS resource_count,
           (SELECT COUNT(*) FROM prompts p WHERE p.gateway_id = g.id) AS prompt_count
         FROM gateways g"
    };
}

macro_rules! list_gateways_query {
    ($teams:literal, $date:literal) => {
        concat!(
            "WITH visible_team_ids(id) AS (", $teams, ") ",
            gateway_select!(),
            " WHERE ($1 OR g.enabled)
                AND (CAST($2 AS TEXT) IS NULL OR g.visibility = $2)
                AND (CAST($3 AS TEXT) IS NULL OR g.team_id = $3)
                AND (CAST($4 AS TEXT) IS NULL OR g.created_at < ", $date,
                " OR (g.created_at = ", $date, " AND g.id < $5))
                AND (g.visibility = 'public'
                     OR (g.visibility = 'team' AND ($8 OR g.team_id IN (SELECT id FROM visible_team_ids)))
                     OR (g.visibility = 'private' AND $9 AND g.owner_email = $7))
              ORDER BY g.created_at DESC, g.id DESC LIMIT $6"
        )
    };
}

const GATEWAY_LOOKUP_QUERY: &str = concat!(
    gateway_select!(),
    " WHERE g.id = $1 OR ((g.name = $1 OR g.slug = $1)
           AND NOT EXISTS (SELECT 1 FROM gateways exact WHERE exact.id = $1))
      ORDER BY g.id"
);

impl Database {
    pub(crate) async fn listed_gateways(
        &self,
        scope: CatalogScope<'_>,
        list: GatewayList<'_>,
    ) -> Result<Vec<GatewayRecord>, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        let (after_date, after_id) = list.after.unzip();
        macro_rules! select {
            ($pool:expr, $teams:literal, $date:literal) => {
                sqlx::query_as::<_, GatewayRecord>(list_gateways_query!($teams, $date))
                    .bind(list.include_inactive)
                    .bind(list.visibility)
                    .bind(list.team)
                    .bind(after_date)
                    .bind(after_id)
                    .bind(list.limit)
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(teams)
                    .fetch_all($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool, "SELECT value FROM json_each($10)", "$4"),
            Self::Postgres(pool) => select!(
                pool,
                "SELECT json_array_elements_text(CAST($10 AS JSON))",
                "CAST(CAST($4 AS TEXT) AS TIMESTAMPTZ)"
            ),
        }
    }

    pub(crate) async fn gateway_records(
        &self,
        key: &str,
    ) -> Result<Vec<GatewayRecord>, sqlx::Error> {
        macro_rules! select {
            ($pool:expr) => {
                sqlx::query_as::<_, GatewayRecord>(GATEWAY_LOOKUP_QUERY)
                    .bind(key)
                    .fetch_all($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool),
            Self::Postgres(pool) => select!(pool),
        }
    }
}
