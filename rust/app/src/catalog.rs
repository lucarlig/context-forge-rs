// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use futures_util::TryStreamExt;
use rmcp::model::CompletionInfo;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    auth::TeamVisibility,
    credentials::PreparedAuth,
    database::Database,
    upstream::{DiscoveredMetadata, UpstreamTransport},
};

mod entry_filters;
mod metrics;
mod prompts;
mod resources;
mod servers;
mod tools;
pub(crate) use entry_filters::CatalogEntryFilters;
pub(crate) use metrics::{ExecutionMetrics, MetricEntity};
pub(crate) use prompts::{PromptRecord, PromptWriteError};
pub(crate) use resources::{ResourceRecord, ResourceWriteError};
pub(crate) use servers::{
    ServerInterfaceInput, ServerLinkUpdate, ServerLinks, ServerRecord, ServerWriteError,
};
pub(crate) use tools::{ToolRecord, ToolWriteError};

pub(crate) const CATALOG_LOCK: &str = "SELECT pg_advisory_xact_lock(1128682067)";

macro_rules! delete_tool_dependencies {
    ($tx:ident, $id:expr, $purge_hourly:expr, $table_exists:expr) => {{
        for (table, statement) in [
            (
                "tool_metrics",
                "DELETE FROM tool_metrics WHERE tool_id = $1",
            ),
            (
                "tool_metrics_hourly",
                "DELETE FROM tool_metrics_hourly WHERE tool_id = $1",
            ),
        ] {
            if (table == "tool_metrics" || $purge_hourly)
                && sqlx::query_scalar::<_, bool>($table_exists)
                    .bind(table)
                    .fetch_one(&mut *$tx)
                    .await?
            {
                sqlx::query(statement).bind($id).execute(&mut *$tx).await?;
            }
        }
        sqlx::query("DELETE FROM server_tool_association WHERE tool_id = $1")
            .bind($id)
            .execute(&mut *$tx)
            .await?;
    }};
}

pub(crate) use delete_tool_dependencies;

#[derive(Clone, Copy)]
pub struct CatalogScope<'a> {
    pub email: Option<&'a str>,
    pub visibility: &'a TeamVisibility,
}

impl CatalogScope<'_> {
    pub(crate) fn can_own(&self) -> bool {
        self.email.is_some() && self.visibility != &TeamVisibility::Public
    }

    pub(crate) fn visible(
        &self,
        visibility: &str,
        team_id: Option<&str>,
        owner_email: Option<&str>,
    ) -> bool {
        match visibility {
            "public" => true,
            "team" => match self.visibility {
                TeamVisibility::Admin => true,
                TeamVisibility::Teams(allowed) => {
                    team_id.is_some_and(|id| allowed.iter().any(|team| team == id))
                }
                TeamVisibility::Public => false,
            },
            "private" => self.can_own() && self.email == owner_email,
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CatalogServer {
    pub id: String,
    pub name: String,
    pub team_id: Option<String>,
    pub enabled: bool,
    pub oauth_enabled: bool,
    pub instructions: Option<String>,
    owner_email: Option<String>,
    visibility: String,
}

impl CatalogServer {
    pub fn is_visible(&self, scope: CatalogScope<'_>) -> bool {
        scope.visible(
            &self.visibility,
            self.team_id.as_deref(),
            self.owner_email.as_deref(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, deserialize_with = "nullable_description")]
    pub description: String,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(
        default = "default_annotations",
        skip_serializing_if = "Option::is_none"
    )]
    pub annotations: Option<Value>,
}

fn nullable_description<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

fn default_annotations() -> Option<Value> {
    Some(Value::Object(Default::default()))
}

#[derive(Clone)]
pub struct CatalogTool {
    pub id: String,
    pub original_name: String,
    pub gateway_id: String,
    pub gateway_name: String,
    pub gateway_url: String,
    pub(crate) gateway_version: Option<i32>,
    pub gateway_mode: String,
    pub gateway_transport: String,
    pub request_type: String,
    pub requires_gateway_policy: bool,
    pub(crate) deprecated: bool,
    pub(crate) reachable: bool,
    pub(crate) needs_upstream_config: bool,
    pub(crate) rest: Option<RestTool>,
    pub(crate) grpc_service_id: Option<String>,
    pub(crate) response_filter: String,
    pub definition: ToolDefinition,
}

#[derive(Clone, sqlx::FromRow)]
pub(crate) struct RestTool {
    pub(crate) http_url: Option<String>,
    pub(crate) headers: Option<String>,
    pub(crate) auth_type: Option<String>,
    pub(crate) auth_value: Option<String>,
    pub(crate) sigv4_config: Option<String>,
    pub(crate) query_mapping: Option<String>,
    pub(crate) header_mapping: Option<String>,
    pub(crate) pending_policy: bool,
}

#[derive(Clone, Copy)]
pub(crate) enum CatalogList {
    Resources,
    Templates,
    Prompts,
}

pub(crate) struct ContentGateway {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) transport: Option<UpstreamTransport>,
    pub(crate) available: bool,
    pub(crate) needs_upstream_config: bool,
}

pub(crate) struct DirectGateway {
    pub(crate) content: ContentGateway,
    pub(crate) revision: String,
    visibility: String,
    team_id: Option<String>,
    owner_email: Option<String>,
}

impl DirectGateway {
    pub(crate) fn is_visible(&self, scope: CatalogScope<'_>) -> bool {
        scope.visible(
            &self.visibility,
            self.team_id.as_deref(),
            self.owner_email.as_deref(),
        )
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) struct ResourceSubscriptionTarget {
    pub(crate) gateway_id: String,
    pub(crate) url: String,
    pub(crate) uri: String,
}

pub(crate) struct ResourceContentRecord {
    pub(crate) id: String,
    pub(crate) uri: String,
    pub(crate) mime: Option<String>,
    pub(crate) text: Option<String>,
    pub(crate) blob: Option<Vec<u8>>,
    pub(crate) gateway: Option<ContentGateway>,
}

enum ResourceLookup<'a> {
    Uri(&'a str),
    Template(&'a str),
    Id(&'a str),
    Templates,
}

pub(crate) struct PromptContentRecord {
    pub(crate) original_name: String,
    pub(crate) description: Option<String>,
    pub(crate) template: Option<String>,
    pub(crate) argument_schema: Option<Value>,
    pub(crate) gateway: Option<ContentGateway>,
}

impl CatalogList {
    pub(crate) fn method(self) -> &'static str {
        match self {
            Self::Resources => "resources/list",
            Self::Templates => "resources/templates/list",
            Self::Prompts => "prompts/list",
        }
    }

    pub(crate) fn result_key(self) -> &'static str {
        match self {
            Self::Resources => "resources",
            Self::Templates => "resourceTemplates",
            Self::Prompts => "prompts",
        }
    }

    pub(crate) fn permission(self) -> &'static str {
        match self {
            Self::Resources | Self::Templates => "resources.read",
            Self::Prompts => "prompts.read",
        }
    }
}

pub struct GatewayRegistration<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub slug: &'a str,
    pub url: &'a str,
    pub transport: UpstreamTransport,
    pub description: Option<&'a str>,
    pub capabilities: &'a Value,
    pub visibility: &'a str,
    pub team_id: Option<&'a str>,
    pub owner_email: &'a str,
    pub tags: &'a [String],
}

#[derive(Clone, Copy, Default)]
pub(crate) enum GatewayMode {
    #[default]
    Cache,
    DirectProxy,
}

impl GatewayMode {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::DirectProxy => "direct_proxy",
        }
    }
}

#[derive(Default)]
pub(crate) struct RegistrationOptions<'a> {
    pub(crate) auth: Option<&'a PreparedAuth<'a>>,
    pub(crate) passthrough_headers: Option<&'a [String]>,
    pub(crate) identity: Option<&'a Value>,
    pub(crate) mode: GatewayMode,
    pub(crate) one_time_auth: bool,
    pub(crate) pending: bool,
    pub(crate) refresh_interval_seconds: Option<i32>,
    pub(crate) tls: RegisteredTls<'a>,
    pub(crate) created_from_ip: Option<&'a str>,
    pub(crate) created_user_agent: Option<&'a str>,
    pub(crate) created_via: Option<&'a str>,
    pub(crate) import_batch_id: Option<&'a str>,
}

#[derive(Default)]
pub(crate) struct RegisteredTls<'a> {
    pub(crate) ca_certificate: Option<&'a str>,
    pub(crate) ca_certificate_sig: Option<&'a str>,
    pub(crate) signing_algorithm: Option<&'a str>,
    pub(crate) client_cert: Option<&'a str>,
    pub(crate) client_key: Option<&'a str>,
}

pub struct RegisteredTool<'a> {
    pub id: &'a str,
    pub slug: &'a str,
    pub name: &'a str,
    pub definition: &'a ToolDefinition,
}

pub(crate) struct ResourceRegistration<'a> {
    pub(crate) uri: &'a str,
    pub(crate) template: Option<&'a str>,
    pub(crate) name: &'a str,
    pub(crate) title: Option<&'a str>,
    pub(crate) description: Option<&'a str>,
    pub(crate) mime: &'a str,
    pub(crate) size: Option<i32>,
}

pub(crate) fn resource_registrations(
    metadata: &DiscoveredMetadata,
) -> impl Iterator<Item = ResourceRegistration<'_>> {
    let resources = metadata.resources.iter().map(|item| ResourceRegistration {
        uri: &item.uri,
        template: None,
        name: &item.name,
        title: item.title.as_deref(),
        description: item.description.as_deref(),
        mime: item.mime_type.as_deref().unwrap_or("text/plain"),
        size: item.size.and_then(|size| i32::try_from(size).ok()),
    });
    let templates = metadata.templates.iter().map(|item| ResourceRegistration {
        uri: &item.uri_template,
        template: Some(&item.uri_template),
        name: &item.name,
        title: item.title.as_deref(),
        description: item.description.as_deref(),
        mime: item.mime_type.as_deref().unwrap_or("text/plain"),
        size: None,
    });
    resources.chain(templates)
}

pub(crate) const INSERT_RESOURCE: &str = "INSERT INTO resources (
    id, uri, uri_template, name, original_name, custom_name_slug, title, description,
    mime_type, size, gateway_id, owner_email, team_id, visibility,
    enabled, tags, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
        TRUE,'[]',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)";

#[derive(Debug, Error)]
pub enum RegistrationError {
    #[error("an MCP server with the same name already exists")]
    NameConflict,
    #[error("an MCP server with the same URL already exists")]
    UrlConflict,
    #[error("gateway tool name conflicts with an existing tool")]
    ToolNameConflict,
    #[error("{0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

type ServerRow = (
    String,
    String,
    Option<String>,
    bool,
    bool,
    Option<String>,
    String,
    Option<String>,
);
#[derive(sqlx::FromRow)]
struct ToolRow {
    id: String,
    original_name: String,
    gateway_id: String,
    gateway_name: String,
    gateway_url: String,
    gateway_version: Option<i32>,
    gateway_mode: String,
    gateway_transport: String,
    request_type: String,
    requires_gateway_policy: bool,
    reachable: bool,
    deprecated: bool,
    needs_upstream_config: bool,
    name: String,
    title: Option<String>,
    description: String,
    input_schema: String,
    output_schema: Option<String>,
    annotations: Option<String>,
    integration_type: String,
    grpc_service_id: Option<String>,
    response_filter: String,
    #[sqlx(flatten)]
    rest: RestTool,
}

macro_rules! visible {
    ($table:literal) => {
        concat!(
            "(",
            $table,
            ".visibility = 'public'
                OR (",
            $table,
            ".visibility = 'team' AND ($5 OR ",
            $table,
            ".team_id IN (SELECT id FROM visible_team_ids)))
                OR (",
            $table,
            ".visibility = 'private' AND $6 AND ",
            $table,
            ".owner_email = $4))"
        )
    };
}

macro_rules! non_empty_json {
    ($field:literal) => {
        concat!(
            "COALESCE(TRIM(CAST(",
            $field,
            " AS TEXT)), '') NOT IN ('', 'null', '{}', '[]', '\"\"')"
        )
    };
}

macro_rules! gateway_policy {
    () => {
        concat!(
            "(LOWER(COALESCE(g.auth_type, 'none')) NOT IN ('', 'none', 'one_time_auth', 'basic', 'bearer', 'authheaders', 'query_param', 'sigv4', 'oauth')
            OR (LOWER(COALESCE(g.auth_type, 'none')) IN ('', 'none', 'one_time_auth') AND ",
            non_empty_json!("g.auth_value"),
            ")
            OR (LOWER(COALESCE(g.auth_type, '')) <> 'oauth' AND ",
            non_empty_json!("g.oauth_config"),
            ")
            OR (LOWER(COALESCE(g.auth_type, '')) <> 'query_param' AND ",
            non_empty_json!("g.auth_query_params"),
            ")
            OR (LOWER(COALESCE(g.auth_type, '')) <> 'sigv4' AND ",
            non_empty_json!("g.sigv4_config"),
            ")
            OR ",
            non_empty_json!("g.add_headers"),
            "
            OR ",
            non_empty_json!("g.remove_headers"),
            ")"
        )
    };
}

macro_rules! configured_auth {
    () => {
        "LOWER(COALESCE(g.auth_type, '')) IN ('basic', 'bearer', 'authheaders', 'query_param', 'sigv4', 'oauth')"
    };
}

macro_rules! connection_configured {
    () => {
        concat!(
            "(",
            configured_auth!(),
            " OR ",
            non_empty_json!("g.identity_propagation"),
            " OR COALESCE(g.ca_certificate, '') <> '' OR COALESCE(g.client_cert, '') <> ''
            OR COALESCE(g.client_key, '') <> '')"
        )
    };
}

// Keep configured gateway and tool policies visible to callers before network dispatch.
macro_rules! tool_query {
    ($team_ids:literal) => {
        concat!(
            "WITH visible_team_ids(id) AS (", $team_ids, ")
             SELECT t.id, t.original_name, COALESCE(g.id, '') AS gateway_id,
                COALESCE(g.name, '') AS gateway_name, COALESCE(g.url, '') AS gateway_url,
                g.version AS gateway_version,
                COALESCE(g.gateway_mode, '') AS gateway_mode, COALESCE(g.transport, '') AS gateway_transport,
                t.request_type, t.integration_type,
                CASE WHEN t.integration_type = 'gRPC' THEN t.grpc_service_id END AS grpc_service_id,
                COALESCE(t.jsonpath_filter, '') AS response_filter,
                (
                    ", gateway_policy!(), "
                    OR ((LOWER(COALESCE(t.auth_type, 'none')) NOT IN ('', 'none', 'one_time_auth')
                        OR COALESCE(t.auth_value, '') <> '')
                        AND NOT (", configured_auth!(), "
                            AND LOWER(COALESCE(t.auth_type, '')) = LOWER(COALESCE(g.auth_type, ''))))
                    OR COALESCE(t.tool_validation_policy, '') <> ''
                    OR COALESCE(t.timeout_ms, 0) <> 0
                    OR t.validation_refusal IS NOT NULL
                    OR ", non_empty_json!("t.headers"), "
                    OR ", non_empty_json!("t.sigv4_config"), "
                    OR ", non_empty_json!("t.plugin_chain_pre"), "
                    OR ", non_empty_json!("t.plugin_chain_post"), "
                ) AS requires_gateway_policy,
                ", connection_configured!(), " AS needs_upstream_config,
                (t.reachable AND COALESCE(g.reachable, TRUE)) AS reachable, t.deprecated, t.name, t.title,
                COALESCE(t.description, '') AS description, CAST(t.input_schema AS TEXT) AS input_schema,
                CAST(t.output_schema AS TEXT) AS output_schema, CAST(t.annotations AS TEXT) AS annotations,
                t.url AS http_url,
                CASE WHEN CAST($2 AS TEXT) IS NOT NULL AND t.integration_type = 'REST'
                    THEN CAST(t.headers AS TEXT) END AS headers,
                t.auth_type,
                CASE WHEN CAST($2 AS TEXT) IS NOT NULL AND t.integration_type = 'REST'
                    THEN t.auth_value END AS auth_value,
                CASE WHEN CAST($2 AS TEXT) IS NOT NULL AND t.integration_type = 'REST'
                    THEN CAST(t.sigv4_config AS TEXT) END AS sigv4_config,
                CAST(t.query_mapping AS TEXT) AS query_mapping,
                CAST(t.header_mapping AS TEXT) AS header_mapping,
                (t.validation_refusal IS NOT NULL
                    OR COALESCE(t.tool_validation_policy, '') <> ''
                    OR COALESCE(g.tool_validation_policy, '') <> ''
                    OR ", non_empty_json!("t.plugin_chain_pre"), "
                    OR ", non_empty_json!("t.plugin_chain_post"), ") AS pending_policy
             FROM tools t
             LEFT JOIN gateways g ON g.id = t.gateway_id
             LEFT JOIN grpc_services gs ON gs.id = t.grpc_service_id
             WHERE t.enabled = TRUE AND t.name IS NOT NULL
                AND ((t.integration_type IN ('MCP', 'REST')
                    AND ((t.integration_type = 'REST' AND t.gateway_id IS NULL)
                        OR (g.enabled = TRUE AND g.status = 'active' AND ", visible!("g"), ")))
                    OR ($9 AND t.integration_type = 'gRPC' AND t.gateway_id IS NULL
                        AND gs.enabled = TRUE AND ", visible!("gs"), "))
                AND (CAST($2 AS TEXT) IS NULL OR t.name = $2)
                AND (CAST($3 AS TEXT) IS NULL OR t.id > $3)
                AND ", visible!("t"), "
                AND (CAST($1 AS TEXT) IS NULL OR EXISTS (
                    SELECT 1 FROM server_tool_association a
                    JOIN servers s ON s.id = a.server_id
                    WHERE a.server_id = $1 AND a.tool_id = t.id AND s.enabled = TRUE AND ", visible!("s"), "
                ))
             ORDER BY t.id
             LIMIT $8"
        )
    };
}

macro_rules! metadata_query {
    ($team_ids:literal, $columns:expr, $table:literal, $association:literal, $id:literal, $filter:expr) => {
        concat!(
            "WITH visible_team_ids(id) AS (",
            $team_ids,
            ")
            SELECT item.id, item.name, item.title, item.description, ",
            $columns,
            "
            FROM ",
            $table,
            " item LEFT JOIN gateways g ON g.id = item.gateway_id
            WHERE item.enabled = TRUE AND ",
            $filter,
            "
                AND ",
            visible!("item"),
            "
                AND (item.gateway_id IS NULL OR (g.enabled = TRUE AND g.status = 'active' AND ",
            visible!("g"),
            "))
                AND (CAST($3 AS TEXT) IS NULL OR item.id > $3)
                AND (CAST($1 AS TEXT) IS NULL OR EXISTS (
                    SELECT 1 FROM ",
            $association,
            " a
                    JOIN servers s ON s.id = a.server_id
                    WHERE a.server_id = $1 AND a.",
            $id,
            " = item.id AND s.enabled = TRUE AND ",
            visible!("s"),
            "
                ))
            ORDER BY item.id LIMIT $2"
        )
    };
}

macro_rules! content_gateway_columns {
    () => {
        concat!(
            "g.id, g.url, g.transport, COALESCE(UPPER(g.transport) IN ('SSE', 'STREAMABLEHTTP')
            AND g.gateway_mode IN ('cache', 'direct_proxy') AND NOT ",
            gateway_policy!(),
            ", FALSE), ",
            connection_configured!()
        )
    };
}

macro_rules! resource_content_query {
    ($teams:literal) => {
        metadata_query!($teams,
            concat!("item.uri_template, item.mime_type, CASE WHEN item.gateway_id IS NULL THEN item.text_content END,
            CASE WHEN item.gateway_id IS NULL THEN item.binary_content END, ", content_gateway_columns!(), ", item.uri"),
            "resources", "server_resource_association", "resource_id",
            "((CAST($10 AS TEXT) IS NOT NULL AND item.id = $10)
                OR (CAST($8 AS TEXT) IS NOT NULL AND item.uri = $8)
                OR (CAST($9 AS TEXT) IS NOT NULL AND item.uri_template = $9)
                OR (CAST($8 AS TEXT) IS NULL AND CAST($9 AS TEXT) IS NULL
                    AND CAST($10 AS TEXT) IS NULL AND item.uri_template IS NOT NULL))")
    };
}

macro_rules! prompt_content_query {
    ($teams:literal) => {
        metadata_query!(
            $teams,
            concat!(
                "item.original_name, item.template, CAST(item.argument_schema AS TEXT), ",
                content_gateway_columns!()
            ),
            "prompts",
            "server_prompt_association",
            "prompt_id",
            "(item.name = $8 OR (NOT CAST($9 AS BOOLEAN) AND item.id = $8))"
        )
    };
}

type ResourceContentRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    bool,
    String,
);
type PromptContentRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    bool,
);

type ResourceSubscriptionRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
    Option<String>,
);

macro_rules! catalog_metadata_query {
    ($list:expr, $teams:literal) => {
        match $list {
            CatalogList::Resources => metadata_query!(
                $teams,
                "item.uri, item.mime_type, CAST(item.size AS BIGINT)",
                "resources",
                "server_resource_association",
                "resource_id",
                "item.uri_template IS NULL"
            ),
            CatalogList::Templates => metadata_query!(
                $teams,
                "item.uri_template, item.mime_type, CAST(NULL AS BIGINT)",
                "resources",
                "server_resource_association",
                "resource_id",
                "item.uri_template IS NOT NULL"
            ),
            CatalogList::Prompts => metadata_query!(
                $teams,
                "CAST(item.argument_schema AS TEXT), CAST(NULL AS TEXT), CAST(NULL AS BIGINT)",
                "prompts",
                "server_prompt_association",
                "prompt_id",
                "TRUE"
            ),
        }
    };
}

type MetadataRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
);

const SERVER_QUERY: &str = "
    SELECT id, name, team_id, enabled, oauth_enabled, owner_email, visibility, instructions
    FROM servers WHERE id = $1";

const CONFLICT_QUERY: &str = concat!(
    "SELECT CASE
        WHEN EXISTS (
            SELECT 1 FROM gateways g WHERE g.slug = $1 AND
                ((g.visibility = 'public' AND $3 = 'public')
                  OR (g.visibility = 'team' AND $3 = 'team' AND g.team_id = $4))
        ) THEN 'name'
        WHEN $6 AND EXISTS (
            SELECT 1 FROM gateways g WHERE g.url = $2 AND
                ((g.visibility = 'public' AND $3 = 'public')
                 OR (g.visibility = 'team' AND $3 = 'team' AND g.team_id = $4)
                 OR (g.visibility = 'private' AND $3 = 'private' AND g.owner_email = $5))
                AND LOWER(COALESCE(g.auth_type, 'none')) IN ('', 'none', 'one_time_auth')
                AND NOT (",
    non_empty_json!("g.auth_value"),
    ")
                AND NOT (",
    non_empty_json!("g.oauth_config"),
    ")
                AND NOT (",
    non_empty_json!("g.auth_query_params"),
    ")
                AND NOT (",
    non_empty_json!("g.sigv4_config"),
    ")
        ) THEN 'url'
        ELSE NULL
    END"
);

const AUTH_CONFLICT_QUERY: &str = "
    SELECT CAST(auth_value AS TEXT), CAST(auth_query_params AS TEXT), CAST(sigv4_config AS TEXT), CAST(oauth_config AS TEXT) FROM gateways
    WHERE url = $1 AND (auth_value IS NOT NULL OR auth_query_params IS NOT NULL OR sigv4_config IS NOT NULL OR oauth_config IS NOT NULL)
        AND ((visibility = 'public' AND $2 = 'public')
            OR (visibility = 'team' AND $2 = 'team' AND team_id = $3)
            OR (visibility = 'private' AND $2 = 'private' AND owner_email = $4))";

const CONNECTION_CONFIG: &str = concat!(
    "SELECT LOWER(COALESCE(g.auth_type, '')) AS kind, CAST(g.auth_value AS TEXT) AS headers,
        CAST(g.auth_query_params AS TEXT) AS query, CAST(g.sigv4_config AS TEXT) AS sigv4,
        CAST(g.oauth_config AS TEXT) AS oauth,
        CAST(g.passthrough_headers AS TEXT) AS passthrough, CAST(g.identity_propagation AS TEXT) AS identity,
        g.ca_certificate, g.client_cert, g.client_key, g.version FROM gateways g
    WHERE g.id = $1 AND g.url = $2 AND (g.enabled = TRUE OR $3)
        AND (g.status = 'active' OR (g.status = 'pending' AND g.lifecycle_claimed_by = $5))
        AND (CAST($4 AS INTEGER) IS NULL OR g.version = $4)
        AND g.gateway_mode IN ('cache', 'direct_proxy') AND NOT ",
    gateway_policy!()
);
const DIRECT_GATEWAY_QUERY: &str = concat!(
    "SELECT g.url, g.transport, g.visibility, g.team_id, g.owner_email,
        CAST(g.updated_at AS TEXT) || ':' || CAST(g.version AS TEXT),
        (g.enabled = TRUE AND g.status = 'active' AND NOT ",
    gateway_policy!(),
    ")
    FROM gateways g WHERE g.id = $1 AND g.gateway_mode = 'direct_proxy'"
);
type DirectGatewayRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    bool,
);
#[derive(sqlx::FromRow)]
pub(crate) struct GatewayConnectionRow {
    pub(crate) kind: String,
    pub(crate) version: i32,
    pub(crate) headers: Option<String>,
    pub(crate) query: Option<String>,
    pub(crate) sigv4: Option<String>,
    pub(crate) oauth: Option<String>,
    pub(crate) passthrough: Option<String>,
    pub(crate) identity: Option<String>,
    pub(crate) ca_certificate: Option<String>,
    pub(crate) client_cert: Option<String>,
    pub(crate) client_key: Option<String>,
}

macro_rules! tool_conflict_query {
    ($names:literal) => {
        concat!(
            "SELECT EXISTS (
                SELECT 1 FROM tools t WHERE t.name IN (",
            $names,
            ")
                    AND t.visibility = $2
                    AND ($2 = 'public' OR ($2 = 'team' AND t.team_id = $3)
                      OR ($2 = 'private' AND t.owner_email = $4))
            )"
        )
    };
}

macro_rules! insert_gateway {
    ($capabilities:literal, $tags:literal, $auth_value:literal, $auth_query:literal, $passthrough:literal, $identity:literal, $sigv4:literal, $oauth:literal) => {
        concat!(
            "INSERT INTO gateways (
                id, name, slug, url, description, capabilities, tags, transport, enabled, created_at,
                updated_at, last_seen, reachable, created_by, owner_email, team_id, visibility,
                gateway_mode, status, status_message, refresh_interval_seconds,
                created_from_ip, created_via, created_user_agent, import_batch_id,
                auth_type, auth_value, auth_query_params, passthrough_headers, identity_propagation,
                ca_certificate, ca_certificate_sig, signing_algorithm, client_cert, client_key, sigv4_config, oauth_config
            ) VALUES ($1, $2, $3, $4, $5, ", $capabilities, ", ", $tags, ", $11, TRUE,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CASE WHEN $27 THEN NULL ELSE CURRENT_TIMESTAMP END,
                NOT $27, $8, $8, $9, $10, $17, CASE WHEN $27 THEN 'pending' ELSE 'active' END,
                CASE WHEN $27 THEN 'Gateway registration accepted and pending initialization' END, $28,
                $25, COALESCE($29, 'api'), $26, $30,
                $12, ", $auth_value, ", ", $auth_query, ", ", $passthrough, ", ", $identity, ", $18, $19, $20, $21, $22, ", $sigv4, ", ", $oauth, ")"
        )
    };
}

macro_rules! insert_tool {
    ($input_schema:literal, $output_schema:literal, $annotations:literal) => {
        concat!(
            "INSERT INTO tools (
                id, gateway_id, name, original_name, custom_name_slug, custom_name, description, original_description,
                title, input_schema, output_schema, annotations, url, enabled, reachable, created_at, updated_at,
                jsonpath_filter, integration_type, request_type, created_by, owner_email, team_id, visibility, tags
            ) VALUES ($1, $2, $3, $4, $5, $4, $6, $6, $7, ", $input_schema, ", ", $output_schema, ", ", $annotations, ",
                $11, TRUE, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '', 'MCP', $15, $12, $12, $13, $14, '[]')"
        )
    };
}

pub(crate) const SQLITE_TOOL_INSERT: &str = insert_tool!("json($8)", "json($9)", "json($10)");
pub(crate) const POSTGRES_TOOL_INSERT: &str =
    insert_tool!("CAST($8 AS JSON)", "CAST($9 AS JSON)", "CAST($10 AS JSON)");

impl Database {
    pub async fn catalog_server(&self, id: &str) -> Result<Option<CatalogServer>, sqlx::Error> {
        let row = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, ServerRow>(SERVER_QUERY)
                    .bind(id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, ServerRow>(SERVER_QUERY)
                    .bind(id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        Ok(row.map(
            |(id, name, team_id, enabled, oauth_enabled, owner_email, visibility, instructions)| {
                CatalogServer {
                    id,
                    name,
                    team_id,
                    enabled,
                    oauth_enabled,
                    instructions,
                    owner_email,
                    visibility,
                }
            },
        ))
    }

    pub(crate) async fn tool_refresh_interval(
        &self,
        server_id: &str,
        default_seconds: i32,
    ) -> Result<Option<i32>, sqlx::Error> {
        const QUERY: &str = "
            SELECT MIN(COALESCE(g.refresh_interval_seconds, $2))
            FROM server_tool_association a
            JOIN tools t ON t.id = a.tool_id
            JOIN gateways g ON g.id = t.gateway_id
            WHERE a.server_id = $1";
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar(QUERY)
                    .bind(server_id)
                    .bind(default_seconds)
                    .fetch_one(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar(QUERY)
                    .bind(server_id)
                    .bind(default_seconds)
                    .fetch_one(pool)
                    .await
            }
        }
    }

    pub async fn active_team(&self, id: &str) -> Result<bool, sqlx::Error> {
        const QUERY: &str =
            "SELECT EXISTS (SELECT 1 FROM email_teams WHERE id = $1 AND is_active = TRUE)";
        match self {
            Self::Sqlite(pool) => sqlx::query_scalar(QUERY).bind(id).fetch_one(pool).await,
            Self::Postgres(pool) => sqlx::query_scalar(QUERY).bind(id).fetch_one(pool).await,
        }
    }

    pub async fn list_mcp_tools(
        &self,
        scope: CatalogScope<'_>,
        server_id: Option<&str>,
        after_id: Option<&str>,
        limit: u32,
        grpc_enabled: bool,
    ) -> Result<Vec<CatalogTool>, sqlx::Error> {
        self.mcp_tools(scope, server_id, None, after_id, limit, grpc_enabled)
            .await
    }

    pub(crate) async fn list_catalog_metadata(
        &self,
        list: CatalogList,
        scope: CatalogScope<'_>,
        server: Option<&str>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<(String, Value)>, sqlx::Error> {
        let teams = match scope.visibility {
            TeamVisibility::Teams(teams) => teams.as_slice(),
            TeamVisibility::Admin | TeamVisibility::Public => &[],
        };
        let teams =
            serde_json::to_string(teams).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        macro_rules! select {
            ($pool:ident, $teams:literal) => {
                sqlx::query_as::<_, MetadataRow>(catalog_metadata_query!(list, $teams))
                    .bind(server)
                    .bind(i64::from(limit))
                    .bind(after)
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(teams)
                    .fetch_all($pool)
                    .await?
            };
        }
        let rows = match self {
            Self::Sqlite(pool) => select!(pool, "SELECT value FROM json_each($7)"),
            Self::Postgres(pool) => {
                select!(pool, "SELECT json_array_elements_text(CAST($7 AS JSON))")
            }
        };
        rows.into_iter()
            .map(|row| metadata_item(list, row))
            .collect()
    }

    pub(crate) async fn resource_content(
        &self,
        scope: CatalogScope<'_>,
        server: Option<&str>,
        uri: &str,
    ) -> Result<Option<ResourceContentRecord>, sqlx::Error> {
        let mut exact = self
            .resource_content_rows(scope, server, ResourceLookup::Uri(uri), None, 2)
            .await?;
        if exact.len() > 1 {
            return Err(sqlx::Error::Protocol(
                "ambiguous resource URI in visible catalog".into(),
            ));
        }
        if let Some(row) = exact.pop() {
            return Ok(Some(resource_content_record(row)));
        }
        let mut after = None;
        loop {
            let rows = self
                .resource_content_rows(
                    scope,
                    server,
                    ResourceLookup::Templates,
                    after.as_deref(),
                    64,
                )
                .await?;
            let remaining = rows.len() == 64;
            for row in rows {
                if row
                    .4
                    .as_deref()
                    .is_some_and(|template| uri_matches_template(uri, template))
                {
                    return Ok(Some(resource_content_record(row)));
                }
                after = Some(row.0);
            }
            if !remaining {
                return Ok(None);
            }
        }
    }

    pub(crate) async fn resource_template_content(
        &self,
        scope: CatalogScope<'_>,
        server: Option<&str>,
        template: &str,
    ) -> Result<Option<ResourceContentRecord>, sqlx::Error> {
        let mut rows = self
            .resource_content_rows(scope, server, ResourceLookup::Template(template), None, 1)
            .await?;
        Ok(rows.pop().map(resource_content_record))
    }

    pub(crate) async fn resource_content_by_id(
        &self,
        scope: CatalogScope<'_>,
        server: Option<&str>,
        id: &str,
    ) -> Result<Option<ResourceContentRecord>, sqlx::Error> {
        let mut rows = self
            .resource_content_rows(scope, server, ResourceLookup::Id(id), None, 1)
            .await?;
        Ok(rows.pop().map(resource_content_record))
    }

    pub(crate) async fn resource_subscription_targets(
        &self,
        scope: CatalogScope<'_>,
        server: Option<&str>,
        uris: &[&str],
    ) -> Result<Vec<(ResourceSubscriptionTarget, Option<String>)>, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        let uris =
            serde_json::to_string(uris).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        macro_rules! select {
            ($pool:ident, $teams:literal, $uris:literal) => {{
                let query = metadata_query!(
                    $teams,
                    "item.uri, g.id, g.url,
                    CASE WHEN LOWER(COALESCE(g.auth_type, '')) IN ('basic', 'bearer', 'authheaders')
                        THEN COALESCE(CAST(g.auth_value AS TEXT), 'null') END",
                    "resources",
                    "server_resource_association",
                    "resource_id",
                    concat!(
                        "UPPER(g.transport) = 'STREAMABLEHTTP'
                        AND g.gateway_mode IN ('cache', 'direct_proxy')
                        AND LOWER(COALESCE(g.auth_type, 'none')) IN ('', 'none', 'one_time_auth', 'basic', 'bearer', 'authheaders')
                        AND COALESCE(g.ca_certificate, '') = ''
                        AND COALESCE(g.client_cert, '') = ''
                        AND COALESCE(g.client_key, '') = ''
                        AND NOT ", gateway_policy!(), "
                        AND item.uri IN (",
                        $uris,
                        ")"
                    )
                );
                sqlx::query_as::<_, ResourceSubscriptionRow>(query)
                    .bind(server)
                    .bind(i64::MAX)
                    .bind(None::<&str>)
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(teams)
                    .bind(uris)
                    .fetch_all($pool)
                    .await?
            }};
        }
        let rows = match self {
            Self::Sqlite(pool) => select!(
                pool,
                "SELECT value FROM json_each($7)",
                "SELECT value FROM json_each($8)"
            ),
            Self::Postgres(pool) => select!(
                pool,
                "SELECT json_array_elements_text(CAST($7 AS JSON))",
                "SELECT json_array_elements_text(CAST($8 AS JSON))"
            ),
        };
        Ok(rows
            .into_iter()
            .map(|(_, _, _, _, uri, gateway_id, url, headers)| {
                (
                    ResourceSubscriptionTarget {
                        gateway_id,
                        uri,
                        url,
                    },
                    headers,
                )
            })
            .collect())
    }

    pub(crate) async fn resource_completions(
        &self,
        scope: CatalogScope<'_>,
        server: Option<&str>,
        input: &str,
    ) -> Result<CompletionInfo, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        let needle = input.to_lowercase();
        let mut values = Vec::new();
        let mut total = 0_u32;
        macro_rules! collect {
            ($pool:ident, $teams:literal) => {{
                let query = metadata_query!(
                    $teams,
                    "item.uri, CAST(NULL AS TEXT), CAST(NULL AS BIGINT)",
                    "resources",
                    "server_resource_association",
                    "resource_id",
                    "TRUE"
                );
                let mut rows = sqlx::query_as::<_, MetadataRow>(query)
                    .bind(server)
                    .bind(i64::MAX)
                    .bind(None::<&str>)
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(teams)
                    .fetch($pool);
                while let Some((_, _, _, _, Some(uri), _, _)) = rows.try_next().await? {
                    if uri.to_lowercase().contains(&needle) {
                        total = total.saturating_add(1);
                        if values.len() < CompletionInfo::MAX_VALUES {
                            values.push(uri);
                        }
                    }
                }
            }};
        }
        match self {
            Self::Sqlite(pool) => collect!(pool, "SELECT value FROM json_each($7)"),
            Self::Postgres(pool) => {
                collect!(pool, "SELECT json_array_elements_text(CAST($7 AS JSON))")
            }
        }
        let has_more = total as usize > values.len();
        CompletionInfo::with_pagination(values, Some(total), has_more)
            .map_err(sqlx::Error::Protocol)
    }

    async fn resource_content_rows(
        &self,
        scope: CatalogScope<'_>,
        server: Option<&str>,
        lookup: ResourceLookup<'_>,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ResourceContentRow>, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        let (uri, template, id) = match lookup {
            ResourceLookup::Uri(uri) => (Some(uri), None, None),
            ResourceLookup::Template(template) => (None, Some(template), None),
            ResourceLookup::Id(id) => (None, None, Some(id)),
            ResourceLookup::Templates => (None, None, None),
        };
        macro_rules! select {
            ($pool:ident, $teams:literal) => {
                sqlx::query_as::<_, ResourceContentRow>(resource_content_query!($teams))
                    .bind(server)
                    .bind(limit)
                    .bind(after)
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(teams)
                    .bind(uri)
                    .bind(template)
                    .bind(id)
                    .fetch_all($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool, "SELECT value FROM json_each($7)"),
            Self::Postgres(pool) => {
                select!(pool, "SELECT json_array_elements_text(CAST($7 AS JSON))")
            }
        }
    }

    pub(crate) async fn prompt_content(
        &self,
        scope: CatalogScope<'_>,
        server: Option<&str>,
        name: &str,
        name_only: bool,
    ) -> Result<Option<PromptContentRecord>, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        macro_rules! select {
            ($pool:ident, $teams:literal) => {
                sqlx::query_as::<_, PromptContentRow>(prompt_content_query!($teams))
                    .bind(server)
                    .bind(3_i64)
                    .bind(None::<&str>)
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(teams)
                    .bind(name)
                    .bind(name_only)
                    .fetch_all($pool)
                    .await?
            };
        }
        let mut rows = match self {
            Self::Sqlite(pool) => select!(pool, "SELECT value FROM json_each($7)"),
            Self::Postgres(pool) => {
                select!(pool, "SELECT json_array_elements_text(CAST($7 AS JSON))")
            }
        };
        if rows.len() > 1 {
            rows.retain(|row| row.1 == name);
        }
        if rows.len() > 1 {
            return Err(sqlx::Error::Protocol(
                "ambiguous prompt name in visible catalog".into(),
            ));
        }
        let Some((
            _,
            _,
            _,
            description,
            original_name,
            template,
            schema,
            id,
            url,
            transport,
            available,
            needs_upstream_config,
        )) = rows.pop()
        else {
            return Ok(None);
        };
        Ok(Some(PromptContentRecord {
            original_name,
            description,
            template,
            argument_schema: decode_optional_json(schema.as_deref())?,
            gateway: content_gateway(
                id,
                url,
                transport.as_deref(),
                available,
                needs_upstream_config,
            ),
        }))
    }

    pub async fn find_mcp_tool(
        &self,
        scope: CatalogScope<'_>,
        server_id: Option<&str>,
        name: &str,
        grpc_enabled: bool,
    ) -> Result<Option<CatalogTool>, sqlx::Error> {
        let mut matches = self
            .mcp_tools(scope, server_id, Some(name), None, 2, grpc_enabled)
            .await?;
        if matches.len() > 1 {
            return Err(sqlx::Error::Protocol(
                "ambiguous MCP tool name in visible catalog".into(),
            ));
        }
        Ok(matches.pop())
    }

    async fn mcp_tools(
        &self,
        scope: CatalogScope<'_>,
        server_id: Option<&str>,
        name: Option<&str>,
        after_id: Option<&str>,
        limit: u32,
        grpc_enabled: bool,
    ) -> Result<Vec<CatalogTool>, sqlx::Error> {
        let teams = match scope.visibility {
            TeamVisibility::Teams(teams) => teams.as_slice(),
            TeamVisibility::Admin | TeamVisibility::Public => &[],
        };
        let team_ids =
            serde_json::to_string(teams).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        macro_rules! read_tools {
            ($pool:ident, $query:expr) => {
                sqlx::query_as::<_, ToolRow>($query)
                    .bind(server_id)
                    .bind(name)
                    .bind(after_id)
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(team_ids)
                    .bind(i64::from(limit))
                    .bind(grpc_enabled)
                    .fetch_all($pool)
                    .await?
            };
        }
        let rows = match self {
            Self::Sqlite(pool) => read_tools!(pool, tool_query!("SELECT value FROM json_each($7)")),
            Self::Postgres(pool) => read_tools!(
                pool,
                tool_query!("SELECT json_array_elements_text(CAST($7 AS JSON))")
            ),
        };
        rows.into_iter().map(decode_tool).collect()
    }

    /// Persist a discovered cache-mode Streamable HTTP server and all its tools.
    pub async fn register_gateway(
        &self,
        gateway: &GatewayRegistration<'_>,
        tools: &[RegisteredTool<'_>],
    ) -> Result<(), RegistrationError> {
        self.register_discovered_gateway(
            gateway,
            tools,
            &DiscoveredMetadata::default(),
            RegistrationOptions::default(),
        )
        .await
    }

    pub(crate) async fn register_discovered_gateway(
        &self,
        gateway: &GatewayRegistration<'_>,
        tools: &[RegisteredTool<'_>],
        metadata: &DiscoveredMetadata,
        options: RegistrationOptions<'_>,
    ) -> Result<(), RegistrationError> {
        validate_registration(gateway, tools)?;
        let capabilities = gateway.capabilities.to_string();
        let tags = serde_json::to_string(gateway.tags)
            .map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        let auth = options.auth;
        let passthrough = options
            .passthrough_headers
            .map(|headers| json!(headers).to_string());
        let identity = options.identity.map(Value::to_string);
        let names: Vec<_> = tools.iter().map(|tool| tool.name).collect();
        if names.iter().copied().collect::<HashSet<_>>().len() != names.len() {
            return Err(RegistrationError::ToolNameConflict);
        }
        let names =
            serde_json::to_string(&names).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;

        // The duplicate check and all inserts share a write transaction, including on SQLite.
        macro_rules! register {
            ($tx:ident, $tool_conflicts:expr, $gateway_insert:expr, $tool_insert:expr, $schema:literal) => {{
                let conflict = sqlx::query_scalar::<_, Option<String>>(CONFLICT_QUERY)
                    .bind(gateway.slug)
                    .bind(gateway.url)
                    .bind(gateway.visibility)
                    .bind(gateway.team_id)
                    .bind(gateway.owner_email)
                    .bind(auth.is_none() && !options.one_time_auth)
                    .fetch_one(&mut *$tx)
                    .await?;
                match conflict.as_deref() {
                    Some("name") => return Err(RegistrationError::NameConflict),
                    Some("url") => return Err(RegistrationError::UrlConflict),
                    _ => {}
                }
                if let Some(auth) = auth {
                    let existing = sqlx::query_as::<_, (Option<String>, Option<String>, Option<String>, Option<String>)>(AUTH_CONFLICT_QUERY)
                        .bind(gateway.url)
                        .bind(gateway.visibility)
                        .bind(gateway.team_id)
                        .bind(gateway.owner_email)
                        .fetch_all(&mut *$tx)
                        .await?;
                    if existing.iter().any(|(headers, query, sigv4, oauth)| auth.matches_stored(headers.as_deref(), query.as_deref(), sigv4.as_deref(), oauth.as_deref())) {
                        return Err(RegistrationError::UrlConflict);
                    }
                }

                if sqlx::query_scalar::<_, bool>($tool_conflicts)
                    .bind(names)
                    .bind(gateway.visibility)
                    .bind(gateway.team_id)
                    .bind(gateway.owner_email)
                    .fetch_one(&mut *$tx)
                    .await?
                {
                    return Err(RegistrationError::ToolNameConflict);
                }

                sqlx::query($gateway_insert)
                    .bind(gateway.id)
                    .bind(gateway.name)
                    .bind(gateway.slug)
                    .bind(gateway.url)
                    .bind(gateway.description)
                    .bind(capabilities)
                    .bind(tags)
                    .bind(gateway.owner_email)
                    .bind(gateway.team_id)
                    .bind(gateway.visibility)
                    .bind(gateway.transport.name())
                    .bind(if options.one_time_auth { Some("one_time_auth") } else { auth.map(|auth| auth.kind) })
                    .bind(auth.and_then(|auth| auth.encoded_headers.as_deref()))
                    .bind(auth.and_then(|auth| auth.encoded_query.as_deref()))
                    .bind(passthrough)
                    .bind(identity)
                    .bind(options.mode.name())
                    .bind(options.tls.ca_certificate)
                    .bind(options.tls.ca_certificate_sig)
                    .bind(options.tls.signing_algorithm)
                    .bind(options.tls.client_cert)
                    .bind(options.tls.client_key)
                    .bind(auth.and_then(|auth| auth.encoded_sigv4.as_deref()))
                    .bind(auth.and_then(|auth| auth.encoded_oauth.as_deref()))
                    .bind(options.created_from_ip)
                    .bind(options.created_user_agent)
                    .bind(options.pending)
                    .bind(options.refresh_interval_seconds)
                    .bind(options.created_via)
                    .bind(options.import_batch_id)
                    .execute(&mut *$tx)
                    .await?;
                for tool in tools {
                    let definition = tool.definition;
                    let annotations = definition
                        .annotations
                        .as_ref()
                        .map(Value::to_string)
                        .unwrap_or_else(|| "{}".into());
                    sqlx::query($tool_insert)
                        .bind(tool.id)
                        .bind(gateway.id)
                        .bind(tool.name)
                        .bind(&definition.name)
                        .bind(tool.slug)
                        .bind(&definition.description)
                        .bind(&definition.title)
                        .bind(definition.input_schema.to_string())
                        .bind(definition.output_schema.as_ref().map(Value::to_string))
                        .bind(annotations)
                        .bind(gateway.url)
                        .bind(gateway.owner_email)
                        .bind(gateway.team_id)
                        .bind(gateway.visibility)
                        .bind(gateway.transport.name())
                        .execute(&mut *$tx)
                        .await?;
                }
                let mut uris = HashSet::new();
                for resource in resource_registrations(metadata) {
                    if !uris.insert((resource.uri, resource.template.is_some())) { continue; }
                    let slug = slugify(resource.name);
                    let name = format!("{}-{slug}", gateway.slug);
                    if slug.is_empty() || name.len() > 255 || resource.uri.is_empty() || resource.uri.len() > 767 {
                        return Err(RegistrationError::Invalid("Invalid upstream resource"));
                    }
                    sqlx::query(INSERT_RESOURCE)
                        .bind(uuid::Uuid::new_v4().simple().to_string())
                        .bind(resource.uri).bind(resource.template).bind(name).bind(resource.name).bind(slug)
                        .bind(resource.title).bind(resource.description).bind(resource.mime).bind(resource.size)
                        .bind(gateway.id).bind(gateway.owner_email).bind(gateway.team_id).bind(gateway.visibility)
                        .execute(&mut *$tx).await?;
                }
                let mut prompts = HashSet::new();
                for prompt in &metadata.prompts {
                    if !prompts.insert(prompt.name.as_str()) { continue; }
                    let slug = slugify(&prompt.name);
                    let name = format!("{}-{slug}", gateway.slug);
                    if slug.is_empty() || name.len() > 255 || prompt.name.len() > 255 {
                        return Err(RegistrationError::Invalid("Invalid upstream prompt"));
                    }
                    sqlx::query(concat!("INSERT INTO prompts (id, name, original_name, custom_name, custom_name_slug,
                        title, description, argument_schema, gateway_id, owner_email, team_id, visibility,
                        enabled, tags, created_at, updated_at)
                        VALUES ($1,$2,$3,$3,$4,$5,$6,", $schema, ",$8,$9,$10,$11,
                            TRUE,'[]',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
                        .bind(uuid::Uuid::new_v4().simple().to_string())
                        .bind(name).bind(&prompt.name).bind(slug).bind(&prompt.title).bind(&prompt.description)
                        .bind(prompt_argument_schema(prompt).to_string())
                        .bind(gateway.id).bind(gateway.owner_email).bind(gateway.team_id).bind(gateway.visibility)
                        .execute(&mut *$tx).await?;
                }
                $tx.commit().await?;
            }};
        }

        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
                register!(
                    transaction,
                    tool_conflict_query!("SELECT value FROM json_each($1)"),
                    insert_gateway!(
                        "json($6)",
                        "json($7)",
                        "json($13)",
                        "json($14)",
                        "json($15)",
                        "json($16)",
                        "json($23)",
                        "json($24)"
                    ),
                    SQLITE_TOOL_INSERT,
                    "json($7)"
                );
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *transaction).await?;
                register!(
                    transaction,
                    tool_conflict_query!("SELECT json_array_elements_text(CAST($1 AS JSON))"),
                    insert_gateway!(
                        "CAST($6 AS JSON)",
                        "CAST($7 AS JSON)",
                        "CAST($13 AS JSON)",
                        "CAST($14 AS JSON)",
                        "CAST($15 AS JSON)",
                        "CAST($16 AS JSON)",
                        "CAST($23 AS JSON)",
                        "CAST($24 AS JSON)"
                    ),
                    POSTGRES_TOOL_INSERT,
                    "CAST($7 AS JSON)"
                );
            }
        }
        Ok(())
    }

    pub(crate) async fn gateway_connection(
        &self,
        id: &str,
        url: &str,
        allow_disabled: bool,
        version: Option<i32>,
        lifecycle_claim: Option<&str>,
    ) -> Result<Option<GatewayConnectionRow>, sqlx::Error> {
        macro_rules! fetch {
            ($pool:expr) => {
                sqlx::query_as::<_, GatewayConnectionRow>(CONNECTION_CONFIG)
                    .bind(id)
                    .bind(url)
                    .bind(allow_disabled)
                    .bind(version)
                    .bind(lifecycle_claim)
                    .fetch_optional($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => fetch!(pool),
            Self::Postgres(pool) => fetch!(pool),
        }
    }

    pub(crate) async fn direct_gateway(
        &self,
        id: &str,
    ) -> Result<Option<DirectGateway>, sqlx::Error> {
        macro_rules! fetch {
            ($pool:expr) => {
                sqlx::query_as::<_, DirectGatewayRow>(DIRECT_GATEWAY_QUERY)
                    .bind(id)
                    .fetch_optional($pool)
                    .await?
            };
        }
        let row = match self {
            Self::Sqlite(pool) => fetch!(pool),
            Self::Postgres(pool) => fetch!(pool),
        };
        Ok(row.map(
            |(url, transport, visibility, team_id, owner_email, revision, available)| {
                DirectGateway {
                    content: ContentGateway {
                        id: id.to_owned(),
                        url,
                        transport: UpstreamTransport::from_name(&transport),
                        available,
                        needs_upstream_config: true,
                    },
                    revision,
                    visibility,
                    team_id,
                    owner_email,
                }
            },
        ))
    }

    pub(crate) async fn global_passthrough_headers(&self) -> Result<Option<String>, sqlx::Error> {
        const QUERY: &str =
            "SELECT CAST(passthrough_headers AS TEXT) FROM global_config ORDER BY id LIMIT 1";
        let headers = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, Option<String>>(QUERY)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, Option<String>>(QUERY)
                    .fetch_optional(pool)
                    .await?
            }
        };
        Ok(headers.flatten())
    }
}

pub(crate) fn visible_team_ids(scope: CatalogScope<'_>) -> Result<String, sqlx::Error> {
    let teams = match scope.visibility {
        TeamVisibility::Teams(teams) => teams.as_slice(),
        TeamVisibility::Admin | TeamVisibility::Public => &[],
    };
    serde_json::to_string(teams).map_err(|error| sqlx::Error::Encode(Box::new(error)))
}

fn resource_content_record(row: ResourceContentRow) -> ResourceContentRecord {
    let (
        id,
        _,
        _,
        _,
        _,
        mime,
        text,
        blob,
        gateway,
        url,
        transport,
        available,
        needs_upstream_config,
        uri,
    ) = row;
    ResourceContentRecord {
        id,
        uri,
        mime,
        text,
        blob,
        gateway: content_gateway(
            gateway,
            url,
            transport.as_deref(),
            available,
            needs_upstream_config,
        ),
    }
}

fn content_gateway(
    id: Option<String>,
    url: Option<String>,
    transport: Option<&str>,
    available: bool,
    needs_upstream_config: bool,
) -> Option<ContentGateway> {
    Some(ContentGateway {
        id: id?,
        url: url?,
        transport: transport.and_then(UpstreamTransport::from_name),
        available,
        needs_upstream_config,
    })
}

fn uri_matches_template(uri: &str, mut template: &str) -> bool {
    let mut pattern = String::from(r"\A");
    while let Some((literal, expression)) = template.split_once('{') {
        pattern.push_str(&regex::escape(literal));
        let Some((variable, remainder)) = expression.split_once('}') else {
            return false;
        };
        if !variable.starts_with('?') {
            if variable.is_empty() {
                return false;
            }
            pattern.push_str(if variable.ends_with('*') {
                ".+"
            } else {
                "[^/]+"
            });
        }
        template = remainder;
    }
    pattern.push_str(&regex::escape(template));
    pattern.push_str(r"\z");
    let path = uri.split_once('?').map_or(uri, |(path, _)| path);
    regex::Regex::new(&pattern).is_ok_and(|matcher| matcher.is_match(path))
}

pub(crate) fn prompt_argument_schema(prompt: &rmcp::model::Prompt) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for argument in prompt.arguments.iter().flatten() {
        let mut property = json!({"type":"string"});
        if let Some(description) = &argument.description {
            property["description"] = json!(description);
        }
        properties.insert(argument.name.clone(), property);
        if argument.required == Some(true) {
            required.push(&argument.name);
        }
    }
    json!({"type":"object","properties":properties,"required":required})
}

pub(crate) fn slugify(value: &str) -> String {
    slugify_with_separator(value, "-")
}

pub(crate) fn slugify_with_separator(value: &str, delimiter: &str) -> String {
    use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

    let is_alphanumeric =
        |character: char| character.is_alphanumeric() && !is_combining_mark(character);
    let is_word = |character: char| is_alphanumeric(character) || character == '_';
    let lower = value.to_lowercase();
    let mut letters = lower.chars().peekable();
    let mut contracted = String::with_capacity(lower.len());
    while let Some(character) = letters.next() {
        contracted.push(character);
        if is_word(character) && letters.next_if_eq(&'\'').is_some() {
            contracted.push(letters.next_if(|next| is_word(*next)).unwrap_or('\''));
        }
    }

    let mut result = String::new();
    let mut separator = false;
    for character in contracted.chars() {
        if is_alphanumeric(character) {
            if separator && !result.is_empty() {
                result.push_str(delimiter);
            }
            match character {
                'æ' => result.push_str("ae"),
                'ß' => result.push_str("ss"),
                'ø' => result.push('o'),
                character => result.push(character),
            }
            separator = false;
        } else {
            separator = true;
        }
    }
    result.nfkd().filter(char::is_ascii).collect()
}

fn metadata_item(list: CatalogList, row: MetadataRow) -> Result<(String, Value), sqlx::Error> {
    let (id, name, title, description, detail, mime, size) = row;
    let mut item = serde_json::Map::new();
    item.insert("name".to_owned(), name.into());
    for (key, value) in [
        ("title", title),
        ("description", description),
        ("mimeType", mime),
    ] {
        if let Some(value) = value {
            item.insert(key.to_owned(), value.into());
        }
    }
    match list {
        CatalogList::Resources | CatalogList::Templates => {
            let key = if matches!(list, CatalogList::Resources) {
                "uri"
            } else {
                "uriTemplate"
            };
            let uri = detail.ok_or_else(|| {
                sqlx::Error::Protocol("MCP resource URI missing from catalog".into())
            })?;
            item.insert(key.to_owned(), uri.into());
            if let Some(size) = size.filter(|size| *size >= 0) {
                item.insert("size".to_owned(), size.into());
            }
        }
        CatalogList::Prompts => {
            let schema = decode_optional_json(detail.as_deref())?.unwrap_or(Value::Null);
            let required = schema["required"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default();
            let arguments: Vec<Value> = schema["properties"].as_object().into_iter().flatten().map(|(name, property)| {
                json!({"name":name, "description":property["description"].as_str().unwrap_or_default(),
                    "required":required.iter().any(|value| value.as_str() == Some(name))})
            }).collect();
            item.insert("arguments".to_owned(), arguments.into());
        }
    }
    Ok((id, Value::Object(item)))
}

fn decode_tool(row: ToolRow) -> Result<CatalogTool, sqlx::Error> {
    let ToolRow {
        id,
        original_name,
        gateway_id,
        gateway_name,
        gateway_url,
        gateway_version,
        gateway_mode,
        gateway_transport,
        request_type,
        requires_gateway_policy,
        reachable,
        deprecated,
        needs_upstream_config,
        name,
        title,
        description,
        input_schema,
        output_schema,
        annotations,
        integration_type,
        grpc_service_id,
        response_filter,
        rest,
    } = row;
    Ok(CatalogTool {
        id,
        original_name,
        gateway_id,
        gateway_name,
        gateway_url,
        gateway_version,
        gateway_mode,
        gateway_transport,
        request_type,
        requires_gateway_policy,
        reachable,
        deprecated,
        rest: (integration_type == "REST").then_some(rest),
        grpc_service_id,
        response_filter,
        needs_upstream_config,
        definition: ToolDefinition {
            name,
            title,
            description,
            input_schema: decode_json(&input_schema)?,
            output_schema: decode_optional_json(output_schema.as_deref())?,
            annotations: decode_optional_json(annotations.as_deref())?,
        },
    })
}

fn decode_json(text: &str) -> Result<Value, sqlx::Error> {
    serde_json::from_str(text).map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

fn decode_optional_json(text: Option<&str>) -> Result<Option<Value>, sqlx::Error> {
    Ok(text
        .map(decode_json)
        .transpose()?
        .filter(|value| !value.is_null()))
}

fn validate_registration(
    gateway: &GatewayRegistration<'_>,
    tools: &[RegisteredTool<'_>],
) -> Result<(), RegistrationError> {
    if gateway.id.is_empty()
        || gateway.name.is_empty()
        || gateway.slug.is_empty()
        || gateway.url.is_empty()
        || gateway.owner_email.is_empty()
        || !gateway.capabilities.is_object()
    {
        return Err(RegistrationError::Invalid(
            "invalid MCP server identity, endpoint, or capabilities",
        ));
    }
    match gateway.visibility {
        "public" | "private" => {}
        "team" if gateway.team_id.is_some_and(|id| !id.is_empty()) => {}
        _ => return Err(RegistrationError::Invalid("invalid MCP server visibility")),
    }
    for tool in tools {
        let definition = tool.definition;
        if tool.id.is_empty()
            || tool.name.is_empty()
            || tool.slug.is_empty()
            || definition.name.is_empty()
            || !definition.input_schema.is_object()
            || definition
                .output_schema
                .as_ref()
                .is_some_and(|schema| !schema.is_object())
            || definition
                .annotations
                .as_ref()
                .is_some_and(|annotations| !annotations.is_object())
        {
            return Err(RegistrationError::Invalid(
                "invalid MCP tool identity or descriptor",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;

    async fn database() -> Database {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let database = Database::Sqlite(pool);
        database.migrate_schema().await.unwrap();
        database.migrate_schema().await.unwrap();
        let Database::Sqlite(pool) = &database else {
            unreachable!();
        };
        sqlx::raw_sql(
            "INSERT INTO email_users (id, email) VALUES ('owner', 'owner@example.com');
             INSERT INTO email_teams (id, name, slug, created_by)
                 VALUES ('fort', 'Fort', 'fort', 'owner@example.com');",
        )
        .execute(pool)
        .await
        .unwrap();
        database
    }

    fn gateway<'a>(
        id: &'a str,
        url: &'a str,
        capabilities: &'a Value,
        visibility: &'a str,
        team_id: Option<&'a str>,
    ) -> GatewayRegistration<'a> {
        GatewayRegistration {
            id,
            name: id,
            slug: id,
            url,
            transport: UpstreamTransport::StreamableHttp,
            description: Some("Catalog fixture"),
            capabilities,
            visibility,
            team_id,
            owner_email: "owner@example.com",
            tags: &[],
        }
    }

    fn tool_definition() -> ToolDefinition {
        serde_json::from_value(json!({
            "name": "echo",
            "title": "Echo",
            "description": null,
            "inputSchema": { "type": "object" },
            "outputSchema": { "type": "object" }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn catalogue_filters_tools_gateway_and_server_visibility() {
        let database = database().await;
        let capabilities = json!({"tools": {}});
        let definition = tool_definition();
        for (id, tool_id, name, visibility, team) in [
            ("public", "01", "public-echo", "public", None),
            ("fort", "02", "fort-echo", "team", Some("fort")),
            ("own", "03", "own-echo", "private", None),
        ] {
            database
                .register_gateway(
                    &gateway(
                        id,
                        &format!("http://localhost:9000/{id}"),
                        &capabilities,
                        visibility,
                        team,
                    ),
                    &[RegisteredTool {
                        id: tool_id,
                        slug: "echo",
                        name,
                        definition: &definition,
                    }],
                )
                .await
                .unwrap();
        }

        let Database::Sqlite(pool) = &database else {
            unreachable!();
        };
        sqlx::raw_sql(
            "INSERT INTO servers (id, name, visibility, team_id, owner_email, oauth_enabled)
                VALUES ('fort-server', 'Fort server', 'team', 'fort', 'owner@example.com', TRUE);
             INSERT INTO server_tool_association (server_id, tool_id)
                VALUES ('fort-server', '01'), ('fort-server', '02');",
        )
        .execute(pool)
        .await
        .unwrap();
        let public = CatalogScope {
            email: Some("owner@example.com"),
            visibility: &TeamVisibility::Public,
        };
        let fort = TeamVisibility::Teams(vec!["fort".into()]);
        let member = CatalogScope {
            email: Some("member@example.com"),
            visibility: &fort,
        };
        let owner = CatalogScope {
            email: Some("owner@example.com"),
            visibility: &fort,
        };
        let outsider_teams = TeamVisibility::Teams(vec!["outside".into()]);
        let outsider = CatalogScope {
            email: Some("outside@example.com"),
            visibility: &outsider_teams,
        };
        let ids =
            |tools: Vec<CatalogTool>| tools.into_iter().map(|tool| tool.id).collect::<Vec<_>>();

        assert_eq!(
            ids(database
                .list_mcp_tools(public, None, None, 10, false)
                .await
                .unwrap()),
            ["01"]
        );
        assert_eq!(
            ids(database
                .list_mcp_tools(owner, None, Some("01"), 10, false)
                .await
                .unwrap()),
            ["02", "03"]
        );
        let server = database
            .catalog_server("fort-server")
            .await
            .unwrap()
            .unwrap();
        assert!(server.oauth_enabled && server.is_visible(member));
        assert!(!server.is_visible(outsider));
        assert!(database.active_team("fort").await.unwrap());
        assert!(!database.active_team("missing").await.unwrap());
        assert!(
            database
                .list_mcp_tools(outsider, Some("fort-server"), None, 10, false)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            database
                .find_mcp_tool(outsider, Some("fort-server"), "public-echo", false)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            ids(database
                .list_mcp_tools(member, Some("fort-server"), Some("01"), 1, false)
                .await
                .unwrap()),
            ["02"]
        );
        assert!(
            database
                .find_mcp_tool(member, Some("fort-server"), "own-echo", false)
                .await
                .unwrap()
                .is_none()
        );

        let tool = database
            .find_mcp_tool(member, Some("fort-server"), "fort-echo", false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tool.original_name, "echo");
        assert_eq!(tool.gateway_name, "fort");
        assert_eq!(tool.gateway_url, "http://localhost:9000/fort");
        assert!(!tool.requires_gateway_policy);
        assert_eq!(
            serde_json::to_value(&tool.definition).unwrap(),
            json!({
                "name": "fort-echo",
                "title": "Echo",
                "description": "",
                "inputSchema": { "type": "object" },
                "outputSchema": { "type": "object" },
                "annotations": {}
            })
        );
        sqlx::query("UPDATE gateways SET remove_headers = '[\"Authorization\"]' WHERE id = 'fort'")
            .execute(pool)
            .await
            .unwrap();
        assert!(
            database
                .find_mcp_tool(member, Some("fort-server"), "fort-echo", false)
                .await
                .unwrap()
                .unwrap()
                .requires_gateway_policy
        );
        sqlx::query("UPDATE gateways SET visibility = 'private' WHERE id = 'fort'")
            .execute(pool)
            .await
            .unwrap();
        assert!(
            database
                .find_mcp_tool(member, Some("fort-server"), "fort-echo", false)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn registration_checks_duplicates_and_rolls_back_tool_insert_failure() {
        let database = database().await;
        let capabilities = json!({"tools": {}});
        let echo = tool_definition();
        let distinct = ToolDefinition {
            name: "different".into(),
            ..echo.clone()
        };
        let mut tools = [
            RegisteredTool {
                id: "first",
                slug: "echo",
                name: "fixture-echo",
                definition: &echo,
            },
            RegisteredTool {
                id: "first",
                slug: "echo",
                name: "fixture-echo",
                definition: &distinct,
            },
        ];
        let fixture = gateway(
            "fixture",
            "http://localhost:9000/mcp",
            &capabilities,
            "public",
            None,
        );
        assert!(matches!(
            database.register_gateway(&fixture, &tools).await,
            Err(RegistrationError::ToolNameConflict)
        ));
        tools[1].name = "fixture-different";
        assert!(matches!(
            database.register_gateway(&fixture, &tools).await,
            Err(RegistrationError::Database(_))
        ));
        database
            .register_gateway(&fixture, &tools[..1])
            .await
            .unwrap();
        let public = CatalogScope {
            email: None,
            visibility: &TeamVisibility::Public,
        };
        assert!(
            database
                .find_mcp_tool(public, None, "fixture-echo", false)
                .await
                .unwrap()
                .is_some()
        );
        let same_name = GatewayRegistration {
            url: "http://localhost:9000/other",
            ..fixture
        };
        assert!(matches!(
            database.register_gateway(&same_name, &[]).await,
            Err(RegistrationError::NameConflict)
        ));
        let same_url = GatewayRegistration {
            id: "new",
            name: "new",
            slug: "new",
            url: "http://localhost:9000/mcp",
            ..same_name
        };
        assert!(matches!(
            database.register_gateway(&same_url, &[]).await,
            Err(RegistrationError::UrlConflict)
        ));
        let different_url = GatewayRegistration {
            url: "http://localhost:9000/different",
            ..same_url
        };
        let collision = [RegisteredTool {
            id: "new-tool",
            ..tools[0]
        }];
        assert!(matches!(
            database.register_gateway(&different_url, &collision).await,
            Err(RegistrationError::ToolNameConflict)
        ));
    }
}
