// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{auth::TeamVisibility, database::Database, upstream::DiscoveredMetadata};

const MIGRATION: &str = include_str!("../migrations/002_catalog.sql");
const CATALOG_LOCK: &str = "SELECT pg_advisory_xact_lock(1128682067)";

#[derive(Clone, Copy)]
pub struct CatalogScope<'a> {
    pub email: Option<&'a str>,
    pub visibility: &'a TeamVisibility,
}

impl CatalogScope<'_> {
    fn can_own(&self) -> bool {
        self.email.is_some() && self.visibility != &TeamVisibility::Public
    }

    fn visible(&self, visibility: &str, team_id: Option<&str>, owner_email: Option<&str>) -> bool {
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

#[derive(Clone, Debug)]
pub struct CatalogTool {
    pub id: String,
    pub original_name: String,
    pub gateway_id: String,
    pub gateway_name: String,
    pub gateway_url: String,
    pub gateway_mode: String,
    pub gateway_transport: String,
    pub request_type: String,
    pub requires_gateway_policy: bool,
    pub definition: ToolDefinition,
}

#[derive(Clone, Copy)]
pub(crate) enum CatalogList {
    Resources,
    Templates,
    Prompts,
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
    pub description: Option<&'a str>,
    pub capabilities: &'a Value,
    pub visibility: &'a str,
    pub team_id: Option<&'a str>,
    pub owner_email: &'a str,
    pub tags: &'a [String],
}

pub struct RegisteredTool<'a> {
    pub id: &'a str,
    pub slug: &'a str,
    pub name: &'a str,
    pub definition: &'a ToolDefinition,
}

struct ResourceRegistration<'a> {
    uri: &'a str,
    template: Option<&'a str>,
    name: &'a str,
    title: Option<&'a str>,
    description: Option<&'a str>,
    mime: &'a str,
    size: Option<i32>,
}

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
type ToolRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    bool,
    String,
    Option<String>,
    String,
    String,
    Option<String>,
    Option<String>,
);

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

// Keep configured gateway and tool policies visible to callers before network dispatch.
macro_rules! tool_query {
    ($team_ids:literal) => {
        concat!(
            "WITH visible_team_ids(id) AS (", $team_ids, ")
             SELECT t.id, t.original_name, g.id, g.name, g.url, g.gateway_mode, g.transport, t.request_type,
                (
                    LOWER(COALESCE(g.auth_type, 'none')) NOT IN ('', 'none')
                    OR LOWER(COALESCE(t.auth_type, 'none')) NOT IN ('', 'none')
                    OR COALESCE(t.auth_value, '') <> ''
                    OR COALESCE(g.ca_certificate, '') <> ''
                    OR COALESCE(g.client_cert, '') <> ''
                    OR COALESCE(g.client_key, '') <> ''
                    OR COALESCE(t.jsonpath_filter, '') <> ''
                    OR COALESCE(t.timeout_ms, 0) <> 0
                    OR t.validation_refusal IS NOT NULL
                    OR ", non_empty_json!("g.auth_value"), "
                    OR ", non_empty_json!("g.oauth_config"), "
                    OR ", non_empty_json!("g.auth_query_params"), "
                    OR ", non_empty_json!("g.sigv4_config"), "
                    OR ", non_empty_json!("g.identity_propagation"), "
                    OR ", non_empty_json!("g.passthrough_headers"), "
                    OR ", non_empty_json!("g.add_headers"), "
                    OR ", non_empty_json!("g.remove_headers"), "
                    OR ", non_empty_json!("t.headers"), "
                    OR ", non_empty_json!("t.sigv4_config"), "
                    OR ", non_empty_json!("t.plugin_chain_pre"), "
                    OR ", non_empty_json!("t.plugin_chain_post"), "
                ),
                t.name, t.title, COALESCE(t.description, ''), CAST(t.input_schema AS TEXT),
                CAST(t.output_schema AS TEXT), CAST(t.annotations AS TEXT)
             FROM tools t
             JOIN gateways g ON g.id = t.gateway_id
             WHERE t.enabled = TRUE AND t.integration_type = 'MCP' AND t.name IS NOT NULL
                AND g.enabled = TRUE AND g.status = 'active'
                AND (CAST($2 AS TEXT) IS NULL OR t.name = $2)
                AND (CAST($3 AS TEXT) IS NULL OR t.id > $3)
                AND ", visible!("t"), "
                AND ", visible!("g"), "
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
    ($team_ids:literal, $columns:literal, $table:literal, $association:literal, $id:literal, $filter:literal) => {
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
        WHEN EXISTS (
            SELECT 1 FROM gateways g WHERE g.url = $2 AND
                ((g.visibility = 'public' AND $3 = 'public')
                 OR (g.visibility = 'team' AND $3 = 'team' AND g.team_id = $4)
                 OR (g.visibility = 'private' AND $3 = 'private' AND g.owner_email = $5))
                AND LOWER(COALESCE(g.auth_type, 'none')) IN ('', 'none')
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
    ($capabilities:literal, $tags:literal) => {
        concat!(
            "INSERT INTO gateways (
                id, name, slug, url, description, capabilities, tags, transport, enabled, created_at,
                updated_at, last_seen, reachable, created_by, owner_email, team_id, visibility, gateway_mode, status
            ) VALUES ($1, $2, $3, $4, $5, ", $capabilities, ", ", $tags, ", 'STREAMABLEHTTP', TRUE,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE, $8, $8, $9, $10, 'cache', 'active')"
        )
    };
}

macro_rules! insert_tool {
    ($input_schema:literal, $output_schema:literal, $annotations:literal) => {
        concat!(
            "INSERT INTO tools (
                id, gateway_id, name, original_name, custom_name_slug, custom_name, description, original_description,
                title, input_schema, output_schema, annotations, url, enabled, reachable, created_at, updated_at,
                jsonpath_filter, integration_type, request_type, created_by, owner_email, team_id, visibility
            ) VALUES ($1, $2, $3, $4, $5, $4, $6, $6, $7, ", $input_schema, ", ", $output_schema, ", ", $annotations, ",
                $11, TRUE, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '', 'MCP', 'STREAMABLEHTTP', $12, $12, $13, $14)"
        )
    };
}

impl Database {
    pub async fn migrate_catalog(&self) -> Result<(), sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
                sqlx::raw_sql(MIGRATION).execute(&mut *transaction).await?;
                transaction.commit().await
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *transaction).await?;
                sqlx::raw_sql(MIGRATION).execute(&mut *transaction).await?;
                transaction.commit().await
            }
        }
    }

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
    ) -> Result<Vec<CatalogTool>, sqlx::Error> {
        self.mcp_tools(scope, server_id, None, after_id, limit)
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

    pub async fn find_mcp_tool(
        &self,
        scope: CatalogScope<'_>,
        server_id: Option<&str>,
        name: &str,
    ) -> Result<Option<CatalogTool>, sqlx::Error> {
        let mut matches = self
            .mcp_tools(scope, server_id, Some(name), None, 2)
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
        self.register_discovered_gateway(gateway, tools, &DiscoveredMetadata::default())
            .await
    }

    pub(crate) async fn register_discovered_gateway(
        &self,
        gateway: &GatewayRegistration<'_>,
        tools: &[RegisteredTool<'_>],
        metadata: &DiscoveredMetadata,
    ) -> Result<(), RegistrationError> {
        validate_registration(gateway, tools)?;
        let capabilities = gateway.capabilities.to_string();
        let tags = serde_json::to_string(gateway.tags)
            .map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
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
                    .fetch_one(&mut *$tx)
                    .await?;
                match conflict.as_deref() {
                    Some("name") => return Err(RegistrationError::NameConflict),
                    Some("url") => return Err(RegistrationError::UrlConflict),
                    _ => {}
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
                        .execute(&mut *$tx)
                        .await?;
                }
                let resources = metadata.resources.iter().map(|item| ResourceRegistration {
                    uri: &item.uri, template: None, name: &item.name, title: item.title.as_deref(),
                    description: item.description.as_deref(), mime: item.mime_type.as_deref().unwrap_or("text/plain"),
                    size: item.size.and_then(|size| i32::try_from(size).ok()),
                });
                let templates = metadata.templates.iter().map(|item| ResourceRegistration {
                    uri: &item.uri_template, template: Some(&item.uri_template), name: &item.name,
                    title: item.title.as_deref(), description: item.description.as_deref(),
                    mime: item.mime_type.as_deref().unwrap_or("text/plain"), size: None,
                });
                let mut uris = HashSet::new();
                for resource in resources.chain(templates) {
                    if !uris.insert((resource.uri, resource.template.is_some())) { continue; }
                    let slug = slugify(resource.name);
                    let name = format!("{}-{slug}", gateway.slug);
                    if slug.is_empty() || name.len() > 255 || resource.uri.is_empty() || resource.uri.len() > 767 {
                        return Err(RegistrationError::Invalid("Invalid upstream resource"));
                    }
                    sqlx::query("INSERT INTO resources (id, uri, uri_template, name, original_name, custom_name_slug,
                        title, description, mime_type, size, gateway_id, owner_email, team_id, visibility)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
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
                        title, description, argument_schema, gateway_id, owner_email, team_id, visibility)
                        VALUES ($1,$2,$3,$3,$4,$5,$6,", $schema, ",$8,$9,$10,$11)"))
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
                    insert_gateway!("json($6)", "json($7)"),
                    insert_tool!("json($8)", "json($9)", "json($10)"),
                    "json($7)"
                );
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *transaction).await?;
                register!(
                    transaction,
                    tool_conflict_query!("SELECT json_array_elements_text(CAST($1 AS JSON))"),
                    insert_gateway!("CAST($6 AS JSON)", "CAST($7 AS JSON)"),
                    insert_tool!("CAST($8 AS JSON)", "CAST($9 AS JSON)", "CAST($10 AS JSON)"),
                    "CAST($7 AS JSON)"
                );
            }
        }
        Ok(())
    }
}

fn prompt_argument_schema(prompt: &rmcp::model::Prompt) -> Value {
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
    let mut result = String::new();
    let mut separator = false;
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'_' {
            if separator && !result.is_empty() {
                result.push('-');
            }
            result.push(char::from(byte.to_ascii_lowercase()));
            separator = false;
        } else if byte == b'-' || byte.is_ascii_whitespace() {
            separator = true;
        }
    }
    result.trim_matches('_').to_owned()
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
    let (
        id,
        original_name,
        gateway_id,
        gateway_name,
        gateway_url,
        gateway_mode,
        gateway_transport,
        request_type,
        requires_gateway_policy,
        name,
        title,
        description,
        input_schema,
        output_schema,
        annotations,
    ) = row;
    Ok(CatalogTool {
        id,
        original_name,
        gateway_id,
        gateway_name,
        gateway_url,
        gateway_mode,
        gateway_transport,
        request_type,
        requires_gateway_policy,
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
        database.migrate_identity().await.unwrap();
        database.migrate_catalog().await.unwrap();
        database.migrate_catalog().await.unwrap();
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
                .list_mcp_tools(public, None, None, 10)
                .await
                .unwrap()),
            ["01"]
        );
        assert_eq!(
            ids(database
                .list_mcp_tools(owner, None, Some("01"), 10)
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
                .list_mcp_tools(outsider, Some("fort-server"), None, 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            database
                .find_mcp_tool(outsider, Some("fort-server"), "public-echo")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            ids(database
                .list_mcp_tools(member, Some("fort-server"), Some("01"), 1)
                .await
                .unwrap()),
            ["02"]
        );
        assert!(
            database
                .find_mcp_tool(member, Some("fort-server"), "own-echo")
                .await
                .unwrap()
                .is_none()
        );

        let tool = database
            .find_mcp_tool(member, Some("fort-server"), "fort-echo")
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
        sqlx::query(
            "UPDATE gateways SET passthrough_headers = '[\"Authorization\"]' WHERE id = 'fort'",
        )
        .execute(pool)
        .await
        .unwrap();
        assert!(
            database
                .find_mcp_tool(member, Some("fort-server"), "fort-echo")
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
                .find_mcp_tool(member, Some("fort-server"), "fort-echo")
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
                .find_mcp_tool(public, None, "fixture-echo")
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
