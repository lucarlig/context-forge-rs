// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use jiff::Timestamp;
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    catalog::{
        INSERT_RESOURCE, POSTGRES_TOOL_INSERT, RegistrationError, SQLITE_TOOL_INSERT,
        ToolDefinition, prompt_argument_schema, resource_registrations, slugify,
    },
    upstream::DiscoveredMetadata,
};

use super::*;

pub(crate) struct CatalogRefreshInput<'a> {
    pub(crate) tools: &'a [ToolDefinition],
    pub(crate) capabilities: &'a Value,
    pub(crate) metadata: &'a DiscoveredMetadata,
    pub(crate) include_resources: bool,
    pub(crate) include_prompts: bool,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CatalogChanges {
    pub(crate) tools_added: usize,
    pub(crate) tools_updated: usize,
    pub(crate) tools_removed: usize,
    pub(crate) resources_added: usize,
    pub(crate) resources_updated: usize,
    pub(crate) resources_removed: usize,
    pub(crate) prompts_added: usize,
    pub(crate) prompts_updated: usize,
    pub(crate) prompts_removed: usize,
}

impl CatalogChanges {
    pub(crate) fn changed(&self) -> bool {
        [
            self.tools_added,
            self.tools_updated,
            self.tools_removed,
            self.resources_added,
            self.resources_updated,
            self.resources_removed,
            self.prompts_added,
            self.prompts_updated,
            self.prompts_removed,
        ]
        .into_iter()
        .any(|count| count > 0)
    }
}

#[derive(sqlx::FromRow)]
struct StoredTool {
    id: String,
    original_name: String,
    original_description: Option<String>,
    title: Option<String>,
    input_schema: String,
    output_schema: Option<String>,
    annotations: Option<String>,
}

#[derive(sqlx::FromRow)]
struct StoredResource {
    id: String,
    uri: String,
    uri_template: Option<String>,
    original_name: Option<String>,
    title: Option<String>,
    description: Option<String>,
    mime_type: Option<String>,
    size: Option<i32>,
}

#[derive(sqlx::FromRow)]
struct StoredPrompt {
    id: String,
    original_name: String,
    title: Option<String>,
    description: Option<String>,
    argument_schema: Option<String>,
}

const STORED_TOOLS: &str = "
    SELECT id, original_name, original_description, title,
        CAST(input_schema AS TEXT) AS input_schema, CAST(output_schema AS TEXT) AS output_schema,
        CAST(annotations AS TEXT) AS annotations
    FROM tools WHERE gateway_id = $1 AND integration_type = 'MCP'";
const STORED_RESOURCES: &str = "
    SELECT id, uri, uri_template, original_name, title, description, mime_type, size
    FROM resources WHERE gateway_id = $1";
const STORED_PROMPTS: &str = "
    SELECT id, original_name, title, description, CAST(argument_schema AS TEXT) AS argument_schema
    FROM prompts WHERE gateway_id = $1";

const TOOL_CONFLICT: &str = "
    SELECT EXISTS (
        SELECT 1 FROM tools WHERE name = $1 AND visibility = $2
        AND ($2 = 'public' OR ($2 = 'team' AND team_id = $3)
             OR ($2 = 'private' AND owner_email = $4))
    )";
const TOOL_DEPENDENCIES: &[(&str, &str)] = &[(
    "tool_metrics",
    "DELETE FROM tool_metrics WHERE tool_id = $1",
)];
const TOOL_REMOVAL: &[&str] = &[
    "DELETE FROM server_tool_association WHERE tool_id = $1",
    "DELETE FROM tools WHERE id = $1",
];
const RESOURCE_DEPENDENCIES: &[(&str, &str)] = &[
    (
        "resource_metrics",
        "DELETE FROM resource_metrics WHERE resource_id = $1",
    ),
    (
        "resource_subscriptions",
        "DELETE FROM resource_subscriptions WHERE resource_id = $1",
    ),
];
const RESOURCE_REMOVAL: &[&str] = &[
    "DELETE FROM server_resource_association WHERE resource_id = $1",
    "DELETE FROM resources WHERE id = $1",
];
const PROMPT_DEPENDENCIES: &[(&str, &str)] = &[(
    "prompt_metrics",
    "DELETE FROM prompt_metrics WHERE prompt_id = $1",
)];
const PROMPT_REMOVAL: &[&str] = &[
    "DELETE FROM server_prompt_association WHERE prompt_id = $1",
    "DELETE FROM prompts WHERE id = $1",
];

fn stored_json(raw: Option<&str>) -> Option<Value> {
    raw.and_then(|raw| serde_json::from_str(raw).ok())
        .filter(|value: &Value| !value.is_null())
}

macro_rules! json_parameter {
    (sqlite, $parameter:literal) => {
        concat!("json(", $parameter, ")")
    };
    (postgres, $parameter:literal) => {
        concat!("CAST(", $parameter, " AS JSON)")
    };
}

macro_rules! refresh_metadata {
    ($tx:ident, $exists:literal, $dialect:ident, $gateway:ident, $input:ident, $changes:ident) => {{
        if $input.include_resources {
            let mut existing: HashMap<_, _> = sqlx::query_as::<_, StoredResource>(STORED_RESOURCES)
                .bind(&$gateway.id).fetch_all(&mut *$tx).await?
                .into_iter().map(|row| ((row.uri.clone(), row.uri_template.is_some()), row)).collect();
            let mut seen = HashSet::new();
            for item in resource_registrations($input.metadata) {
                if !seen.insert((item.uri, item.template.is_some())) {
                    continue;
                }
                let slug = slugify(item.name);
                let name = format!("{}-{slug}", $gateway.slug);
                if slug.is_empty() || name.len() > 255 || item.uri.is_empty() || item.uri.len() > 767 {
                    return Err(RegistrationError::Invalid("Invalid upstream resource"));
                }
                if let Some(previous) = existing.remove(&(item.uri.to_owned(), item.template.is_some())) {
                    if previous.original_name.as_deref() != Some(item.name)
                        || previous.title.as_deref() != item.title
                        || previous.description.as_deref() != item.description
                        || previous.mime_type.as_deref() != Some(item.mime)
                        || previous.size != item.size
                    {
                        sqlx::query("UPDATE resources SET original_name = $2, title = $3,
                            description = $4, mime_type = $5, size = $6, updated_at = CURRENT_TIMESTAMP WHERE id = $1")
                            .bind(previous.id).bind(item.name).bind(item.title).bind(item.description)
                            .bind(item.mime).bind(item.size).execute(&mut *$tx).await?;
                        $changes.resources_updated += 1;
                    }
                } else {
                    sqlx::query(INSERT_RESOURCE)
                        .bind(Uuid::new_v4().simple().to_string())
                        .bind(item.uri).bind(item.template).bind(name).bind(item.name).bind(slug)
                        .bind(item.title).bind(item.description).bind(item.mime).bind(item.size)
                        .bind(&$gateway.id).bind($gateway.owner_email.as_deref())
                        .bind($gateway.team_id.as_deref()).bind(&$gateway.visibility)
                        .execute(&mut *$tx).await?;
                    $changes.resources_added += 1;
                }
            }
            for previous in existing.into_values() {
                delete_catalog_rows!($tx, &previous.id, $exists, RESOURCE_DEPENDENCIES, RESOURCE_REMOVAL);
                $changes.resources_removed += 1;
            }
        }

        if $input.include_prompts {
            let mut existing: HashMap<_, _> = sqlx::query_as::<_, StoredPrompt>(STORED_PROMPTS)
                .bind(&$gateway.id).fetch_all(&mut *$tx).await?
                .into_iter().map(|row| (row.original_name.clone(), row)).collect();
            let mut seen = HashSet::new();
            for item in &$input.metadata.prompts {
                if !seen.insert(item.name.as_str()) {
                    continue;
                }
                let slug = slugify(&item.name);
                let name = format!("{}-{slug}", $gateway.slug);
                if slug.is_empty() || name.len() > 255 || item.name.len() > 255 {
                    return Err(RegistrationError::Invalid("Invalid upstream prompt"));
                }
                let arguments = prompt_argument_schema(item);
                if let Some(previous) = existing.remove(&item.name) {
                    if previous.title != item.title || previous.description != item.description
                        || stored_json(previous.argument_schema.as_deref()).as_ref() != Some(&arguments)
                    {
                        sqlx::query(concat!("UPDATE prompts SET title = $2, description = $3,
                            argument_schema = ", json_parameter!($dialect, "$4"),
                            ", updated_at = CURRENT_TIMESTAMP WHERE id = $1"))
                            .bind(previous.id).bind(&item.title).bind(&item.description)
                            .bind(arguments.to_string()).execute(&mut *$tx).await?;
                        $changes.prompts_updated += 1;
                    }
                } else {
                    sqlx::query(concat!("INSERT INTO prompts (id, name, original_name, custom_name,
                        custom_name_slug, title, description, argument_schema, gateway_id, owner_email,
                        team_id, visibility, enabled, tags, created_at, updated_at)
                        VALUES ($1,$2,$3,$3,$4,$5,$6,", json_parameter!($dialect, "$7"), ",$8,$9,$10,$11,
                            TRUE,'[]',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
                        .bind(Uuid::new_v4().simple().to_string()).bind(name).bind(&item.name)
                        .bind(slug).bind(&item.title).bind(&item.description).bind(arguments.to_string())
                        .bind(&$gateway.id).bind($gateway.owner_email.as_deref())
                        .bind($gateway.team_id.as_deref()).bind(&$gateway.visibility)
                        .execute(&mut *$tx).await?;
                    $changes.prompts_added += 1;
                }
            }
            for previous in existing.into_values() {
                delete_catalog_rows!($tx, &previous.id, $exists, PROMPT_DEPENDENCIES, PROMPT_REMOVAL);
                $changes.prompts_removed += 1;
            }
        }
    }};
}

impl Database {
    pub(crate) async fn refresh_catalog(
        &self,
        gateway: &GatewayRecord,
        input: CatalogRefreshInput<'_>,
    ) -> Result<Option<CatalogChanges>, RegistrationError> {
        let mut names = HashSet::new();
        for tool in input.tools {
            let slug = slugify(&tool.name);
            if slug.is_empty() || slug.len() + gateway.slug.len() >= 255 || tool.name.len() > 255 {
                return Err(RegistrationError::Invalid("Invalid upstream tool name"));
            }
            if !names.insert(slug) {
                return Err(RegistrationError::ToolNameConflict);
            }
        }
        let mut changes = CatalogChanges::default();
        macro_rules! sync {
            ($transaction:ident, $lock:literal, $exists:literal, $insert_tool:expr,
             $dialect:ident, $now:literal) => {{
                let id = sqlx::query_scalar::<_, String>(locked_gateway_query!($lock))
                    .bind(&gateway.id).bind(gateway.version).bind(&gateway.updated_at)
                    .bind(&gateway.visibility).bind(gateway.owner_email.as_deref())
                    .bind(gateway.team_id.as_deref())
                    .fetch_optional(&mut *$transaction).await?;
                if id.is_none() {
                    return Ok(None);
                }
                let mut stored_tools: HashMap<_, _> = sqlx::query_as::<_, StoredTool>(STORED_TOOLS)
                    .bind(&gateway.id).fetch_all(&mut *$transaction).await?
                    .into_iter().map(|tool| (tool.original_name.clone(), tool)).collect();
                let incoming: HashSet<&str> = input.tools.iter().map(|tool| tool.name.as_str()).collect();
                for (_, stale) in stored_tools.extract_if(|name, _| !incoming.contains(name.as_str())) {
                    delete_catalog_rows!($transaction, &stale.id, $exists, TOOL_DEPENDENCIES, TOOL_REMOVAL);
                    changes.tools_removed += 1;
                }
                for tool in input.tools {
                    let annotations = tool.annotations.clone().unwrap_or_else(|| json!({}));
                    if let Some(previous) = stored_tools.remove(&tool.name) {
                        let description = (!tool.description.is_empty()).then_some(tool.description.as_str());
                        if previous.original_description.as_deref().filter(|text| !text.is_empty()) != description
                            || previous.title != tool.title
                            || stored_json(Some(&previous.input_schema)).as_ref() != Some(&tool.input_schema)
                            || stored_json(previous.output_schema.as_deref()) != tool.output_schema
                            || stored_json(previous.annotations.as_deref()).unwrap_or_else(|| json!({})) != annotations
                        {
                            sqlx::query(concat!("UPDATE tools SET
                                description = CASE WHEN COALESCE(description, '') = COALESCE(original_description, '') THEN $2 ELSE description END,
                                original_description = $2, title = $3, input_schema = ", json_parameter!($dialect, "$4"), ",
                                output_schema = ", json_parameter!($dialect, "$5"), ", annotations = ", json_parameter!($dialect, "$6"), ",
                                updated_at = CURRENT_TIMESTAMP WHERE id = $1"))
                                .bind(previous.id).bind(&tool.description).bind(&tool.title)
                                .bind(tool.input_schema.to_string()).bind(tool.output_schema.as_ref().map(Value::to_string))
                                .bind(annotations.to_string()).execute(&mut *$transaction).await?;
                            changes.tools_updated += 1;
                        }
                    } else {
                        let slug = slugify(&tool.name);
                        let name = format!("{}-{slug}", gateway.slug);
                        if sqlx::query_scalar::<_,bool>(TOOL_CONFLICT)
                            .bind(&name).bind(&gateway.visibility).bind(gateway.team_id.as_deref())
                            .bind(gateway.owner_email.as_deref()).fetch_one(&mut *$transaction).await?
                        {
                            return Err(RegistrationError::ToolNameConflict);
                        }
                        sqlx::query($insert_tool)
                            .bind(Uuid::new_v4().simple().to_string()).bind(&gateway.id)
                            .bind(name).bind(&tool.name).bind(slug).bind(&tool.description).bind(&tool.title)
                            .bind(tool.input_schema.to_string()).bind(tool.output_schema.as_ref().map(Value::to_string))
                            .bind(annotations.to_string()).bind(&gateway.url).bind(gateway.owner_email.as_deref())
                            .bind(gateway.team_id.as_deref()).bind(&gateway.visibility).bind(&gateway.transport)
                            .execute(&mut *$transaction).await?;
                        changes.tools_added += 1;
                    }
                }
                refresh_metadata!($transaction, $exists, $dialect, gateway, input, changes);
                let now = Timestamp::now().to_string();
                sqlx::query(concat!("UPDATE gateways SET capabilities = ", json_parameter!($dialect, "$2"),
                    ", last_refresh_at = ", $now, ", updated_at = ", $now, " WHERE id = $1"))
                    .bind(&gateway.id).bind(input.capabilities.to_string()).bind(now)
                    .execute(&mut *$transaction).await?;
                $transaction.commit().await?;
                Ok(Some(changes))
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
                sync!(
                    transaction,
                    "",
                    "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = $1)",
                    SQLITE_TOOL_INSERT,
                    sqlite,
                    "$3"
                )
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *transaction).await?;
                sync!(
                    transaction,
                    " FOR UPDATE",
                    "SELECT to_regclass(CAST($1 AS TEXT)) IS NOT NULL",
                    POSTGRES_TOOL_INSERT,
                    postgres,
                    "CAST(CAST($3 AS TEXT) AS TIMESTAMPTZ)"
                )
            }
        }
    }
}
