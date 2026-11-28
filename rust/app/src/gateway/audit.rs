// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use axum::extract::RawQuery;
use regex::Regex;

use super::{catalog_api::CatalogApiError, *};
use crate::{
    audit::{AuditFilters, AuditWrite, StoredEvent, parse_time},
    catalog::{PromptRecord, ResourceRecord, ServerRecord, ToolRecord},
    config::{flag, value},
    gateway_records::GatewayRecord,
};

pub(super) struct AuditSettings {
    record: bool,
    queries: bool,
    user_identifier: Regex,
}

const USER_IDENTIFIER: &str = r"^[a-zA-Z0-9._%+@-]+$";

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            record: false,
            queries: true,
            user_identifier: Regex::new(USER_IDENTIFIER).expect("valid user identifier pattern"),
        }
    }
}

pub(super) fn router(service: &Arc<GatewayService>) -> Router {
    if !service.audit.queries {
        return Router::new();
    }
    service.access.protect_browser_api(
        Router::new()
            .route("/api/logs/audit-trails", get(trails))
            .route("/api/logs/activity", get(activity))
            .with_state(service.clone()),
        None,
    )
}

pub(super) enum Subject<'a> {
    Tool(&'a ToolRecord),
    Resource(&'a ResourceRecord),
    Prompt(&'a PromptRecord),
    Server(&'a ServerRecord),
    Gateway(&'a GatewayRecord),
    RegisteredGateway {
        registration: &'a GatewayRegistration<'a>,
        address: Option<&'a str>,
        agent: Option<&'a str>,
        via: &'a str,
    },
}

pub(super) enum Change {
    Create,
    Update,
    Delete,
    State,
    ViewServer,
}

impl GatewayService {
    pub fn with_audit_settings(mut self) -> Result<Self, Box<dyn Error + Send + Sync>> {
        self.audit = AuditSettings {
            record: flag("AUDIT_TRAIL_ENABLED")?.unwrap_or(false),
            queries: flag("STRUCTURED_LOGGING_ENABLED")?.unwrap_or(true),
            user_identifier: Regex::new(&value(
                "VALIDATION_USER_IDENTIFIER_PATTERN",
                USER_IDENTIFIER,
            )?)?,
        };
        Ok(self)
    }

    pub(super) async fn audit_catalog(
        &self,
        actor: &Principal,
        change: Change,
        subject: Subject<'_>,
    ) {
        if !self.audit.record {
            return;
        }
        let after;
        let mut context = None;
        macro_rules! origin {
            ($row:ident) => {
                match change {
                    Change::Create => (
                        $row.created_from_ip.as_deref(),
                        $row.created_user_agent.as_deref(),
                        $row.created_via.as_deref(),
                    ),
                    Change::Update => (
                        $row.modified_from_ip.as_deref(),
                        $row.modified_user_agent.as_deref(),
                        $row.modified_via.as_deref(),
                    ),
                    _ => (None, None, None),
                }
            };
        }
        let (kind, id, name, team, (address, user_agent, via)) = match subject {
            Subject::Tool(row) => {
                after = match change {
                    Change::Create => Some(json!({"name":row.name,"display_name":row.display_name,
                        "visibility":row.visibility,"integration_type":row.integration_type})),
                    Change::Update => Some(
                        json!({"name":row.name,"display_name":row.display_name,"version":row.version}),
                    ),
                    Change::State => Some(json!({"enabled":row.enabled,"reachable":row.reachable})),
                    _ => None,
                };
                (
                    "tool",
                    row.id.as_str(),
                    row.name.as_str(),
                    row.team_id.as_deref(),
                    origin!(row),
                )
            }
            Subject::Resource(row) => {
                after = match change {
                    Change::Create => Some(json!({"name":row.name,"visibility":row.visibility})),
                    Change::Update => Some(json!({"name":row.name,"version":row.version})),
                    Change::State => Some(json!({"enabled":row.enabled})),
                    _ => None,
                };
                (
                    "resource",
                    row.id.as_str(),
                    row.name.as_str(),
                    row.team_id.as_deref(),
                    origin!(row),
                )
            }
            Subject::Prompt(row) => {
                after = match change {
                    Change::Create => Some(json!({"name":row.name,"visibility":row.visibility})),
                    Change::Update => Some(json!({"name":row.name,"version":row.version})),
                    Change::State => Some(json!({"enabled":row.enabled})),
                    _ => None,
                };
                (
                    "prompt",
                    row.id.as_str(),
                    row.name.as_str(),
                    row.team_id.as_deref(),
                    origin!(row),
                )
            }
            Subject::Server(row) => {
                context = Some(
                    json!({"server_name":row.name,"visibility":row.visibility,"version":row.version}),
                );
                after = matches!(change, Change::State).then(|| json!({"enabled":row.enabled}));
                (
                    "server",
                    row.id.as_str(),
                    row.name.as_str(),
                    row.team_id.as_deref(),
                    origin!(row),
                )
            }
            Subject::Gateway(row) => {
                after = match change {
                    Change::Create | Change::Update => Some(
                        json!({"name":row.name,"visibility":row.visibility,"transport":row.transport}),
                    ),
                    Change::State => Some(json!({"enabled":row.enabled,"reachable":row.reachable})),
                    _ => None,
                };
                (
                    "gateway",
                    row.id.as_str(),
                    row.name.as_str(),
                    row.team_id.as_deref(),
                    origin!(row),
                )
            }
            Subject::RegisteredGateway {
                registration,
                address,
                agent,
                via,
            } => {
                after = Some(
                    json!({"name":registration.name,"visibility":registration.visibility,
                    "transport":registration.transport.name()}),
                );
                (
                    "gateway",
                    registration.id,
                    registration.name,
                    registration.team_id,
                    (address, agent, Some(via)),
                )
            }
        };
        let action = match change {
            Change::Create => format!("create_{kind}"),
            Change::Update => format!("update_{kind}"),
            Change::Delete => format!("delete_{kind}"),
            Change::State if kind == "server" => {
                let enabled = after
                    .as_ref()
                    .and_then(|state| state["enabled"].as_bool())
                    .unwrap_or(false);
                if enabled {
                    "activate_server"
                } else {
                    "deactivate_server"
                }
                .to_owned()
            }
            Change::State => format!("set_{kind}_state"),
            Change::ViewServer => "view_server".to_owned(),
        };
        let view = matches!(change, Change::ViewServer);
        if let Some(via) = via {
            let key = if matches!(change, Change::Create) {
                "created_via"
            } else {
                "modified_via"
            };
            context.get_or_insert_with(|| json!({}))[key] = json!(via);
        }
        let entry = AuditWrite {
            action: &action,
            resource_type: kind,
            id,
            name: (kind != "server" || view).then_some(name),
            user_id: if view { "system" } else { &actor.email },
            user_email: (kind != "server").then_some(&actor.email),
            team,
            address,
            user_agent,
            before: (kind != "server" && matches!(change, Change::Delete))
                .then(|| json!({"name":name})),
            after,
            context,
        };
        // Catalog operations have already committed. Audit failure must preserve their result.
        if let Err(error) = self.database.record_audit(entry).await {
            tracing::error!(%error, %action, resource_type=kind, resource_id=id, "Audit trail write failed");
        }
    }
}

async fn require(
    service: &GatewayService,
    principal: &Principal,
    global: bool,
) -> Result<(), CatalogApiError> {
    if (!global || principal.visibility == TeamVisibility::Admin)
        && service
            .access
            .allows(principal, "audit:read", RoleContext::AnyTeam, true)
            .await?
    {
        Ok(())
    } else {
        Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ))
    }
}

async fn trails(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    RawQuery(query): RawQuery,
) -> Result<Json<Vec<Value>>, CatalogApiError> {
    require(&service, &principal, true).await?;
    let mut filters = AuditFilters {
        limit: 100,
        ..Default::default()
    };
    for (key, value) in url::form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes()) {
        match key.as_ref() {
            "action" => filters.actions.push(value.into_owned()),
            "resource_type" => filters.resource_types.push(value.into_owned()),
            "user_id" => {
                let pattern = &service.audit.user_identifier;
                if value.chars().count() > 255 {
                    return Err(invalid_query(
                        &key,
                        "string_too_long",
                        "String should have at most 255 characters",
                        Some(json!({"max_length":255})),
                    ));
                }
                if !pattern.is_match(&value) {
                    return Err(invalid_query(
                        &key,
                        "string_pattern_mismatch",
                        &format!("String should match pattern '{}'", pattern.as_str()),
                        Some(json!({"pattern":pattern.as_str()})),
                    ));
                }
                filters.user = Some(value.into_owned());
            }
            "requires_review" => {
                filters.review = Some(catalog_query_flag(Some(&value)).map_err(|_| {
                    invalid_query(
                        &key,
                        "bool_parsing",
                        "Input should be a valid boolean, unable to interpret input",
                        None,
                    )
                })?)
            }
            "start_time" => filters.since = Some(date_parameter(&key, &value)?),
            "end_time" => filters.until = Some(date_parameter(&key, &value)?),
            "limit" => filters.limit = number_parameter(&key, &value, 1, 1000)?,
            "offset" => filters.offset = number_parameter(&key, &value, 0, i64::MAX)?,
            _ => {}
        }
    }
    let postgres = matches!(service.database, Database::Postgres(_));
    let rows = service
        .database
        .audit_trails(filters)
        .await
        .map_err(|error| failed(error, "Audit trails query failed"))?;
    Ok(Json(rows.iter().map(|row| row.trail(postgres)).collect()))
}

async fn activity(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, CatalogApiError> {
    require(&service, &principal, false).await?;
    let mut limit = 50;
    let mut since = None;
    for (key, value) in url::form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes()) {
        match key.as_ref() {
            "limit" => limit = number_parameter(&key, &value, 1, 100)?,
            "since" => since = Some(date_parameter(&key, &value)?),
            _ => {}
        }
    }
    let security = service
        .access
        .allows(&principal, "security:read", RoleContext::AnyTeam, true)
        .await?;
    let rows = service
        .database
        .audit_activity(
            &principal.visibility,
            &principal.email,
            security,
            since,
            limit,
        )
        .await
        .map_err(|error| failed(error, "Activity feed query failed"))?;
    Ok(Json(
        json!({"items":rows.iter().map(render_activity).collect::<Vec<_>>()}),
    ))
}

fn number_parameter(key: &str, value: &str, min: i64, max: i64) -> Result<i64, CatalogApiError> {
    let number = value.parse().map_err(|_| {
        invalid_query(
            key,
            "int_parsing",
            "Input should be a valid integer, unable to parse string as an integer",
            None,
        )
    })?;
    if number < min {
        return Err(invalid_query(
            key,
            "greater_than_equal",
            &format!("Input should be greater than or equal to {min}"),
            Some(json!({"ge":min})),
        ));
    }
    if number > max {
        return Err(invalid_query(
            key,
            "less_than_equal",
            &format!("Input should be less than or equal to {max}"),
            Some(json!({"le":max})),
        ));
    }
    Ok(number)
}

fn date_parameter(key: &str, value: &str) -> Result<Timestamp, CatalogApiError> {
    if let Some(time) = parse_time(value) {
        return Ok(time);
    }
    if let Ok(date) = value.parse::<jiff::civil::Date>()
        && let Ok(time) = jiff::tz::Offset::UTC.to_timestamp(date.at(0, 0, 0, 0))
    {
        return Ok(time);
    }
    let reason = if value.len() < 10 {
        "input is too short"
    } else if !value.as_bytes()[..4].iter().all(u8::is_ascii_digit) {
        "invalid character in year"
    } else {
        "invalid date or datetime"
    };
    Err(invalid_query(
        key,
        "datetime_from_date_parsing",
        &format!("Input should be a valid datetime or date, {reason}"),
        Some(json!({"error":reason})),
    ))
}

fn invalid_query(key: &str, kind: &str, message: &str, context: Option<Value>) -> CatalogApiError {
    let mut error = json!({"loc":["query",key],"type":kind,"msg":message});
    if let Some(context) = context {
        error["ctx"] = context;
    }
    CatalogApiError(StatusCode::UNPROCESSABLE_ENTITY, json!({"detail":[error]}))
}

fn failed(error: sqlx::Error, message: &'static str) -> CatalogApiError {
    tracing::error!(%error, "{message}");
    CatalogApiError::detail(StatusCode::INTERNAL_SERVER_ERROR, message)
}

fn label(kind: &str) -> String {
    match kind {
        "gateway" | "mcp_server" => "MCP server".into(),
        "server" => "virtual server".into(),
        "a2a_agent" => "A2A agent".into(),
        "tool" | "resource" | "prompt" | "plugin" => kind.to_owned(),
        _ => capitalized(&kind.replace('_', " ").to_lowercase()),
    }
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().to_string() + chars.as_str())
        .unwrap_or_default()
}

fn verbs(action: &str) -> (String, Option<String>, bool) {
    if action.eq_ignore_ascii_case("create_gateway") {
        return ("registered".into(), Some("register".into()), false);
    }
    if action.eq_ignore_ascii_case("delete_gateway") {
        return ("deregistered".into(), Some("deregister".into()), false);
    }
    let lower = action.to_ascii_lowercase();
    let mut words = lower.split('_');
    let mut head = words.next().unwrap_or("");
    let mut prefix = String::new();
    while head == "bulk" {
        prefix.push_str("bulk ");
        head = words.next().unwrap_or("");
    }
    let (past, infinitive) = match head {
        "create" => ("created", "create"),
        "update" => ("updated", "update"),
        "delete" => ("deleted", "delete"),
        "read" => ("accessed", "read"),
        "execute" => ("executed", "execute"),
        "login" => ("logged in", "log in"),
        "view" => ("viewed", "view"),
        "invoke" => ("invoked", "invoke"),
        "browse" => ("browsed", "browse"),
        "activate" => ("enabled", "enable"),
        "deactivate" => ("disabled", "disable"),
        _ => return (action.replace('_', " "), None, false),
    };
    let info = matches!(head, "read" | "view" | "browse" | "execute" | "invoke");
    (
        format!("{prefix}{past}"),
        Some(format!("{prefix}{infinitive}")),
        info,
    )
}

fn state_action(action: &str) -> bool {
    matches!(
        action,
        "set_gateway_state" | "set_tool_state" | "set_prompt_state" | "set_resource_state"
    )
}

fn state_transition(values: Option<&str>) -> Option<(&'static str, &'static str)> {
    let state: Value = serde_json::from_str(values?).ok()?;
    match (state["enabled"].as_bool(), state["reachable"].as_bool()) {
        (Some(false), _) => Some(("disabled", "success")),
        (_, Some(false)) => Some(("went offline", "warning")),
        (_, Some(true)) => Some(("came online", "success")),
        (Some(true), _) => Some(("enabled", "success")),
        _ => None,
    }
}

fn render_activity(row: &StoredEvent) -> Value {
    let timestamp = parse_time(&row.stamp).map(|time| time.to_string());
    let correlation = row.correlation_id.as_deref().unwrap_or_default();
    if row.source == "security" {
        let status = match row
            .severity
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "critical" | "high" => "error",
            "medium" => "warning",
            _ => "info",
        };
        return json!({
            "id":format!("security:{}",row.id), "timestamp":timestamp, "source":"security",
            "title":capitalized(&row.action.replace('_'," ").to_lowercase()), "description":row.error_message,
            "status":status, "resource_type":row.resource_type, "resource_name":row.user_email.as_deref().unwrap_or_default(),
            "actor":row.user_email.as_deref().filter(|value| !value.is_empty()).unwrap_or("system"), "correlation_id":correlation,
        });
    }
    let label = label(&row.resource_type);
    let title_label = capitalized(&label);
    let actor = row
        .user_email
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(&row.user_id);
    let name = row
        .resource_name
        .as_deref()
        .filter(|value| !value.is_empty())
        .or(row.resource_id.as_deref())
        .unwrap_or_default();
    let object = if name.is_empty() {
        title_label.clone()
    } else {
        format!("{title_label} '{name}'")
    };
    let state = state_action(&row.action);
    let transition = state
        .then(|| state_transition(row.new_values.as_deref()))
        .flatten();
    let (past, infinitive, info) = verbs(&row.action);
    let (title, description, status) = if !row.success {
        let (title, mut description) = if state {
            (
                format!("Failed to update {label} state"),
                format!("{object} state update failed."),
            )
        } else if let Some(verb) = infinitive {
            (
                format!("Failed to {verb} {label}"),
                format!("{object} failed to {verb}."),
            )
        } else {
            (
                format!("{title_label} {past} failed"),
                format!("{object} {past} failed."),
            )
        };
        if let Some(error) = row
            .error_message
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            description.push(' ');
            description.push_str(error);
        }
        (title, description, "error")
    } else {
        let (verb, status) = transition.unwrap_or((
            if state { "state updated" } else { &past },
            if info { "info" } else { "success" },
        ));
        let by = if actor.is_empty() || actor == "system" {
            String::new()
        } else {
            format!(" by {actor}")
        };
        let was = if matches!(verb, "went offline" | "came online") {
            ""
        } else {
            "was "
        };
        let writer = row
            .context
            .as_deref()
            .and_then(|context| serde_json::from_str::<Value>(context).ok());
        let description = writer
            .as_ref()
            .and_then(|context| context["description"].as_str())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{object} {was}{verb}{by}."));
        (
            format!("{title_label} {verb}"),
            description,
            if row.requires_review {
                "warning"
            } else {
                status
            },
        )
    };
    json!({
        "id":format!("audit:{}",row.id), "timestamp":timestamp, "source":"audit",
        "title":title, "description":description, "status":status, "resource_type":row.resource_type,
        "resource_name":name, "actor":actor, "correlation_id":correlation,
    })
}
