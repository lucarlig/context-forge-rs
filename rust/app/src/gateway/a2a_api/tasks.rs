// SPDX-License-Identifier: Apache-2.0

use base64::{Engine, engine::general_purpose::URL_SAFE};

use super::*;
use crate::catalog::{AgentTask, AgentTaskCursor, TaskContinuation, terminal_task_state};

const DEFAULT_PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 100;
const MAX_MESSAGE_PARTS: usize = 50;
const MAX_TEXT_LENGTH: usize = 65_536;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TaskList {
    state: Option<String>,
    page_size: Option<i64>,
    page_token: Option<String>,
}

pub(super) async fn list(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(agent): Path<String>,
    Query(query): Query<TaskList>,
) -> Result<Json<Value>, CatalogApiError> {
    manageable(&app, &principal, &agent, "a2a.read").await?;
    let size = query.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&size) {
        return Err(invalid("pageSize must be between 1 and 100"));
    }
    if query.state.as_deref().is_some_and(|state| {
        !matches!(
            state,
            "submitted"
                | "working"
                | "input-required"
                | "auth-required"
                | "completed"
                | "canceled"
                | "failed"
                | "rejected"
        )
    }) {
        return Err(invalid("Invalid task state"));
    }
    let after = decode_cursor(query.page_token.as_deref())?;
    let mut tasks = app
        .database
        .agent_tasks_page(&agent, query.state.as_deref(), after.as_ref(), size + 1)
        .await?;
    let next = if tasks.len() > size as usize {
        tasks.truncate(size as usize);
        let cursor = tasks.last().expect("nonempty task page").cursor();
        let data = serde_json::to_vec(&cursor).map_err(|_| CatalogApiError::unavailable())?;
        URL_SAFE.encode(data)
    } else {
        String::new()
    };
    let summaries = tasks
        .iter()
        .map(|task| task.wire(false))
        .collect::<Vec<_>>();
    Ok(Json(json!({"tasks":summaries,"nextPageToken":next})))
}

fn decode_cursor(token: Option<&str>) -> Result<Option<AgentTaskCursor>, CatalogApiError> {
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        return Ok(None);
    };
    let bad = || CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid pageToken");
    if token.len() > 512 {
        return Err(bad());
    }
    let bytes = URL_SAFE.decode(token).map_err(|_| bad())?;
    let cursor: AgentTaskCursor = serde_json::from_slice(&bytes).map_err(|_| bad())?;
    if cursor.row_id.is_empty()
        || cursor.row_id.chars().count() > 36
        || (cursor.updated_at.parse::<jiff::civil::DateTime>().is_err()
            && cursor.updated_at.parse::<Timestamp>().is_err())
    {
        return Err(bad());
    }
    Ok(Some(cursor))
}

pub(super) async fn detail(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path((agent, task)): Path<(String, String)>,
) -> Result<Json<Value>, CatalogApiError> {
    manageable(&app, &principal, &agent, "a2a.read").await?;
    let task = app
        .database
        .agent_task(&agent, &task)
        .await?
        .ok_or_else(|| missing(&task))?;
    Ok(Json(task.wire(true)))
}

pub(super) async fn cancel(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path((agent, task)): Path<(String, String)>,
) -> Result<Json<Value>, CatalogApiError> {
    manageable(&app, &principal, &agent, "a2a.invoke").await?;
    let task = app
        .database
        .cancel_agent_task(&agent, &task)
        .await?
        .ok_or_else(|| missing(&task))?;
    tracing::info!(actor = %principal.email, agent_id = %agent, task_id = %task.task_id, state = %task.state, "A2A task cancellation");
    Ok(Json(task.wire(true)))
}

#[derive(Deserialize)]
pub(super) struct FollowUp {
    text: Option<String>,
    message: Option<Map<String, Value>>,
}

impl FollowUp {
    fn into_message(self) -> Result<Map<String, Value>, CatalogApiError> {
        let message = match (self.text, self.message) {
            (Some(text), None) if !text.is_empty() && text.chars().count() <= MAX_TEXT_LENGTH => {
                Map::from_iter([("parts".into(), json!([{"text":text}]))])
            }
            (Some(_), None) => {
                return Err(invalid("text must contain between 1 and 65536 characters"));
            }
            (None, Some(message)) => message,
            _ => return Err(invalid("Provide exactly one of 'message' or 'text'")),
        };
        const FIELDS: [&str; 9] = [
            "parts",
            "metadata",
            "extensions",
            "referenceTaskIds",
            "messageId",
            "role",
            "taskId",
            "contextId",
            "kind",
        ];
        let mut unknown = message
            .keys()
            .map(String::as_str)
            .filter(|key| !FIELDS.contains(key))
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            unknown.sort_unstable();
            return Err(invalid(format!(
                "message has unsupported fields: {}",
                unknown.join(", ")
            )));
        }
        let parts = message
            .get("parts")
            .and_then(Value::as_array)
            .filter(|parts| !parts.is_empty())
            .ok_or_else(|| invalid("message.parts must be a non-empty list"))?;
        if parts.len() > MAX_MESSAGE_PARTS {
            return Err(invalid("message.parts holds at most 50 parts"));
        }
        if parts
            .iter()
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .any(|text| text.chars().count() > MAX_TEXT_LENGTH)
        {
            return Err(invalid("A text part holds at most 65536 characters"));
        }
        Ok(message)
    }
}

pub(super) async fn continue_task(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path((agent_id, task_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<FollowUp>,
) -> Result<Json<Value>, CatalogApiError> {
    let agent = manageable(&app, &principal, &agent_id, "a2a.invoke").await?;
    let message = input.into_message()?;
    let task = app
        .database
        .agent_task(&agent_id, &task_id)
        .await?
        .ok_or_else(|| missing(&task_id))?;
    if terminal_task_state(&task.state) {
        return Err(CatalogApiError::detail(
            StatusCode::CONFLICT,
            format!(
                "Task '{task_id}' is in terminal state '{}' and cannot accept follow-up messages",
                task.state
            ),
        ));
    }
    let (message, message_id) = bind_message(message, &task)?;
    let parts = summarize_parts(&message);
    let result = invoke(
        &app,
        &agent,
        Invocation {
            parameters: Map::from_iter([
                ("message".into(), Value::Object(message)),
                ("taskId".into(), json!(task_id)),
            ]),
            interaction_type: query_interaction(),
        },
        Some(&principal),
        Some(&headers),
        InvocationSource::Api,
    )
    .await?;
    record(
        &app,
        &agent_id,
        &result,
        Some(TaskContinuation {
            task: &task,
            message_id: &message_id,
            parts,
        }),
    )
    .await;
    tracing::info!(actor = %principal.email, %agent_id, %task_id, "A2A task continued");
    Ok(Json(result))
}

fn bind_message(
    mut message: Map<String, Value>,
    task: &AgentTask,
) -> Result<(Map<String, Value>, String), CatalogApiError> {
    for (field, expected) in [
        ("taskId", Some(task.task_id.as_str())),
        ("contextId", task.context_id.as_deref()),
    ] {
        if let Some(supplied) = message.get(field).filter(|value| !value.is_null())
            && supplied
                .as_str()
                .is_none_or(|value| Some(value) != expected)
        {
            return Err(CatalogApiError::detail(
                StatusCode::BAD_REQUEST,
                format!("message.{field} does not match task '{}'", task.task_id),
            ));
        }
    }
    if let Some(role) = message.get("role").filter(|value| !value.is_null())
        && !role
            .as_str()
            .map(str::trim)
            .is_some_and(|role| matches!(role.to_ascii_lowercase().as_str(), "user" | "role_user"))
    {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "message.role must be the user role",
        ));
    }
    let id = format!("contextforge-{}", Uuid::new_v4().simple());
    message.insert("messageId".into(), json!(id));
    message.insert("role".into(), json!("user"));
    message.insert("taskId".into(), json!(task.task_id));
    if let Some(context) = task.context_id.as_deref().filter(|value| !value.is_empty()) {
        message.insert("contextId".into(), json!(context));
    }
    Ok((message, id))
}

fn summarize_parts(message: &Map<String, Value>) -> Value {
    const KINDS: [&str; 5] = ["text", "raw", "url", "data", "file"];
    let parts = message
        .get("parts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    Value::Array(
        parts
            .map(|part| {
                let kind = part
                    .get("kind")
                    .and_then(Value::as_str)
                    .filter(|kind| KINDS.contains(kind))
                    .or_else(|| KINDS.into_iter().find(|key| part.get(*key).is_some()))
                    .unwrap_or("unknown");
                let length = part.get(kind).map_or(0, |value| match value.as_str() {
                    Some(text) => text.chars().count(),
                    None => value.to_string().chars().count(),
                });
                json!({"kind":kind,"length":length})
            })
            .collect(),
    )
}

pub(super) async fn record(
    app: &GatewayService,
    agent: &str,
    response: &Value,
    event: Option<TaskContinuation<'_>>,
) {
    if let Err(error) = app.database.record_agent_task(agent, response, event).await {
        tracing::warn!(%error, agent_id = %agent, "failed to record A2A task result");
    }
}

pub(super) async fn manageable(
    app: &GatewayService,
    principal: &Principal,
    id: &str,
    permission: &str,
) -> Result<AgentRecord, CatalogApiError> {
    require(app, principal, permission).await?;
    let not_found =
        || CatalogApiError::detail(StatusCode::NOT_FOUND, format!("Agent '{id}' not found"));
    let agent = app
        .database
        .find_agent(access::catalog_scope(Some(principal)), AgentLookup::Id(id))
        .await?
        .ok_or_else(not_found)?;
    if owns_agent(app, principal, &agent).await? {
        return Ok(agent);
    }
    Err(not_found())
}

fn invalid(message: impl Into<String>) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}

pub(super) fn missing(task: &str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::NOT_FOUND, format!("Task '{task}' not found"))
}
