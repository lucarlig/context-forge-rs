// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::types::Json;
use uuid::Uuid;

use crate::database::{Database, observed};

pub(crate) fn terminal_task_state(state: &str) -> bool {
    let state = state.trim().to_ascii_lowercase();
    matches!(
        state.strip_prefix("task_state_").unwrap_or(&state),
        "completed" | "failed" | "canceled" | "cancelled" | "rejected"
    )
}

#[derive(sqlx::FromRow)]
pub(crate) struct AgentTask {
    id: String,
    pub(crate) task_id: String,
    pub(crate) context_id: Option<String>,
    pub(crate) state: String,
    latest_message: Option<Json<Value>>,
    payload: Option<Json<Value>>,
    last_error: Option<String>,
    updated_at: String,
}

impl AgentTask {
    pub(crate) fn wire(&self, details: bool) -> Value {
        let mut status = json!({"state":self.state});
        if let Some(message) = self
            .latest_message
            .as_ref()
            .map(|message| &message.0)
            .filter(|value| meaningful(value))
        {
            status["message"] = message.clone();
        }
        if let Some(error) = self.last_error.as_deref().filter(|error| !error.is_empty())
            && self.state == "failed"
        {
            status["message"] = json!({"role":"agent","parts":[{"text":error}]});
        }
        let mut task = json!({"id":self.task_id,"contextId":self.context_id,"status":status});
        if details && let Some(payload) = &self.payload {
            for key in ["history", "artifacts"] {
                if let Some(value) = payload.0.get(key) {
                    task[key] = value.clone();
                }
            }
        }
        task
    }

    pub(crate) fn cursor(&self) -> AgentTaskCursor {
        let time = self.updated_at.replacen(' ', "T", 1);
        let updated_at = if time
            .as_bytes()
            .get(time.len().saturating_sub(3))
            .is_some_and(|byte| matches!(byte, b'+' | b'-'))
        {
            format!("{time}:00")
        } else {
            time
        };
        AgentTaskCursor {
            updated_at,
            row_id: self.id.clone(),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct AgentTaskCursor {
    #[serde(rename = "u")]
    pub(crate) updated_at: String,
    #[serde(rename = "i")]
    pub(crate) row_id: String,
}

pub(crate) struct TaskContinuation<'a> {
    pub(crate) task: &'a AgentTask,
    pub(crate) message_id: &'a str,
    pub(crate) parts: Value,
}

struct Snapshot<'a> {
    task_id: String,
    context_id: Option<&'a str>,
    state: &'a str,
    latest_message: Option<&'a Value>,
    payload: Option<Value>,
}

impl<'a> Snapshot<'a> {
    fn from_response(response: &'a Value) -> Option<Self> {
        let task = response.get("result").unwrap_or(response);
        let raw_id = task
            .get("id")
            .filter(|id| meaningful(id))
            .or_else(|| task.get("task_id"))?;
        let task_id = match raw_id {
            Value::String(id) if !id.is_empty() && id.chars().count() <= 255 => id.clone(),
            Value::Number(id) if id.as_i64() != Some(0) => id.to_string(),
            _ => return None,
        };
        let status = task.get("status").and_then(Value::as_object);
        let state = match status {
            Some(status) => status.get("state"),
            None => task.get("state"),
        }?
        .as_str()
        .filter(|value| !value.is_empty() && value.chars().count() <= 50)?;
        let context_id = task
            .get("contextId")
            .and_then(Value::as_str)
            .filter(|value| value.chars().count() <= 255);
        let latest_message = status
            .and_then(|status| status.get("message"))
            .filter(|value| !value.is_null());
        let payload = (meaningful(&task["history"]) || meaningful(&task["artifacts"]))
            .then(|| json!({"history":task["history"],"artifacts":task["artifacts"]}));
        Some(Self {
            task_id,
            context_id,
            state,
            latest_message,
            payload,
        })
    }
}

fn meaningful(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(list) => !list.is_empty(),
        Value::Object(map) => !map.is_empty(),
        Value::String(text) => !text.is_empty(),
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
    }
}

macro_rules! terminal_states {
    () => {
        "('completed','canceled','cancelled','failed','rejected',
          'task_state_completed','task_state_canceled','task_state_cancelled','task_state_failed','task_state_rejected')"
    };
}

macro_rules! task_columns {
    ($payload:literal) => {
        concat!(
            "id, task_id, context_id, state, latest_message, ",
            $payload,
            " AS payload, last_error, CAST(updated_at AS TEXT) AS updated_at"
        )
    };
}

const GET: &str = concat!(
    "SELECT ",
    task_columns!("payload"),
    " FROM a2a_tasks WHERE a2a_agent_id = $1 AND task_id = $2"
);

macro_rules! page_sql {
    ($date:literal) => {
        concat!(
            "SELECT ",
            task_columns!("CAST(NULL AS JSON)"),
            " FROM a2a_tasks WHERE a2a_agent_id = $1
                AND (CAST($2 AS TEXT) IS NULL OR state = $2)
                AND (CAST($3 AS TEXT) IS NULL OR updated_at < ",
            $date,
            " OR (updated_at = ",
            $date,
            " AND id < $4))
              ORDER BY updated_at DESC, id DESC LIMIT $5"
        )
    };
}

macro_rules! cancel_sql {
    ($now:literal) => {
        concat!(
            "UPDATE a2a_tasks SET state = 'canceled', completed_at = ",
            $now,
            ", updated_at = ",
            $now,
            " WHERE a2a_agent_id = $1 AND task_id = $2
                AND LOWER(TRIM(state)) NOT IN ",
            terminal_states!()
        )
    };
}

macro_rules! upsert_sql {
    ($now:literal) => {
        concat!(
            "INSERT INTO a2a_tasks
                (id,a2a_agent_id,task_id,context_id,state,latest_message,payload,created_at,updated_at,completed_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,", $now, ",", $now, ",CASE WHEN $8 THEN ", $now," END)
             ON CONFLICT (a2a_agent_id,task_id) DO UPDATE SET
                context_id = COALESCE(excluded.context_id, a2a_tasks.context_id),
                state = excluded.state, latest_message = COALESCE(excluded.latest_message,a2a_tasks.latest_message),
                payload = COALESCE(excluded.payload, a2a_tasks.payload), updated_at = excluded.updated_at,
                completed_at = excluded.completed_at
             WHERE LOWER(TRIM(a2a_tasks.state)) NOT IN ", terminal_states!(),
            " OR a2a_tasks.state = excluded.state"
        )
    };
}

const CONTINUED: &str = "
    INSERT INTO a2a_task_events (id,a2a_agent_id,task_id,event_id,sequence,event_type,payload,created_at)
    VALUES ($1,$2,$3,$4,(
        SELECT COALESCE(MAX(sequence),0) + 1 FROM a2a_task_events WHERE a2a_agent_id = $2 AND task_id = $3
    ),'task_continued',$5,CURRENT_TIMESTAMP)";

impl Database {
    pub(crate) async fn agent_task(
        &self,
        agent: &str,
        task: &str,
    ) -> Result<Option<AgentTask>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(GET)
                    .bind(agent)
                    .bind(task)
                    .fetch_optional(observed(pool))
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(GET)
                    .bind(agent)
                    .bind(task)
                    .fetch_optional(observed(pool))
                    .await
            }
        }
    }

    pub(crate) async fn agent_tasks_page(
        &self,
        agent: &str,
        state: Option<&str>,
        after: Option<&AgentTaskCursor>,
        limit: i64,
    ) -> Result<Vec<AgentTask>, sqlx::Error> {
        let timestamp = after.map(|cursor| cursor.updated_at.replacen('T', " ", 1));
        let row = after.map(|cursor| cursor.row_id.as_str());
        macro_rules! fetch {
            ($pool:expr, $date:literal) => {
                sqlx::query_as(page_sql!($date))
                    .bind(agent)
                    .bind(state)
                    .bind(timestamp)
                    .bind(row)
                    .bind(limit)
                    .fetch_all(observed($pool))
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => fetch!(pool, "$3"),
            Self::Postgres(pool) => fetch!(pool, "CAST(CAST($3 AS TEXT) AS TIMESTAMPTZ)"),
        }
    }

    pub(crate) async fn cancel_agent_task(
        &self,
        agent: &str,
        task: &str,
    ) -> Result<Option<AgentTask>, sqlx::Error> {
        macro_rules! cancel {
            ($tx:ident, $now:literal) => {{
                sqlx::query(cancel_sql!($now))
                    .bind(agent)
                    .bind(task)
                    .execute(observed(&mut *$tx))
                    .await?;
                let result = sqlx::query_as(GET)
                    .bind(agent)
                    .bind(task)
                    .fetch_optional(observed(&mut *$tx))
                    .await?;
                $tx.commit().await?;
                Ok(result)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                cancel!(tx, "STRFTIME('%Y-%m-%d %H:%M:%f','now')")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                cancel!(tx, "clock_timestamp()")
            }
        }
    }

    pub(crate) async fn record_agent_task(
        &self,
        agent: &str,
        response: &Value,
        continuation: Option<TaskContinuation<'_>>,
    ) -> Result<(), sqlx::Error> {
        let snapshot = Snapshot::from_response(response).filter(|item| {
            continuation.as_ref().is_none_or(|event| {
                item.task_id == event.task.task_id
                    && event
                        .task
                        .context_id
                        .as_deref()
                        .zip(item.context_id)
                        .is_none_or(|(old, new)| old == new)
            })
        });
        if snapshot.is_none() && continuation.is_none() {
            return Ok(());
        }
        macro_rules! save {
            ($tx:ident, $lock:literal, $now:literal) => {{
                // Sequence task events under the same agent lock as snapshot writes.
                if sqlx::query_scalar::<_, String>(concat!("SELECT id FROM a2a_agents WHERE id = $1", $lock))
                    .bind(agent).fetch_optional(observed(&mut *$tx)).await?.is_none()
                {
                    return Ok(());
                }
                if let Some(task) = snapshot {
                    sqlx::query(upsert_sql!($now))
                        .bind(Uuid::new_v4().to_string())
                        .bind(agent)
                        .bind(task.task_id)
                        .bind(task.context_id)
                        .bind(task.state)
                        .bind(task.latest_message.map(Json))
                        .bind(task.payload.map(Json))
                        .bind(terminal_task_state(task.state))
                        .execute(observed(&mut *$tx)).await?;
                }
                if let Some(event) = continuation {
                    let task_id = &event.task.task_id;
                    let updated: Option<AgentTask> = sqlx::query_as(GET).bind(agent).bind(task_id)
                        .fetch_optional(observed(&mut *$tx)).await?;
                    if let Some(updated) = updated {
                        let payload = json!({
                            "message_id":event.message_id,"parts":event.parts,
                            "previous_state":event.task.state,"state":updated.state
                        });
                        sqlx::query(CONTINUED).bind(Uuid::new_v4().to_string()).bind(agent).bind(task_id)
                            .bind(Uuid::new_v4().to_string()).bind(Json(payload))
                            .execute(observed(&mut *$tx)).await?;
                    }
                }
                $tx.commit().await?;
                Ok(())
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                save!(tx, "", "STRFTIME('%Y-%m-%d %H:%M:%f','now')")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                save!(tx, " FOR UPDATE", "clock_timestamp()")
            }
        }
    }
}
