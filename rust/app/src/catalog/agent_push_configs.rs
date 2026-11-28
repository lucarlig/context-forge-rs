// SPDX-License-Identifier: Apache-2.0

use jiff::Timestamp;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::types::Json as DbJson;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    credentials::{CredentialCipher, CredentialError},
    database::{Database, observed},
};

#[derive(sqlx::FromRow)]
pub(crate) struct PushConfig {
    pub(crate) id: String,
    agent_id: String,
    task_id: String,
    webhook_url: String,
    auth_token: Option<String>,
    events: Option<DbJson<Value>>,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

impl PushConfig {
    pub(crate) fn wire(&self) -> Value {
        json!({
            "id":self.id, "a2a_agent_id":self.agent_id, "task_id":self.task_id,
            "webhook_url":self.webhook_url, "events":self.events, "enabled":self.enabled,
            "created_at":wire_timestamp(&self.created_at), "updated_at":wire_timestamp(&self.updated_at),
        })
    }
}

fn wire_timestamp(value: &str) -> String {
    let value = value.replacen(' ', "T", 1);
    if let Some(utc) = value
        .strip_suffix("+00:00")
        .or_else(|| value.strip_suffix("+00"))
    {
        return format!("{utc}Z");
    }
    value
}

pub(crate) struct PushConfigInput<'a> {
    pub(crate) webhook_url: &'a str,
    pub(crate) token: Option<&'a str>,
    pub(crate) events: Option<&'a [String]>,
    pub(crate) enabled: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PushConfigWriteError {
    #[error("A2A task not found")]
    MissingTask,
    #[error(transparent)]
    Credential(#[from] CredentialError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

#[derive(Deserialize)]
struct StoredToken {
    token: Option<String>,
}

fn same_token(
    cipher: Option<&CredentialCipher>,
    stored: Option<&str>,
    requested: Option<&str>,
) -> bool {
    let Some(stored) = stored else {
        return requested.is_none();
    };
    let Some(decoded) = cipher.and_then(|cipher| cipher.open::<StoredToken>(stored).ok()) else {
        return false;
    };
    let token = decoded.token.map(Zeroizing::new);
    token.as_ref().map(|token| token.as_str()) == requested
}

fn encrypt_token(
    cipher: Option<&CredentialCipher>,
    token: Option<&str>,
) -> Result<Option<String>, CredentialError> {
    token
        .map(|token| {
            let value = std::collections::BTreeMap::from([("token", token)]);
            cipher.ok_or(CredentialError)?.seal(&value)
        })
        .transpose()
}

macro_rules! projection {
    ($token:literal) => {
        concat!(
            "SELECT id, a2a_agent_id AS agent_id, task_id, webhook_url, ",$token," AS auth_token,
                events, enabled, CAST(created_at AS TEXT) AS created_at, CAST(updated_at AS TEXT) AS updated_at
             FROM a2a_push_notification_configs WHERE a2a_agent_id=$1 AND task_id=$2"
        )
    };
}

const LIST: &str = concat!(
    projection!("CAST(NULL AS TEXT)"),
    " ORDER BY created_at, id"
);
const GET: &str = concat!(projection!("CAST(NULL AS TEXT)"), " AND id=$3");
const EXISTS_TASK: &str =
    "SELECT EXISTS(SELECT 1 FROM a2a_tasks WHERE a2a_agent_id=$1 AND task_id=$2)";

macro_rules! insert_sql {
    ($stamp:literal) => {
        concat!(
            "INSERT INTO a2a_push_notification_configs
                (id,a2a_agent_id,task_id,webhook_url,auth_token,events,enabled,created_at,updated_at)
             VALUES ($3,$1,$2,$4,$5,$6,$7,", $stamp,",",$stamp,")"
        )
    };
}

macro_rules! update_sql {
    ($stamp:literal) => {
        concat!(
            "UPDATE a2a_push_notification_configs SET auth_token=$4, events=$5, enabled=$6, updated_at=",
            $stamp," WHERE a2a_agent_id=$1 AND task_id=$2 AND id=$3"
        )
    };
}

impl Database {
    pub(crate) async fn agent_task_exists(
        &self,
        agent: &str,
        task: &str,
    ) -> Result<bool, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar(EXISTS_TASK)
                    .bind(agent)
                    .bind(task)
                    .fetch_one(observed(pool))
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar(EXISTS_TASK)
                    .bind(agent)
                    .bind(task)
                    .fetch_one(observed(pool))
                    .await
            }
        }
    }

    pub(crate) async fn push_configs(
        &self,
        agent: &str,
        task: &str,
    ) -> Result<Vec<PushConfig>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(LIST)
                    .bind(agent)
                    .bind(task)
                    .fetch_all(observed(pool))
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(LIST)
                    .bind(agent)
                    .bind(task)
                    .fetch_all(observed(pool))
                    .await
            }
        }
    }

    pub(crate) async fn push_config(
        &self,
        agent: &str,
        task: &str,
        id: &str,
    ) -> Result<Option<PushConfig>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(GET)
                    .bind(agent)
                    .bind(task)
                    .bind(id)
                    .fetch_optional(observed(pool))
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(GET)
                    .bind(agent)
                    .bind(task)
                    .bind(id)
                    .fetch_optional(observed(pool))
                    .await
            }
        }
    }

    pub(crate) async fn delete_push_config(
        &self,
        agent: &str,
        task: &str,
        id: &str,
    ) -> Result<bool, sqlx::Error> {
        let delete = "DELETE FROM a2a_push_notification_configs WHERE a2a_agent_id=$1 AND task_id=$2 AND id=$3";
        let count = match self {
            Self::Sqlite(pool) => sqlx::query(delete)
                .bind(agent)
                .bind(task)
                .bind(id)
                .execute(observed(pool))
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(delete)
                .bind(agent)
                .bind(task)
                .bind(id)
                .execute(observed(pool))
                .await?
                .rows_affected(),
        };
        Ok(count == 1)
    }

    pub(crate) async fn save_push_config(
        &self,
        agent: &str,
        task: &str,
        input: PushConfigInput<'_>,
        cipher: Option<&CredentialCipher>,
    ) -> Result<(bool, PushConfig), PushConfigWriteError> {
        let events = input.events.map(|events| DbJson(json!(events)));
        let token = input.token.filter(|token| !token.is_empty());
        macro_rules! save {
            ($tx:ident, $lock:literal, $insert_time:literal, $update_time:literal) => {{
                if sqlx::query_scalar::<_, String>(concat!(
                    "SELECT id FROM a2a_agents WHERE id=$1",
                    $lock
                ))
                .bind(agent)
                .fetch_optional(observed(&mut *$tx))
                .await?
                .is_none()
                    || !sqlx::query_scalar::<_, bool>(EXISTS_TASK)
                        .bind(agent)
                        .bind(task)
                        .fetch_one(observed(&mut *$tx))
                        .await?
                {
                    return Err(PushConfigWriteError::MissingTask);
                }
                let existing: Option<PushConfig> = sqlx::query_as(concat!(
                    projection!("auth_token"),
                    " AND webhook_url=$3",
                    $lock
                ))
                .bind(agent)
                .bind(task)
                .bind(input.webhook_url)
                .fetch_optional(observed(&mut *$tx))
                .await?;
                let stamp = Timestamp::now().strftime("%F %T%.6f").to_string();
                let (created, id) = if let Some(current) = existing {
                    let same_token = same_token(cipher, current.auth_token.as_deref(), token);
                    let current_events =
                        current.events.as_ref().filter(|events| !events.0.is_null());
                    if !same_token
                        || current.enabled != input.enabled
                        || current_events != events.as_ref()
                    {
                        let encrypted = if same_token {
                            current.auth_token
                        } else {
                            encrypt_token(cipher, token)?
                        };
                        sqlx::query(update_sql!($update_time))
                            .bind(agent)
                            .bind(task)
                            .bind(&current.id)
                            .bind(encrypted)
                            .bind(events.as_ref())
                            .bind(input.enabled)
                            .bind(&stamp)
                            .execute(observed(&mut *$tx))
                            .await?;
                    }
                    (false, current.id)
                } else {
                    let id = Uuid::new_v4().to_string();
                    sqlx::query(insert_sql!($insert_time))
                        .bind(agent)
                        .bind(task)
                        .bind(&id)
                        .bind(input.webhook_url)
                        .bind(encrypt_token(cipher, token)?)
                        .bind(events.as_ref())
                        .bind(input.enabled)
                        .bind(&stamp)
                        .execute(observed(&mut *$tx))
                        .await?;
                    (true, id)
                };
                let row = sqlx::query_as(GET)
                    .bind(agent)
                    .bind(task)
                    .bind(id)
                    .fetch_one(observed(&mut *$tx))
                    .await?;
                $tx.commit().await?;
                Ok((created, row))
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                save!(tx, "", "$8", "$7")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                save!(
                    tx,
                    " FOR UPDATE",
                    "CAST((CAST($8 AS TEXT) || '+00:00') AS TIMESTAMPTZ)",
                    "CAST((CAST($7 AS TEXT) || '+00:00') AS TIMESTAMPTZ)"
                )
            }
        }
    }
}
