// SPDX-License-Identifier: Apache-2.0

use axum::routing::MethodRouter;

use super::*;
use crate::catalog::{PushConfig, PushConfigInput, PushConfigWriteError};

pub(super) fn collection() -> MethodRouter<Arc<GatewayService>> {
    get(list).post(save)
}

pub(super) fn item() -> MethodRouter<Arc<GatewayService>> {
    get(detail).delete(remove)
}

#[derive(Deserialize)]
struct ConfigInput {
    webhook_url: String,
    auth_token: Option<String>,
    events: Option<Vec<String>>,
    #[serde(default = "enabled")]
    enabled: bool,
}

fn enabled() -> bool {
    true
}

async fn save(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path((agent, task)): Path<(String, String)>,
    Json(input): Json<ConfigInput>,
) -> Result<(StatusCode, Json<Value>), CatalogApiError> {
    let token = input.auth_token.map(Zeroizing::new);
    require_task(&app, &principal, &agent, &task, "a2a.update").await?;
    let target = input.webhook_url.trim();
    let blocked = || {
        CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Webhook URL blocked by URL policy",
        )
    };
    if target.len() > 2048 {
        return Err(blocked());
    }
    tokio::time::timeout(app.a2a_timeout, app.upstream.pinned_addresses(target))
        .await
        .map_err(|_| blocked())?
        .map_err(|_| blocked())?;

    let (created, config) = app
        .database
        .save_push_config(
            &agent,
            &task,
            PushConfigInput {
                webhook_url: target,
                token: token.as_ref().map(|token| token.as_str()),
                events: input.events.as_deref(),
                enabled: input.enabled,
            },
            app.credential_cipher.as_ref(),
        )
        .await
        .map_err(|error| match error {
            PushConfigWriteError::MissingTask => tasks::missing(&task),
            PushConfigWriteError::Credential(_) => CatalogApiError::detail(
                StatusCode::SERVICE_UNAVAILABLE,
                "Webhook token encryption is unavailable",
            ),
            PushConfigWriteError::Database(error) => error.into(),
        })?;
    tracing::info!(actor = %principal.email, agent_id = %agent, task_id = %task,
        config_id = %config.id, "A2A push configuration saved");
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(config.wire())))
}

async fn list(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path((agent, task)): Path<(String, String)>,
) -> Result<Json<Value>, CatalogApiError> {
    require_task(&app, &principal, &agent, &task, "a2a.read").await?;
    let configs = app.database.push_configs(&agent, &task).await?;
    Ok(Json(
        json!({"configs":configs.iter().map(PushConfig::wire).collect::<Vec<_>>()}),
    ))
}

async fn detail(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path((agent, task, id)): Path<(String, String, String)>,
) -> Result<Json<Value>, CatalogApiError> {
    require_task(&app, &principal, &agent, &task, "a2a.read").await?;
    let row = app
        .database
        .push_config(&agent, &task, &id)
        .await?
        .ok_or_else(|| missing(&id))?;
    Ok(Json(row.wire()))
}

async fn remove(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path((agent, task, id)): Path<(String, String, String)>,
) -> Result<Json<Value>, CatalogApiError> {
    require_task(&app, &principal, &agent, &task, "a2a.update").await?;
    if !app.database.delete_push_config(&agent, &task, &id).await? {
        return Err(missing(&id));
    }
    tracing::info!(actor = %principal.email, agent_id = %agent, task_id = %task,
        config_id = %id, "A2A push configuration deleted");
    Ok(Json(json!({"deleted":true})))
}

async fn require_task(
    app: &GatewayService,
    principal: &Principal,
    agent: &str,
    task: &str,
    permission: &str,
) -> Result<(), CatalogApiError> {
    tasks::manageable(app, principal, agent, permission).await?;
    if !app.database.agent_task_exists(agent, task).await? {
        return Err(tasks::missing(task));
    }
    Ok(())
}

fn missing(id: &str) -> CatalogApiError {
    CatalogApiError::detail(
        StatusCode::NOT_FOUND,
        format!("Push config '{id}' not found"),
    )
}
