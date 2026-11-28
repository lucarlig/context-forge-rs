// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::{
        StatusCode,
        header::{ALLOW, VARY},
    },
    response::IntoResponse,
    routing::get,
};
use redis::AsyncConnectionConfig;
use serde::Serialize;
use serde_json::json;

use crate::{config::RedisSettings, database::Database, observability::telemetry::redis_client};

#[derive(Clone)]
pub struct RedisProbe {
    client: redis::Client,
    config: AsyncConnectionConfig,
}

impl RedisProbe {
    pub fn new(settings: &RedisSettings) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let client = redis::Client::open(settings.url.as_str()).map_err(|_| "invalid REDIS_URL")?;
        let config = AsyncConnectionConfig::new()
            .set_connection_timeout(Some(settings.connect_timeout))
            .set_response_timeout(Some(settings.response_timeout));
        Ok(Self { client, config })
    }

    async fn ping(&self) -> bool {
        let result = self.query(&redis::cmd("PING")).await;
        matches!(result.as_deref(), Ok("PONG"))
    }

    pub(crate) async fn server_version(&self) -> Option<String> {
        let info = self.query(redis::cmd("INFO").arg("server")).await.ok()?;
        let version = info
            .lines()
            .find_map(|line| line.strip_prefix("redis_version:"));
        Some(version.unwrap_or("unknown").to_owned())
    }

    async fn query(&self, command: &redis::Cmd) -> redis::RedisResult<String> {
        let mut connection = self
            .client
            .get_multiplexed_async_connection_with_config(&self.config)
            .await?;
        redis_client::query(&self.client, command, &mut connection).await
    }
}

struct ProbeState {
    database: Database,
    redis: Option<RedisProbe>,
}

pub fn router(database: Database, redis: Option<RedisProbe>) -> Router {
    Router::new()
        .route("/health", get(health).head(probe_head))
        .route("/ready", get(ready).head(probe_head))
        .with_state(Arc::new(ProbeState { database, redis }))
}

async fn probe_head() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(ALLOW, "GET")],
        Json(json!({"detail": "Method Not Allowed"})),
    )
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

async fn health(State(state): State<Arc<ProbeState>>) -> axum::response::Response {
    use crate::observability::framework;
    const FUNCTION: &str = concat!(module_path!(), "::health");
    framework::dependencies(FUNCTION);
    let healthy = framework::handler(FUNCTION, state.database.ping())
        .await
        .is_ok();
    let health = if healthy {
        Health {
            status: "healthy",
            error: None,
        }
    } else {
        Health {
            status: "unhealthy",
            error: Some("Database connection error"),
        }
    };
    framework::serialize(FUNCTION, || {
        ([(VARY, "Origin")], Json(health)).into_response()
    })
}

#[derive(Serialize)]
struct DependencyStatus {
    name: &'static str,
    status_code: u16,
    message: &'static str,
}

impl DependencyStatus {
    fn new(name: &'static str, ready: bool, success: &'static str, failure: &'static str) -> Self {
        Self {
            name,
            status_code: if ready { 200 } else { 503 },
            message: if ready { success } else { failure },
        }
    }
}

#[derive(Serialize)]
struct Readiness {
    status: &'static str,
    status_items: Vec<DependencyStatus>,
}

async fn ready(State(state): State<Arc<ProbeState>>) -> axum::response::Response {
    use crate::observability::framework;
    const FUNCTION: &str = concat!(module_path!(), "::ready");
    framework::dependencies(FUNCTION);
    let status_items = framework::handler(FUNCTION, async {
        let mut items = vec![DependencyStatus::new(
            "Database",
            state.database.ping().await.is_ok(),
            "Database Connection Successful",
            "Cannot connect to Database",
        )];
        if let Some(probe) = &state.redis {
            items.push(DependencyStatus::new(
                "Cache",
                probe.ping().await,
                "Cache Connection Successful",
                "Cannot connect to Cache",
            ));
        }
        items
    })
    .await;
    let (code, status) = if status_items.iter().all(|item| item.status_code == 200) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unready")
    };
    framework::serialize(FUNCTION, || {
        (
            code,
            [(VARY, "Origin")],
            Json(Readiness {
                status,
                status_items,
            }),
        )
            .into_response()
    })
}
