// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header::VARY},
    response::IntoResponse,
    routing::get,
};
use redis::AsyncConnectionConfig;
use serde::Serialize;

use crate::{config::RedisSettings, database::Database};

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
        let result = async {
            let mut connection = self
                .client
                .get_multiplexed_async_connection_with_config(&self.config)
                .await?;
            redis::cmd("PING")
                .query_async::<String>(&mut connection)
                .await
        }
        .await;
        matches!(result.as_deref(), Ok("PONG"))
    }
}

struct ProbeState {
    database: Database,
    redis: Option<RedisProbe>,
}

pub fn router(database: Database, redis: Option<RedisProbe>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(Arc::new(ProbeState { database, redis }))
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

async fn health(State(state): State<Arc<ProbeState>>) -> impl IntoResponse {
    let health = if state.database.ping().await.is_ok() {
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
    ([(VARY, "Origin")], Json(health))
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

async fn ready(State(state): State<Arc<ProbeState>>) -> impl IntoResponse {
    let mut status_items = vec![DependencyStatus::new(
        "Database",
        state.database.ping().await.is_ok(),
        "Database Connection Successful",
        "Cannot connect to Database",
    )];
    if let Some(probe) = &state.redis {
        status_items.push(DependencyStatus::new(
            "Cache",
            probe.ping().await,
            "Cache Connection Successful",
            "Cannot connect to Cache",
        ));
    }
    let (code, status) = if status_items.iter().all(|item| item.status_code == 200) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unready")
    };
    (
        code,
        [(VARY, "Origin")],
        Json(Readiness {
            status,
            status_items,
        }),
    )
}
