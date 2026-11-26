// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use context_forge_rs::{
    config::{RedisSettings, Settings},
    database::Database,
    probes::{self, RedisProbe},
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt;

fn database() -> Database {
    Database::from_settings(&Settings {
        host: "127.0.0.1".into(),
        port: 4444,
        database_url: "sqlite:///:memory:".into(),
        db_pool_size: 50,
        db_pool_timeout: Duration::from_millis(200),
        sqlite_busy_timeout: Duration::from_secs(5),
        redis: None,
    })
    .expect("configure in-memory SQLite")
}

async fn get(app: Router, path: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .expect("send HTTP request");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4096)
        .await
        .expect("read JSON response");
    (status, serde_json::from_slice(&bytes).expect("decode JSON"))
}

#[tokio::test]
async fn health_and_readiness_report_sqlite_status() {
    let database = database();
    let app = probes::router(database.clone(), None);

    assert_eq!(
        get(app.clone(), "/health").await,
        (StatusCode::OK, json!({"status": "healthy"}))
    );
    assert_eq!(
        get(app.clone(), "/ready").await,
        (
            StatusCode::OK,
            json!({
                "status": "ready",
                "status_items": [{
                    "name": "Database",
                    "status_code": 200,
                    "message": "Database Connection Successful",
                }],
            })
        )
    );

    let Database::Sqlite(pool) = database else {
        panic!("expected SQLite");
    };
    pool.close().await;
    assert_eq!(
        get(app.clone(), "/health").await,
        (
            StatusCode::OK,
            json!({"status": "unhealthy", "error": "Database connection error"})
        )
    );
    assert_eq!(
        get(app, "/ready").await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "status": "unready",
                "status_items": [{
                    "name": "Database",
                    "status_code": 503,
                    "message": "Cannot connect to Database",
                }],
            })
        )
    );
}

#[tokio::test]
async fn redis_failure_affects_readiness_only() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let redis = RedisProbe::new(&RedisSettings {
        url: format!("redis://{}", listener.local_addr().unwrap()),
        connect_timeout: Duration::from_millis(100),
        response_timeout: Duration::from_millis(100),
    })
    .unwrap();
    let app = probes::router(database(), Some(redis));

    assert_eq!(
        get(app.clone(), "/health").await,
        (StatusCode::OK, json!({"status": "healthy"}))
    );
    let (status, data) = get(app, "/ready").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        data,
        json!({
            "status": "unready",
            "status_items": [
                {
                    "name": "Database",
                    "status_code": 200,
                    "message": "Database Connection Successful",
                },
                {
                    "name": "Cache",
                    "status_code": 503,
                    "message": "Cannot connect to Cache",
                },
            ],
        })
    );
}
