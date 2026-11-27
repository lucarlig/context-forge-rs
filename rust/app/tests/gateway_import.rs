// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use context_forge_rs::{
    access::Authorizer,
    config::Settings,
    database::Database,
    gateway::{CatalogRefresh, GatewayLifecycle, GatewayService, Pagination},
    jwt::{JwtConfig, JwtVerifier},
    upstream::{ConnectMode, EgressPolicy, UpstreamClient},
};
use jiff::Timestamp;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt;

const JWT_KEY: &[u8] = b"context-forge-gateway-import-test-only-key-1234";
const SOURCE_KEY: &str = "context-forge-auth-api-encryption-fixture-key";
const DESTINATION_KEY: &str = "context-forge-gateway-import-destination-fixture-key";
const RECORDINGS: &str = include_str!("../../replay/export-import/import/gateways.expected.json");
// AES-GCM archive of a synthetic bearer token using SOURCE_KEY.
const ARCHIVED_BEARER: &str = "ZGWD-SCJ_9q-YugpIt3iuvs5Quz9YZogEz0LuMH-8BLR4dvBhfGnNAh-zzzXvGaKTxRrH2JV4rxUPmVf7puw8ntL_w6jSJgsKf4cmjHRu-Wtm4xX4Wxx";

async fn upstream(headers: HeaderMap, Json(packet): Json<Value>) -> Response {
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some("Bearer synthetic-archive-gateway-bearer")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !packet
        .as_object()
        .is_some_and(|fields| fields.contains_key("id"))
    {
        return StatusCode::ACCEPTED.into_response();
    }
    let result = match packet["method"].as_str() {
        Some("initialize") => json!({
            "protocolVersion":"2025-11-25","capabilities":{"tools":{}},
            "serverInfo":{"name":"gateway import fixture","version":"1.0"}
        }),
        Some("tools/list") => json!({"tools":[{"name":"probe","inputSchema":{"type":"object"}}]}),
        Some("resources/list") => json!({"resources":[]}),
        Some("resources/templates/list") => json!({"resourceTemplates":[]}),
        Some("prompts/list") => json!({"prompts":[]}),
        _ => return Json(json!({"jsonrpc":"2.0","id":packet["id"],"error":{"code":-32601,"message":"Method not found"}})).into_response(),
    };
    Json(json!({"jsonrpc":"2.0","id":packet["id"],"result":result})).into_response()
}

#[tokio::test]
async fn imports_gateways_synchronously_with_rekey_and_owner_scope() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = Database::from_settings(&Settings {
        host: "127.0.0.1".into(),
        port: 4444,
        database_url: "sqlite:///:memory:".into(),
        db_pool_size: 1,
        db_pool_timeout: Duration::from_secs(1),
        sqlite_busy_timeout: Duration::from_secs(5),
        redis: None,
    })
    .unwrap();
    database.migrate_schema().await.unwrap();
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::raw_sql(r#"
        INSERT INTO email_users (id, email) VALUES ('importer','importer@example.test'), ('peer','peer@example.test');
        INSERT INTO email_teams (id,name,slug,created_by,is_personal)
        VALUES ('importer-team','Importer team','importer-team','importer@example.test',TRUE),
               ('peer-team','Peer team','peer-team','peer@example.test',TRUE);
        INSERT INTO email_team_members (id,team_id,user_email)
        VALUES ('membership','importer-team','importer@example.test');
        INSERT INTO roles (id,name,scope,permissions,created_by)
        VALUES ('import','Config import','global','["admin.import"]','importer@example.test');
        INSERT INTO user_roles (id,user_email,role_id,scope,granted_by)
        VALUES ('import','importer@example.test','import','global','importer@example.test');
        INSERT INTO gateways (id,name,slug,url,description,transport,visibility,owner_email,team_id)
        VALUES ('peer-gateway','Peer gateway','peer-gateway','https://peer.example.invalid/mcp','Peer original',
                'STREAMABLEHTTP','public','peer@example.test','peer-team');
    "#).execute(pool).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_server = tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/mcp", post(upstream)))
            .await
            .unwrap();
    });
    let authorizer = Arc::new(Authorizer::new(
        database.clone(),
        Some(
            JwtVerifier::new(JwtConfig {
                key: JWT_KEY,
                ..JwtConfig::default()
            })
            .unwrap(),
        ),
        true,
    ));
    let service = Arc::new(
        GatewayService::new(
            database.clone(),
            authorizer,
            UpstreamClient::new(
                EgressPolicy {
                    allow_localhost: true,
                    ..EgressPolicy::default()
                },
                Duration::from_secs(3),
            )
            .with_connect_mode(ConnectMode::Legacy),
            Pagination::new(100, 900, None),
            CatalogRefresh::default(),
        )
        .with_credential_secret(Some(DESTINATION_KEY))
        .with_gateway_lifecycle(Some(GatewayLifecycle {
            poll_interval: Duration::from_secs(30),
            attempt_timeout: Duration::from_secs(10),
            lease: Duration::from_secs(20),
            concurrency: 1,
        })),
    );
    let router = service.registration_router();
    let now = Timestamp::now().as_second();
    let token = encode(
        &Header::default(),
        &json!({
            "sub":"importer@example.test","iss":"mcpgateway","aud":"mcpgateway-api",
            "exp":now+60,"iat":now,"jti":"gateway-import-fixture","is_admin":false,
            "token_use":"api","teams":["importer-team"]
        }),
        &EncodingKey::from_secret(JWT_KEY).unwrap(),
    )
    .unwrap();
    let url = format!("http://{addr}/mcp");
    let gateway = json!({
        "name":"Imported gateway","url":url,"transport":"STREAMABLEHTTP",
        "owner_email":"peer@example.test","team_id":"peer-team","visibility":"public",
        "auth_type":"bearer","auth_value":ARCHIVED_BEARER,
    });

    let recordings: Value = serde_json::from_str(RECORDINGS).unwrap();
    let compare = |case: &str, job: &Value| {
        assert_eq!(job["status"], recordings[case]["status"], "{job}");
        assert_eq!(job["progress"], recordings[case]["progress"], "{job}");
    };
    let dry_run = submit(&router, &token, gateway.clone(), json!({"dry_run":true})).await;
    compare("dry-run", &dry_run);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM gateways WHERE slug='imported-gateway'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    let rejected = submit(&router, &token, gateway.clone(), json!({})).await;
    assert_eq!(rejected["progress"]["failed"], 1);
    assert!(
        rejected["errors"][0]
            .as_str()
            .unwrap()
            .contains("Invalid imported gateway credentials")
    );
    let created = submit(
        &router,
        &token,
        gateway.clone(),
        json!({"rekey_secret":SOURCE_KEY}),
    )
    .await;
    compare("create", &created);
    let row = sqlx::query_as::<_, (String, String, String, String, String, String, String)>(
        "SELECT status,owner_email,team_id,visibility,created_via,import_batch_id,auth_value
           FROM gateways WHERE slug='imported-gateway'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(row.0, "active");
    assert_eq!(row.1, "importer@example.test");
    assert_eq!(row.2, "importer-team");
    assert_eq!(row.3, "team");
    assert_eq!(row.4, "import");
    assert_eq!(row.5, created["import_id"].as_str().unwrap());
    assert!(!row.6.contains("synthetic-archive-gateway-bearer"));
    assert!(!row.6.contains(ARCHIVED_BEARER));

    let mut updated = gateway.clone();
    updated["description"] = json!("Updated archive description");
    let updated = submit(&router, &token, updated, json!({"rekey_secret":SOURCE_KEY})).await;
    compare("update", &updated);
    let skipped = submit(
        &router,
        &token,
        gateway.clone(),
        json!({"conflict_strategy":"skip"}),
    )
    .await;
    compare("skip", &skipped);
    let conflict = submit(
        &router,
        &token,
        gateway.clone(),
        json!({"conflict_strategy":"fail"}),
    )
    .await;
    compare("conflict", &conflict);
    assert!(
        conflict["errors"][0]
            .as_str()
            .unwrap()
            .contains("Gateway name conflict: Imported gateway")
    );
    let mut rename = gateway.clone();
    rename["url"] = json!(format!("{url}?rename=fixture"));
    let renamed = submit(
        &router,
        &token,
        rename,
        json!({"conflict_strategy":"rename","rekey_secret":SOURCE_KEY}),
    )
    .await;
    compare("rename", &renamed);
    assert!(
        renamed["warnings"][0]
            .as_str()
            .unwrap()
            .contains("Renamed gateway")
    );

    let denied = submit(
        &router,
        &token,
        json!({
            "name":"Peer gateway","url":url,"description":"Forbidden edit"
        }),
        json!({}),
    )
    .await;
    assert_eq!(denied["progress"]["failed"], 1);
    assert!(
        denied["errors"][0]
            .as_str()
            .unwrap()
            .contains("Permission denied")
    );
    let peer_description: String =
        sqlx::query_scalar("SELECT description FROM gateways WHERE id='peer-gateway'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(peer_description, "Peer original");
    let modified: String =
        sqlx::query_scalar("SELECT modified_via FROM gateways WHERE slug='imported-gateway'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(modified, "import");
    upstream_server.abort();
}

async fn submit(router: &Router, token: &str, entity: Value, mut request: Value) -> Value {
    request["import_data"] = json!({"version":"2025-11-25","exported_at":"2025-01-01T00:00:00Z","entities":{"gateways":[entity]}});
    let response = router
        .clone()
        .oneshot(
            Request::post("/v1/import")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap()
}
