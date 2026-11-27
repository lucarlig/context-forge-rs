// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use context_forge_rs::{
    access::Authorizer,
    config::Settings,
    database::Database,
    gateway::{CatalogRefresh, GatewayService, Pagination},
    jwt::{JwtConfig, JwtVerifier},
    upstream::{EgressPolicy, UpstreamClient},
};
use jiff::Timestamp;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt;

const JWT_KEY: &[u8] = b"context-forge-auth-api-replay-fixture-key-4d414e4147454d454e54";
const ENCRYPTION_KEY: &str = "context-forge-auth-api-encryption-fixture-key";
const FIXTURE: &str = include_str!("../../replay/export-import/export/fixture.sql");

#[tokio::test]
async fn export_masks_plaintext_and_filters_hidden_dependencies() {
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
    sqlx::raw_sql(FIXTURE).execute(pool).await.unwrap();
    sqlx::raw_sql(
        r#"
        INSERT INTO tools (id, name, original_name, custom_name, custom_name_slug, integration_type,
                           request_type, input_schema, auth_type, visibility, team_id)
        VALUES ('no-access', 'hidden-tool', 'Hidden Tool', 'Hidden Tool', 'hidden-tool', 'REST',
                'POST', '{}', NULL, 'team', 'other-team'),
               ('signed-tool', 'signed-tool', 'Signed Tool', 'Signed Tool', 'signed-tool', 'REST',
                'POST', '{}', 'sigv4', 'public', NULL);
        INSERT INTO server_tool_association (server_id, tool_id) VALUES ('export-server', 'no-access');
        UPDATE tools SET headers = json_set(headers, '$.X-Legacy', 'synthetic-plaintext',
             '$.X-Fixture.unexpected', 'synthetic-plaintext-in-envelope') WHERE id = 'export-tool';
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    let verifier = JwtVerifier::new(JwtConfig {
        key: JWT_KEY,
        ..JwtConfig::default()
    })
    .unwrap();
    let authorizer = Arc::new(Authorizer::new(database.clone(), Some(verifier), true));
    let service = Arc::new(
        GatewayService::new(
            database,
            authorizer,
            UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(1)),
            Pagination::new(100, 900, None),
            CatalogRefresh::default(),
        )
        .with_credential_secret(Some(ENCRYPTION_KEY)),
    );
    let now = Timestamp::now().as_second();
    let token = encode(
        &Header::default(),
        &json!({
            "sub":"exporter@example.com","iss":"mcpgateway","aud":"mcpgateway-api",
            "exp":now+60,"iat":now,"jti":"export-denial-fixture","is_admin":false,
            "token_use":"api","teams":["export-team"]
        }),
        &EncodingKey::from_secret(JWT_KEY).unwrap(),
    )
    .unwrap();
    let response = service
        .registration_router()
        .oneshot(
            Request::post("/v1/export/selective")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"tools":["export-tool","no-access","signed-tool"],
                                   "servers":["export-server"]})
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let export: Value = serde_json::from_slice(&body).unwrap();
    let tools = export["entities"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "Original Tool");
    assert_eq!(tools[0]["headers"]["X-Legacy"], "*****");
    let envelope = tools[0]["headers"]["X-Fixture"].as_object().unwrap();
    assert_eq!(envelope.len(), 1);
    assert!(envelope["_mcpgateway_encrypted_header_value_v1"].is_string());
    assert_eq!(
        export["entities"]["servers"][0]["tool_ids"],
        json!(["export-tool"])
    );
    assert_eq!(
        export["metadata"]["dependencies"]["servers_to_tools"]["Fixture server"],
        json!(["export-tool"])
    );
    assert!(!String::from_utf8_lossy(&body).contains("synthetic-plaintext"));
}
