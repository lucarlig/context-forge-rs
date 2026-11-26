// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use jiff::Timestamp;
use jsonwebtoken::{EncodingKey, Header, encode};
use tower::ServiceExt;

use super::*;
use crate::{config::Settings, gateway::test_service, jwt::JwtConfig};

const KEY: &[u8] = &[0x9d; 32];
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"tests","version":"1"}}}"#;

const FIXTURES: &str = "
    INSERT INTO email_users (id, email, is_admin, is_active) VALUES
        ('member-id', 'member@example.test', FALSE, TRUE),
        ('admin-id', 'admin@example.test', TRUE, TRUE),
        ('disabled-id', 'disabled@example.test', TRUE, FALSE);
    INSERT INTO email_teams (id, name, slug, created_by, is_personal) VALUES
        ('alpha', 'Alpha', 'alpha', 'admin@example.test', FALSE),
        ('beta', 'Beta', 'beta', 'admin@example.test', FALSE),
        ('personal', 'Personal', 'personal', 'member@example.test', TRUE);
    INSERT INTO email_team_members (id, team_id, user_email) VALUES
        ('1', 'alpha', 'member@example.test'),
        ('2', 'beta', 'member@example.test'),
        ('3', 'personal', 'member@example.test');
    INSERT INTO roles (id, name, scope, permissions, created_by) VALUES
        ('reader', 'reader', 'team', '[\"servers.use\",\"tools.read\"]', 'admin@example.test'),
        ('writer', 'writer', 'team', '[\"tools.execute\"]', 'admin@example.test'),
        ('owner', 'owner', 'team', '[\"servers.update\",\"admin.user_management\"]', 'admin@example.test');
    UPDATE roles SET inherits_from = 'reader' WHERE id = 'writer';
    INSERT INTO user_roles (id, user_email, role_id, scope, scope_id, granted_by, expires_at) VALUES
        ('a', 'member@example.test', 'reader', 'team', 'alpha', 'admin@example.test', NULL),
        ('b', 'member@example.test', 'writer', 'team', 'beta', 'admin@example.test', NULL),
        ('c', 'member@example.test', 'owner', 'team', 'personal', 'admin@example.test', NULL),
        ('d', 'member@example.test', 'writer', 'team', 'alpha', 'admin@example.test', '2000-01-01 00:00:00');
";

async fn database() -> Database {
    seeded_database("sqlite:///:memory:".into()).await
}

async fn seeded_database(url: String) -> Database {
    let database = Database::from_settings(&Settings {
        host: "127.0.0.1".into(),
        port: 4444,
        database_url: url,
        db_pool_size: 1,
        db_pool_timeout: Duration::from_secs(1),
        sqlite_busy_timeout: Duration::from_secs(5),
        redis: None,
    })
    .unwrap();
    database.migrate_identity().await.unwrap();
    apply(&database, FIXTURES).await;
    database
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database"]
async fn postgres_authorizes_against_the_native_identity_schema() {
    let url = std::env::var("CONTEXT_FORGE_TEST_DATABASE_URL")
        .expect("disposable PostgreSQL connection URL");
    let database = seeded_database(url).await;
    let Database::Postgres(_) = &database else {
        panic!("expected PostgreSQL");
    };
    database.migrate_identity().await.unwrap();
    let auth = authorizer(&database);
    let credential = token(json!({"teams":["beta"]}));
    let principal = auth.authenticate(&credential, None, None).await.unwrap();
    assert!(
        auth.allows(&principal, "tools.read", RoleContext::Team("beta"), true)
            .await
            .unwrap()
    );
    assert!(
        !auth
            .allows(&principal, "tools.read", RoleContext::Team("alpha"), true)
            .await
            .unwrap()
    );
    assert_eq!(
        request(
            test_service(database, auth).mcp_router(true, crate::mcp::ProtocolMode::Legacy),
            Some(&credential)
        )
        .await
        .0,
        StatusCode::OK
    );
}

async fn apply(database: &Database, sql: &'static str) {
    match database {
        Database::Sqlite(pool) => {
            sqlx::raw_sql(sql).execute(pool).await.unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::raw_sql(sql).execute(pool).await.unwrap();
        }
    }
}

fn authorizer(database: &Database) -> Authorizer {
    let verifier = JwtVerifier::new(JwtConfig {
        key: KEY,
        ..JwtConfig::default()
    })
    .unwrap();
    Authorizer::new(database.clone(), Some(verifier), true)
}

fn token(overrides: Value) -> String {
    let now = Timestamp::now().as_second();
    let mut payload = json!({
        "sub": "member-id",
        "iss": "mcpgateway",
        "aud": "mcpgateway-api",
        "jti": "test-request",
        "iat": now,
        "exp": now + 60,
        "teams": ["alpha"]
    });
    payload
        .as_object_mut()
        .unwrap()
        .extend(overrides.as_object().unwrap().clone());
    encode(
        &Header::default(),
        &payload,
        &EncodingKey::from_secret(KEY).unwrap(),
    )
    .unwrap()
}

async fn request(app: Router, credential: Option<&str>) -> (StatusCode, HeaderMap, Value) {
    let mut req = Request::post("/mcp/")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(INITIALIZE))
        .unwrap();
    if let Some(credential) = credential {
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {credential}").parse().unwrap(),
        );
    }
    let response = app.oneshot(req).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, 8192).await.unwrap();
    (
        parts.status,
        parts.headers,
        serde_json::from_slice(&body).unwrap(),
    )
}

#[tokio::test]
async fn mcp_requires_authentication_and_permissions_before_initialization() {
    let database = database().await;
    let app = test_service(database.clone(), authorizer(&database))
        .mcp_router(true, crate::mcp::ProtocolMode::Legacy);

    let (status, headers, body) = request(app.clone(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(
        body,
        json!({"detail":"Authentication required for MCP endpoints"})
    );

    let (status, _, _) = request(app.clone(), Some("invalid")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let valid = token(json!({}));
    let (status, _, body) = request(app.clone(), Some(&valid)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["protocolVersion"], "2025-11-25");

    let restricted = token(json!({"scopes": {"permissions": ["teams.read"]}}));
    let (status, _, body) = request(app.clone(), Some(&restricted)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"detail":"Access denied"}));

    let disabled = token(json!({"sub": "disabled-id", "teams": null, "is_admin": true}));
    let (status, _, _) = request(app.clone(), Some(&disabled)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let public_admin = token(json!({"sub": "admin-id", "teams": [], "is_admin": true}));
    let (status, _, _) = request(app.clone(), Some(&public_admin)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    apply(&database, "INSERT INTO token_revocations (jti, revoked_by) VALUES ('test-request','admin@example.test')").await;
    let (status, _, _) = request(app, Some(&valid)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn explicit_public_mode_grants_only_anonymous_requests_without_credentials() {
    let database = database().await;
    let app = test_service(database.clone(), authorizer(&database))
        .mcp_router(false, crate::mcp::ProtocolMode::Legacy);
    assert_eq!(request(app.clone(), None).await.0, StatusCode::OK);
    assert_eq!(
        request(app, Some("invalid")).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn team_roles_respect_scope_membership_expiry_and_personal_team_isolation() {
    let database = database().await;
    let auth = authorizer(&database);
    let alpha = token(json!({}));
    let principal = auth.authenticate(&alpha, None, None).await.unwrap();

    assert!(
        auth.allows(&principal, "tools.read", RoleContext::Team("alpha"), true)
            .await
            .unwrap()
    );
    assert!(
        !auth
            .allows(
                &principal,
                "tools.execute",
                RoleContext::Team("alpha"),
                true
            )
            .await
            .unwrap()
    );
    assert!(
        !auth
            .allows(&principal, "tools.read", RoleContext::Team("beta"), true)
            .await
            .unwrap()
    );
    assert!(
        !auth
            .allows(&principal, "tools.execute", RoleContext::AnyTeam, true)
            .await
            .unwrap()
    );

    let beta = token(json!({"teams":["beta"]}));
    let principal = auth.authenticate(&beta, None, None).await.unwrap();
    assert!(
        auth.allows(&principal, "tools.read", RoleContext::Team("beta"), true)
            .await
            .unwrap()
    );
    assert!(
        auth.allows(&principal, "tools.execute", RoleContext::AnyTeam, true)
            .await
            .unwrap()
    );

    let personal = token(json!({"teams":["personal"]}));
    let principal = auth.authenticate(&personal, None, None).await.unwrap();
    assert!(
        !auth
            .allows(&principal, "servers.update", RoleContext::AnyTeam, true)
            .await
            .unwrap()
    );
    assert!(
        auth.allows(
            &principal,
            "servers.update",
            RoleContext::Team("personal"),
            true
        )
        .await
        .unwrap()
    );
    assert!(
        !auth
            .allows(
                &principal,
                "admin.user_management",
                RoleContext::Team("personal"),
                true
            )
            .await
            .unwrap()
    );

    apply(
        &database,
        "UPDATE email_team_members SET is_active = FALSE WHERE id = '1'",
    )
    .await;
    assert!(matches!(
        auth.authenticate(&alpha, None, None).await,
        Err(AuthError::TeamRevoked)
    ));
}

#[tokio::test]
async fn session_scope_uses_database_membership_and_password_change() {
    let database = database().await;
    let auth = authorizer(&database);
    let session =
        token(json!({"token_use":"session", "teams":["alpha","missing"], "is_admin":true}));
    let principal = auth.authenticate(&session, None, None).await.unwrap();
    assert_eq!(
        principal.visibility,
        TeamVisibility::Teams(vec!["alpha".into()])
    );
    assert!(
        !auth
            .allows(&principal, "tools.execute", RoleContext::AnyTeam, true)
            .await
            .unwrap()
    );

    let session = token(json!({"token_use":"session", "sub":"admin-id", "teams":[], "iat":1}));
    let principal = auth.authenticate(&session, None, None).await.unwrap();
    assert_eq!(principal.visibility, TeamVisibility::Admin);
    apply(
        &database,
        "UPDATE email_users SET password_changed_at = '2000-01-01 00:00:00' WHERE id = 'admin-id'",
    )
    .await;
    assert!(matches!(
        auth.authenticate(&session, None, None).await,
        Err(AuthError::Invalid)
    ));
}

#[tokio::test]
async fn signed_scope_restrictions_require_route_and_peer_context() {
    let database = database().await;
    let auth = authorizer(&database);
    let limited =
        token(json!({"scopes": {"ip_restrictions":["192.0.2.0/24"], "server_id":"server-1"}}));
    let peer = "192.0.2.42".parse().unwrap();
    assert!(
        auth.authenticate(&limited, Some(peer), Some("server-1"))
            .await
            .is_ok()
    );
    assert!(matches!(
        auth.authenticate(&limited, Some(peer), None).await,
        Err(AuthError::Forbidden)
    ));
    assert!(matches!(
        auth.authenticate(&limited, None, Some("server-1")).await,
        Err(AuthError::Forbidden)
    ));
}
