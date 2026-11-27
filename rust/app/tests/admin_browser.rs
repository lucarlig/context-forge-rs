// SPDX-License-Identifier: Apache-2.0

use std::{net::TcpListener, path::PathBuf, process::Stdio, time::Duration};

use reqwest::{Client, Response, StatusCode, header, redirect::Policy};
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};
use uuid::Uuid;

struct FixtureDirectory(PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const EMAIL: &str = "admin@example.com";

struct BrowserGateway {
    process: Child,
    fixture: FixtureDirectory,
    client: Client,
    origin: String,
    password: String,
}

async fn gateway() -> BrowserGateway {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fixture = FixtureDirectory(std::env::temp_dir().join(Uuid::new_v4().simple().to_string()));
    std::fs::create_dir(&fixture.0).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let origin = format!("http://127.0.0.1:{port}");
    let password = format!("Fixture!{}", Uuid::new_v4().simple());
    let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let mut gateway = Command::new(env!("CARGO_BIN_EXE_context-forge-rs"))
        .current_dir(&fixture.0)
        .env_clear()
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("JWT_SECRET_KEY", &key)
        .env("AUTH_ENCRYPTION_SECRET", &key)
        .env("PLATFORM_ADMIN_EMAIL", EMAIL)
        .env("PLATFORM_ADMIN_PASSWORD", &password)
        .env("MCPGATEWAY_ADMIN_API_ENABLED", "true")
        .env("SECURE_COOKIES", "false")
        .env("RATE_LIMITING_ENABLED", "false")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                gateway.try_wait().unwrap().is_none(),
                "gateway exited before login"
            );
            if let Ok(response) = client.get(format!("{origin}/health")).send().await {
                assert_eq!(response.status(), StatusCode::OK);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    BrowserGateway {
        process: gateway,
        fixture,
        client,
        origin,
        password,
    }
}

#[tokio::test]
async fn browser_login_rejects_cross_origin_and_logout_revokes_the_session() {
    let mut gateway = gateway().await;
    let BrowserGateway {
        client,
        origin,
        password,
        ..
    } = &gateway;
    let login_url = format!("{origin}/admin/login");
    let login = client.get(&login_url).send().await.unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let csrf = cookie(&login, "mcpgateway_csrf_token");
    let csrf_cookie = format!("mcpgateway_csrf_token={csrf}");
    let login_form = format!("email={EMAIL}&password={password}&csrf_token={csrf}");
    let sign_in = |site: &str| {
        client
            .post(&login_url)
            .header(header::ORIGIN, site)
            .header(header::COOKIE, &csrf_cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(login_form.clone())
    };
    let rejected = sign_in("https://foreign.example.test")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    assert!(
        rejected
            .text()
            .await
            .unwrap()
            .contains("CSRF origin validation failed")
    );

    let accepted = sign_in(origin).send().await.unwrap();
    assert_eq!(accepted.status(), StatusCode::SEE_OTHER);
    let jwt = cookie(&accepted, "jwt_token");
    let csrf = cookie(&accepted, "mcpgateway_csrf_token");
    let cookies = format!("jwt_token={jwt}; mcpgateway_csrf_token={csrf}");
    let home = || {
        client
            .get(format!("{origin}/admin/"))
            .header(header::COOKIE, &cookies)
    };
    assert_eq!(home().send().await.unwrap().status(), StatusCode::OK);

    let logout = || {
        client
            .post(format!("{origin}/admin/logout"))
            .header(header::ORIGIN, origin)
            .header(header::COOKIE, &cookies)
    };
    assert_eq!(
        logout().send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let accepted = logout().header("X-CSRF-Token", csrf).send().await.unwrap();
    assert_eq!(accepted.status(), StatusCode::SEE_OTHER);
    let stale = home()
        .header(header::ACCEPT, "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::FOUND);
    assert_eq!(
        stale.headers()[header::LOCATION],
        "/admin/login?error=token_revoked"
    );
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn browser_password_reset_consumes_a_link_once() {
    let mut gateway = gateway().await;
    let token = Uuid::new_v4().simple().to_string();
    let digest: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let database = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        gateway.fixture.0.join("mcp.db").display()
    ))
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO password_reset_tokens(id,user_email,token_hash,created_at,expires_at)
         VALUES(?,?,?,CURRENT_TIMESTAMP,datetime('now','+5 minutes'))",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(EMAIL)
    .bind(digest)
    .execute(&database)
    .await
    .unwrap();
    database.close().await;

    let reset_url = format!("{}/admin/reset-password/{token}", gateway.origin);
    let page = || gateway.client.get(&reset_url).send();
    let form = page().await.unwrap().text().await.unwrap();
    assert!(form.contains("name=\"confirm_password\""));

    let password = "N3w%21Fixture_q7X4_sT62p";
    let submit = || {
        gateway
            .client
            .post(&reset_url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("password={password}&confirm_password={password}"))
            .send()
    };
    let changed = submit().await.unwrap();
    assert_eq!(changed.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        changed.headers()[header::LOCATION],
        "/admin/login?notice=password_reset_success"
    );
    let used = submit().await.unwrap();
    assert_eq!(used.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        used.headers()[header::LOCATION],
        "/admin/forgot-password?error=reset_link_used"
    );
    let used_form = page().await.unwrap().text().await.unwrap();
    assert!(used_form.contains("This reset link has already been used"));
    assert!(!used_form.contains("name=\"confirm_password\""));
    gateway.process.kill().await.unwrap();
}

fn cookie<'a>(response: &'a Response, name: &str) -> &'a str {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next()?.split_once('='))
        .find_map(|(key, value)| (key == name && !value.is_empty()).then_some(value))
        .unwrap()
}

#[tokio::test]
async fn admin_catalog_paginates_and_hides_inactive_servers_by_default() {
    let mut gateway = gateway().await;
    let signin = gateway
        .client
        .post(format!("{}/auth/email/login", gateway.origin))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email":EMAIL, "password":gateway.password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(signin.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&signin.text().await.unwrap()).unwrap();
    let token = body["access_token"].as_str().unwrap();
    for name in ["fixture-active-server", "fixture-inactive-server"] {
        let response = gateway
            .client
            .post(format!("{}/servers", gateway.origin))
            .bearer_auth(token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(serde_json::json!({"server":{"name":name}, "visibility":"public"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let database = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        gateway.fixture.0.join("mcp.db").display()
    ))
    .await
    .unwrap();
    sqlx::query("UPDATE servers SET enabled=FALSE WHERE name='fixture-inactive-server'")
        .execute(&database)
        .await
        .unwrap();
    database.close().await;

    let cookie = format!("jwt_token={token}");
    let home = gateway
        .client
        .get(format!("{}/admin/", gateway.origin))
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(home.status(), StatusCode::OK);
    let html = home.text().await.unwrap();
    assert!(html.contains("fixture-active-server"));
    assert!(!html.contains("fixture-inactive-server"));

    let response = gateway
        .client
        .get(format!(
            "{}/v1/admin/servers?include_inactive=true&per_page=1&page=999",
            gateway.origin
        ))
        .header(header::COOKIE, cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(body["pagination"]["page"], 2);
    assert_eq!(body["pagination"]["total_items"], 2);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["links"]["prev"],
        "/admin/servers?include_inactive=True&page=1&per_page=1"
    );
    let issued = gateway
        .client
        .post(format!("{}/tokens", gateway.origin))
        .bearer_auth(token)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "name":"catalog-limit","expires_in_days":1,
                "scope":{"usage_limits":{"requests_per_hour":1}}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    let issued: serde_json::Value = serde_json::from_str(&issued.text().await.unwrap()).unwrap();
    let limited = issued["access_token"].as_str().unwrap();
    let first = gateway
        .client
        .get(format!("{}/admin/servers", gateway.origin))
        .bearer_auth(limited)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let blocked = gateway
        .client
        .get(format!("{}/admin/", gateway.origin))
        .bearer_auth(limited)
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn admin_catalog_mutations_require_proof_and_write_permission() {
    let mut gateway = gateway().await;
    let client = &gateway.client;
    let origin = &gateway.origin;
    let login = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email":EMAIL, "password":gateway.password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let login: serde_json::Value = serde_json::from_str(&login.text().await.unwrap()).unwrap();
    let token = login["access_token"].as_str().unwrap();
    let created = client
        .post(format!("{origin}/servers"))
        .bearer_auth(token)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"server":{"name":"fixture-browser-action"},"visibility":"public"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&created.text().await.unwrap()).unwrap();
    let id = created["id"].as_str().unwrap();
    let auth_cookie = format!("jwt_token={token}");
    let home = client
        .get(format!("{origin}/admin/"))
        .header(header::COOKIE, &auth_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(home.status(), StatusCode::OK);
    let proof = cookie(&home, "mcpgateway_csrf_token");
    let cookies = format!("{auth_cookie}; mcpgateway_csrf_token={proof}");
    let state = |submitted: &str| {
        client
            .post(format!("{origin}/admin/servers/{id}/state"))
            .header(header::ORIGIN, origin)
            .header(header::COOKIE, &cookies)
            .header(header::ACCEPT, "text/html")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "activate=false&is_inactive_checked=true&csrf_token={submitted}"
            ))
    };
    assert_eq!(
        state("wrong").send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let listing = |include_inactive: bool| async move {
        let result = client
            .get(format!(
                "{origin}/admin/servers?include_inactive={include_inactive}"
            ))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&result.text().await.unwrap()).unwrap();
        body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .cloned()
    };
    assert_eq!(listing(false).await.unwrap()["enabled"], true);
    let updated = state(proof).send().await.unwrap();
    assert_eq!(updated.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        updated.headers()[header::LOCATION],
        "/admin/?include_inactive=true#catalog"
    );
    assert!(listing(false).await.is_none());
    assert_eq!(listing(true).await.unwrap()["enabled"], false);

    let issued = client
        .post(format!("{origin}/tokens"))
        .bearer_auth(token)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            r#"{"name":"catalog-read","expires_in_days":1,"scope":{"permissions":["admin.dashboard","servers.read"]}}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    let issued: serde_json::Value = serde_json::from_str(&issued.text().await.unwrap()).unwrap();
    let read_only = issued["access_token"].as_str().unwrap();
    let delete = |credential| {
        client
            .post(format!("{origin}/v1/admin/servers/{id}/delete"))
            .bearer_auth(credential)
    };
    assert_eq!(
        delete(read_only).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(listing(true).await.is_some());
    let deleted = delete(token).send().await.unwrap();
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert_eq!(deleted.headers()[header::LOCATION], "/admin#catalog");
    assert!(listing(true).await.is_none());
    gateway.process.kill().await.unwrap();
}
