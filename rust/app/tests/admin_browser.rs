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
    gateway_with_env(&[]).await
}

async fn gateway_with_env(env: &[(&str, &str)]) -> BrowserGateway {
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
        .env("SSRF_ALLOW_LOCALHOST", "true")
        .envs(env.iter().copied())
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

#[tokio::test]
async fn admin_prompt_editor_preserves_the_row_when_validation_fails() {
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
    let create = client
        .post(format!("{origin}/v1/admin/prompts"))
        .bearer_auth(token)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("name=fixture-editor&visibility=public&template=Draft")
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);

    let listing = || async {
        let response = client
            .get(format!("{origin}/admin/prompts"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let data: serde_json::Value =
            serde_json::from_str(&response.text().await.unwrap()).unwrap();
        data["data"][0].clone()
    };
    let draft = listing().await;
    let id = draft["id"].as_str().unwrap();
    assert_eq!(draft["template"], "Draft");
    assert_eq!(draft["createdVia"], "ui");
    let update = |arguments| {
        client
            .post(format!("{origin}/admin/prompts/{id}/edit"))
            .bearer_auth(token)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "name=fixture-editor&visibility=public&template=Published&arguments={arguments}"
            ))
    };
    let rejected = update("invalid").send().await.unwrap();
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(listing().await, draft);
    let published = update("%5B%5D").send().await.unwrap();
    assert_eq!(published.status(), StatusCode::OK);
    let updated = listing().await;
    assert_eq!(updated["template"], "Published");
    assert_eq!(updated["modifiedVia"], "ui");
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn admin_gateway_json_update_preserves_owner_and_unsubmitted_fields() {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    use serde_json::{Value, json};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}/mcp", listener.local_addr().unwrap());
    let upstream_task = tokio::spawn(async move {
        let fixture = Router::new().route(
            "/mcp",
            post(|Json(packet): Json<Value>| async move {
                if packet["id"].is_null() {
                    return StatusCode::ACCEPTED.into_response();
                }
                let result = match packet["method"].as_str() {
                    Some("initialize") => json!({
                        "protocolVersion":packet["params"]["protocolVersion"],
                        "serverInfo":{"name":"admin-editor-fixture","version":"1"},
                        "capabilities":{"tools":{}}
                    }),
                    Some("tools/list") => json!({"tools":[]}),
                    _ => json!({}),
                };
                Json(json!({"jsonrpc":"2.0","id":packet["id"],"result":result})).into_response()
            }),
        );
        axum::serve(listener, fixture).await.unwrap();
    });

    let mut fixture = gateway().await;
    let client = &fixture.client;
    let origin = &fixture.origin;
    let login = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({"email":EMAIL, "password":fixture.password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let login: Value = serde_json::from_str(&login.text().await.unwrap()).unwrap();
    let jwt = login["access_token"].as_str().unwrap();
    let base = format!("{origin}/v1/admin/gateways");
    let created = client
        .post(&base)
        .bearer_auth(jwt)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "name":"fixture-editor", "url":upstream, "transport":"STREAMABLEHTTP",
                "visibility":"public", "description":"Draft",
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let created: Value = serde_json::from_str(&created.text().await.unwrap()).unwrap();
    let gateway = &created["gateway"];
    assert_eq!(gateway["createdVia"], "ui");
    let url = format!("{base}/{}", gateway["id"].as_str().unwrap());
    let updated = client
        .put(&url)
        .bearer_auth(jwt)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"description":"Published","ownerEmail":"other@example.test"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    let detail = client.get(&url).bearer_auth(jwt).send().await.unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    let detail: Value = serde_json::from_str(&detail.text().await.unwrap()).unwrap();
    assert_eq!(detail["description"], "Published");
    assert_eq!(detail["modifiedVia"], "ui");
    assert_eq!(detail["ownerEmail"], EMAIL);
    assert_eq!(detail["visibility"], "public");
    assert_eq!(detail["url"], upstream);

    let deleted = client.delete(&url).bearer_auth(jwt).send().await.unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert!(deleted.text().await.unwrap().is_empty());
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(jwt)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    fixture.process.kill().await.unwrap();
    upstream_task.abort();
}

#[tokio::test]
async fn gateway_oauth_browser_session_requires_csrf_for_tool_fetch() {
    let mut gateway = gateway().await;
    let client = &gateway.client;
    let origin = &gateway.origin;
    let login = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email":EMAIL,"password":gateway.password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let login: serde_json::Value = serde_json::from_str(&login.text().await.unwrap()).unwrap();
    let jwt = login["access_token"].as_str().unwrap();
    let created = client.post(format!("{origin}/gateways"))
        .bearer_auth(jwt)
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({
            "name":"oauth-browser-fixture", "url":format!("{origin}/upstream"), "visibility":"public",
            "transport":"STREAMABLEHTTP", "auth_type":"oauth",
            "oauth_config":{
                "grant_type":"authorization_code", "issuer":origin, "token_url":format!("{origin}/token"),
                "authorization_url":format!("{origin}/consent"), "redirect_uri":format!("{origin}/oauth/callback"),
                "client_id":"fixture-client", "client_secret":"fixture-value"
            }
        }).to_string())
        .send().await.unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let created: serde_json::Value = serde_json::from_str(&created.text().await.unwrap()).unwrap();
    let id = created["id"].as_str().unwrap();
    let session = format!("jwt_token={jwt}");
    let home = client
        .get(format!("{origin}/admin/?section=gateways"))
        .header(header::COOKIE, &session)
        .send()
        .await
        .unwrap();
    assert_eq!(home.status(), StatusCode::OK);
    let proof = cookie(&home, "mcpgateway_csrf_token").to_owned();
    assert!(
        home.text()
            .await
            .unwrap()
            .contains("Authorization required")
    );
    let authorize = client
        .get(format!("{origin}/oauth/authorize/{id}"))
        .header(header::ACCEPT, "text/html")
        .header(header::COOKIE, &session)
        .send()
        .await
        .unwrap();
    assert_eq!(authorize.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = authorize.headers()[header::LOCATION].to_str().unwrap();
    assert!(location.starts_with(&format!("{origin}/consent?")));
    assert!(location.contains("code_challenge_method=S256"));

    for (site, header_value) in [
        (origin.as_str(), ""),
        ("https://foreign.example.test", proof.as_str()),
        (origin.as_str(), "mismatch"),
    ] {
        let response = client
            .post(format!("{origin}/oauth/fetch-tools/{id}"))
            .header(header::ACCEPT, "text/html")
            .header(
                header::COOKIE,
                format!("{session}; mcpgateway_csrf_token={proof}"),
            )
            .header(header::ORIGIN, site)
            .header("X-CSRF-Token", header_value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let raw_token = client
        .get(format!("{origin}/oauth/token/{id}"))
        .header(header::ACCEPT, "text/html")
        .header(header::COOKIE, &session)
        .send()
        .await
        .unwrap();
    assert_eq!(raw_token.status(), StatusCode::UNAUTHORIZED);
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn dashboard_token_is_issued_once_and_revoked_by_its_owner() {
    let mut fixture = gateway().await;
    let client = &fixture.client;
    let origin = &fixture.origin;
    let login = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email":EMAIL,"password":fixture.password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let login: serde_json::Value = serde_json::from_str(&login.text().await.unwrap()).unwrap();
    let jwt = login["access_token"].as_str().unwrap();
    let no_expiry = client
        .post(format!("{origin}/tokens"))
        .bearer_auth(jwt)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"name":"expiry-required"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(no_expiry.status(), StatusCode::BAD_REQUEST);

    let session = format!("jwt_token={jwt}");
    let panel = client
        .get(format!("{origin}/admin/?section=tokens"))
        .header(header::COOKIE, &session)
        .send()
        .await
        .unwrap();
    assert_eq!(panel.status(), StatusCode::OK);
    let proof = cookie(&panel, "mcpgateway_csrf_token");
    let cookies = format!("{session}; mcpgateway_csrf_token={proof}");
    let create = client
        .post(format!("{origin}/admin/tokens"))
        .header(header::COOKIE, &cookies)
        .header(header::ORIGIN, origin)
        .header(header::ACCEPT, "text/html")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "name=fixture-token&expires_in_days=2&permissions=tools.read&csrf_token={proof}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    assert!(
        create.headers()[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    let html = create.text().await.unwrap();
    let secret = html
        .split_once("autocomplete=\"off\">")
        .unwrap()
        .1
        .split_once("</textarea>")
        .unwrap()
        .0;
    assert_eq!(secret.split('.').count(), 3);
    let tools = || client.get(format!("{origin}/tools")).bearer_auth(secret);
    assert_eq!(tools().send().await.unwrap().status(), StatusCode::OK);

    let search = || {
        client
            .get(format!(
                "{origin}/admin/tokens/search?include_inactive=true"
            ))
            .bearer_auth(jwt)
    };
    let rows = search().send().await.unwrap();
    assert_eq!(rows.status(), StatusCode::OK);
    let raw = rows.text().await.unwrap();
    assert!(!raw.contains(secret));
    let rows: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let id = rows[0]["id"].as_str().unwrap();
    let revoke = || {
        client
            .delete(format!("{origin}/admin/tokens/{id}"))
            .header(header::COOKIE, &cookies)
            .header(header::ORIGIN, origin)
            .header(header::ACCEPT, "text/html")
    };
    assert_eq!(
        revoke().send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(tools().send().await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        revoke()
            .header("X-CSRF-Token", proof)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        tools().send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let rows = search().send().await.unwrap().text().await.unwrap();
    let rows: serde_json::Value = serde_json::from_str(&rows).unwrap();
    assert_eq!(rows[0]["is_revoked"], true);
    fixture.process.kill().await.unwrap();
}

#[tokio::test]
async fn admin_users_apply_directory_permissions_and_account_lifecycle() {
    let mut gateway = gateway().await;
    let BrowserGateway {
        client,
        origin,
        password,
        ..
    } = &gateway;
    let encode = |fields: &[(&str, &str)]| {
        let mut body = url::form_urlencoded::Serializer::new(String::new());
        body.extend_pairs(fields.iter().copied());
        body.finish()
    };
    let login_url = format!("{origin}/admin/login");
    let login = client.get(&login_url).send().await.unwrap();
    let proof = cookie(&login, "mcpgateway_csrf_token");
    let signed_in = client
        .post(&login_url)
        .header(header::ORIGIN, origin)
        .header(header::COOKIE, format!("mcpgateway_csrf_token={proof}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(encode(&[
            ("email", EMAIL),
            ("password", password),
            ("csrf_token", proof),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), StatusCode::SEE_OTHER);
    let proof = cookie(&signed_in, "mcpgateway_csrf_token");
    let cookies = format!(
        "jwt_token={}; mcpgateway_csrf_token={proof}",
        cookie(&signed_in, "jwt_token")
    );
    let directory = format!("{origin}/admin/users");
    let email = "mary+fixture@example.test";
    let new_password = "Fixture!NewAccount_83zP";
    let create = |proof: &str| {
        client
            .post(&directory)
            .header(header::ORIGIN, origin)
            .header(header::ACCEPT, "text/html")
            .header(header::COOKIE, &cookies)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(encode(&[
                ("email", email),
                ("full_name", "Literal_% <name>"),
                ("password", new_password),
                ("csrf_token", proof),
            ]))
    };
    assert_eq!(
        create("forged").send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        create(proof).send().await.unwrap().status(),
        StatusCode::CREATED
    );

    let search = client
        .get(format!(
            "{directory}/search?{}",
            encode(&[("q", " Literal_% ")])
        ))
        .header(header::ACCEPT, "text/html")
        .header(header::COOKIE, &cookies)
        .send()
        .await
        .unwrap();
    let results: serde_json::Value = serde_json::from_str(&search.text().await.unwrap()).unwrap();
    assert_eq!(results["count"], 1);
    assert_eq!(results["items"][0]["email"], email);
    assert_eq!(results["items"][0]["full_name"], "Literal_% <name>");

    let dashboard = client
        .get(format!("{origin}/admin/?section=users"))
        .header(header::ACCEPT, "text/html")
        .header(header::COOKIE, &cookies)
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), StatusCode::OK);
    let body = dashboard.text().await.unwrap();
    assert!(body.contains("Literal_% &lt;name&gt;"));
    assert!(body.contains("mary%2Bfixture%40example%2Etest/edit"));
    assert!(!body.contains(new_password));
    assert!(!body.contains("admin%40example%2Ecom/deactivate"));

    let unprivileged = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email": email, "password": new_password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(unprivileged.status(), StatusCode::OK);
    let session: serde_json::Value =
        serde_json::from_str(&unprivileged.text().await.unwrap()).unwrap();
    let session = session["access_token"].as_str().unwrap();
    for path in ["", "/partial", "/search"] {
        let rejected = client
            .get(format!("{directory}{path}"))
            .bearer_auth(session)
            .send()
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    }
    let anonymous = client.get(&directory).send().await.unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let action = |path: &str| {
        client
            .post(format!("{directory}/{path}"))
            .header(header::ORIGIN, origin)
            .header(header::ACCEPT, "text/html")
            .header(header::COOKIE, &cookies)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(encode(&[("csrf_token", proof)]))
    };
    assert_eq!(
        action("admin%40example.com/deactivate")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let changed = action("mary%2Bfixture%40example.test/deactivate")
        .send()
        .await
        .unwrap();
    assert_eq!(changed.status(), StatusCode::OK);
    assert!(changed.text().await.unwrap().contains("Inactive"));
    let revoked = client
        .get(format!("{origin}/auth/email/me"))
        .bearer_auth(session)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn admin_team_directory_applies_token_scope_before_pagination_and_updates() {
    let mut gateway = gateway().await;
    let BrowserGateway {
        client,
        origin,
        password,
        ..
    } = &gateway;
    let session = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email": EMAIL, "password": password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(session.status(), StatusCode::OK);
    let session: serde_json::Value = serde_json::from_str(&session.text().await.unwrap()).unwrap();
    let administrator = session["access_token"].as_str().unwrap();
    let directory = format!("{origin}/admin/teams");
    for name in ["Fixture+Alpha", "Fixture+Zulu"] {
        let response = client
            .post(&directory)
            .bearer_auth(administrator)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("name={name}&visibility=private"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let response = client
        .get(format!("{directory}/search?q=fixture"))
        .bearer_auth(administrator)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let teams: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    let other = teams[0]["id"].as_str().unwrap();
    let own = teams[1]["id"].as_str().unwrap();

    let issued = client
        .post(format!("{origin}/tokens"))
        .bearer_auth(administrator)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "name": "fixture-team",
                "expires_in_days": 1,
                "team_id": own,
                "scope": {"permissions": ["admin.dashboard", "teams.read", "teams.update"]}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    let issued: serde_json::Value = serde_json::from_str(&issued.text().await.unwrap()).unwrap();
    let scoped = issued["access_token"].as_str().unwrap();

    let page = client
        .get(format!("{directory}/partial?q=fixture&per_page=1"))
        .bearer_auth(scoped)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let content = page.text().await.unwrap();
    assert!(content.contains("Fixture Zulu"));
    assert!(!content.contains("Fixture Alpha"));
    let missing_scope = client
        .get(format!("{directory}/{other}/members"))
        .bearer_auth(scoped)
        .send()
        .await
        .unwrap();
    assert_eq!(missing_scope.status(), StatusCode::FORBIDDEN);
    let update = |id: &str, credential: &str| {
        client
            .post(format!("{directory}/{id}/update"))
            .bearer_auth(credential)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("name=New+Fixture&visibility=private")
    };
    assert_eq!(
        update(other, scoped).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        update(own, scoped).send().await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    let denied = client
        .post(format!("{directory}/{own}/delete"))
        .bearer_auth(scoped)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn team_join_requests_keep_scope_and_serialize_cancel_and_approval() {
    let mut gateway = gateway().await;
    let BrowserGateway {
        client,
        origin,
        password,
        ..
    } = &gateway;
    let login = |email: &str, password: &str| {
        let request = client
            .post(format!("{origin}/auth/email/login"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(serde_json::json!({"email": email, "password": password}).to_string());
        async move {
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let session: serde_json::Value =
                serde_json::from_str(&response.text().await.unwrap()).unwrap();
            session["access_token"].as_str().unwrap().to_owned()
        }
    };
    let owner = login(EMAIL, password).await;
    let member_email = "joiner@example.test";
    let member_password = "Fixture!AccountPassword_83zP";
    let create = client
        .post(format!("{origin}/auth/email/admin/users"))
        .bearer_auth(&owner)
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email":member_email,"password":member_password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let applicant = login(member_email, member_password).await;

    let created = client
        .post(format!("{origin}/teams"))
        .bearer_auth(&owner)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"name":"Public Join Fixture","visibility":"public"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let team: serde_json::Value = serde_json::from_str(&created.text().await.unwrap()).unwrap();
    let team = team["id"].as_str().unwrap();
    let directory = format!("{origin}/admin/?section=teams&relationship=public");
    let page = client
        .get(&directory)
        .bearer_auth(&applicant)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.text().await.unwrap().contains("Public Join Fixture"));

    let memberships = client
        .get(format!("{origin}/teams"))
        .bearer_auth(&applicant)
        .send()
        .await
        .unwrap();
    assert_eq!(memberships.status(), StatusCode::OK);
    let memberships: serde_json::Value =
        serde_json::from_str(&memberships.text().await.unwrap()).unwrap();
    let own = memberships["teams"][0]["id"].as_str().unwrap();
    let issued = client
        .post(format!("{origin}/tokens"))
        .bearer_auth(&applicant)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "name":"team-join-fixture","team_id":own,"expires_in_days":1,
                "scope":{"permissions":["admin.dashboard","teams.join","teams.read"]},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    let token: serde_json::Value = serde_json::from_str(&issued.text().await.unwrap()).unwrap();
    let scoped = token["access_token"].as_str().unwrap();
    let scoped_directory = client
        .get(&directory)
        .bearer_auth(scoped)
        .send()
        .await
        .unwrap();
    assert_eq!(scoped_directory.status(), StatusCode::OK);
    assert!(
        !scoped_directory
            .text()
            .await
            .unwrap()
            .contains("Public Join Fixture")
    );

    let team_admin = format!("{origin}/admin/teams/{team}");
    let submit = |credential: &str| {
        client
            .post(format!("{team_admin}/join-request"))
            .bearer_auth(credential)
            .send()
    };
    assert_eq!(
        submit(scoped).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        submit(&applicant).await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(submit(&applicant).await.unwrap().status(), StatusCode::OK);
    let database = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        gateway.fixture.0.join("mcp.db").display()
    ))
    .await
    .unwrap();
    let request: String = sqlx::query_scalar(
        "SELECT id FROM email_team_join_requests WHERE team_id=? AND user_email=?",
    )
    .bind(team)
    .bind(member_email)
    .fetch_one(&database)
    .await
    .unwrap();

    let approve = client
        .post(format!("{team_admin}/join-requests/{request}/approve"))
        .bearer_auth(&owner)
        .send();
    let cancel = client
        .delete(format!("{team_admin}/join-request/{request}"))
        .bearer_auth(&applicant)
        .send();
    let (approve, cancel) = tokio::join!(approve, cancel);
    let (approve, cancel) = (approve.unwrap().status(), cancel.unwrap().status());
    assert!(matches!(
        (approve, cancel),
        (StatusCode::OK, StatusCode::NOT_FOUND) | (StatusCode::NOT_FOUND, StatusCode::OK)
    ));
    let status: String =
        sqlx::query_scalar("SELECT status FROM email_team_join_requests WHERE id=?")
            .bind(&request)
            .fetch_one(&database)
            .await
            .unwrap();
    let membership: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_team_members WHERE team_id=? AND user_email=? AND is_active",
    )
    .bind(team)
    .bind(member_email)
    .fetch_one(&database)
    .await
    .unwrap();
    if approve == StatusCode::OK {
        assert_eq!((status.as_str(), membership), ("approved", 1));
    } else {
        assert_eq!((status.as_str(), membership), ("cancelled", 0));
    }
    database.close().await;
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn admin_a2a_editor_preserves_credentials_and_honors_token_permissions() {
    let mut gateway = gateway().await;
    let BrowserGateway {
        client,
        origin,
        password,
        ..
    } = &gateway;
    let login = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email":EMAIL,"password":password}).to_string())
        .send()
        .await
        .unwrap();
    let login: serde_json::Value = serde_json::from_str(&login.text().await.unwrap()).unwrap();
    let owner = login["access_token"].as_str().unwrap();
    let secret = format!("agent-fixture-{}", Uuid::new_v4().simple());
    let form = |fields: &[(&str, &str)]| {
        let mut body = url::form_urlencoded::Serializer::new(String::new());
        body.extend_pairs(fields.iter().copied());
        body.finish()
    };
    let dir = format!("{origin}/admin/a2a");
    let created = client
        .post(&dir)
        .bearer_auth(owner)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form(&[
            ("name", "Agent Fixture"),
            ("endpoint_url", "http://127.0.0.1:1/a2a"),
            ("visibility", "public"),
            ("auth_type", "bearer"),
            ("auth_token", &secret),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let listing = client.get(&dir).bearer_auth(owner).send().await.unwrap();
    assert_eq!(listing.status(), StatusCode::OK);
    let listing = listing.text().await.unwrap();
    assert!(!listing.contains(&secret));
    let listing: serde_json::Value = serde_json::from_str(&listing).unwrap();
    let id = listing["data"][0]["id"].as_str().unwrap();
    let agent_team = listing["data"][0]["teamId"].as_str().unwrap();
    let compact_team = Uuid::parse_str(agent_team).unwrap().simple().to_string();
    let selected = client
        .get(format!("{dir}?team_id={compact_team}"))
        .bearer_auth(owner)
        .send()
        .await
        .unwrap();
    assert_eq!(selected.status(), StatusCode::OK);
    let selected: serde_json::Value =
        serde_json::from_str(&selected.text().await.unwrap()).unwrap();
    assert_eq!(selected["data"][0]["id"], id);
    let database = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        gateway.fixture.0.join("mcp.db").display()
    ))
    .await
    .unwrap();
    let read_credential = || {
        sqlx::query_scalar::<_, String>("SELECT auth_value FROM a2a_agents WHERE id=?")
            .bind(id)
            .fetch_one(&database)
    };
    let original = read_credential().await.unwrap();
    assert!(!original.contains(&secret));
    let editor = format!("{dir}/{id}/edit");
    let page = client.get(&editor).bearer_auth(owner).send().await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let body = page.text().await.unwrap();
    assert!(body.contains("Agent Fixture"));
    assert!(!body.contains(&secret));

    let other_team = client
        .post(format!("{origin}/teams"))
        .bearer_auth(owner)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"name":"Other Agent Team","visibility":"private"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(other_team.status(), StatusCode::CREATED);
    let other_team: serde_json::Value =
        serde_json::from_str(&other_team.text().await.unwrap()).unwrap();
    let issued = client
        .post(format!("{origin}/tokens"))
        .bearer_auth(owner)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "name":"agent-read","expires_in_days":1,"team_id":other_team["id"],
                "scope":{"permissions":["admin.dashboard","a2a.read"]},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    let issued: serde_json::Value = serde_json::from_str(&issued.text().await.unwrap()).unwrap();
    let reader = issued["access_token"].as_str().unwrap();
    let filtered = client
        .get(format!("{dir}?team_id={agent_team}"))
        .bearer_auth(reader)
        .send()
        .await
        .unwrap();
    assert_eq!(filtered.status(), StatusCode::OK);
    let filtered: serde_json::Value =
        serde_json::from_str(&filtered.text().await.unwrap()).unwrap();
    assert_eq!(filtered["pagination"]["total_items"], 0);
    let update = |credential: &str| {
        client
            .post(&editor)
            .bearer_auth(credential)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form(&[
                ("_dashboard", "true"),
                ("name", "Updated Agent"),
                ("visibility", "public"),
                ("team_id", agent_team),
            ]))
    };
    assert_eq!(
        update(reader).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        update(owner).send().await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    assert!(original == read_credential().await.unwrap());
    let detail = client
        .get(format!("{dir}/{id}"))
        .bearer_auth(reader)
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    let detail = detail.text().await.unwrap();
    assert!(detail.contains("Updated Agent"));
    assert!(!detail.contains(&secret));
    let denied = client
        .post(format!("{dir}/{id}/test"))
        .bearer_auth(reader)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    database.close().await;
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn grpc_dashboard_preserves_metadata_and_enforces_team_scope() {
    let mut gateway = gateway_with_env(&[("MCPGATEWAY_GRPC_ENABLED", "true")]).await;
    let BrowserGateway {
        client,
        origin,
        password,
        ..
    } = &gateway;
    let login = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email":EMAIL,"password":password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let login: serde_json::Value = serde_json::from_str(&login.text().await.unwrap()).unwrap();
    let owner = login["access_token"].as_str().unwrap();
    let mut teams = Vec::new();
    for name in ["gRPC service team", "Other service team"] {
        let created = client
            .post(format!("{origin}/teams"))
            .bearer_auth(owner)
            .header(header::CONTENT_TYPE, "application/json")
            .body(serde_json::json!({"name":name,"visibility":"private"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let team: serde_json::Value = serde_json::from_str(&created.text().await.unwrap()).unwrap();
        teams.push(team["id"].as_str().unwrap().to_owned());
    }
    let issue = client
        .post(format!("{origin}/tokens"))
        .bearer_auth(owner)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({"name":"grpc-team-role","expires_in_days":1,"team_id":teams[1],
            "scope":{"permissions":["admin.dashboard","admin.grpc"]}})
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(issue.status(), StatusCode::CREATED);
    let token: serde_json::Value = serde_json::from_str(&issue.text().await.unwrap()).unwrap();
    let scoped = token["access_token"].as_str().unwrap();

    let secret = format!("fixture-{}", Uuid::new_v4().simple());
    let metadata = serde_json::json!({"fixture-token":secret}).to_string();
    let form = |fields: &[(&str, &str)]| {
        let mut body = url::form_urlencoded::Serializer::new(String::new());
        body.extend_pairs(fields.iter().copied());
        body.finish()
    };
    let dir = format!("{origin}/admin/grpc");
    let create = client
        .post(format!("{dir}/new"))
        .bearer_auth(owner)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form(&[
            ("name", "gRPC Fixture"),
            ("target", "127.0.0.1:1"),
            ("visibility", "public"),
            ("team_id", &teams[0]),
            ("grpc_metadata", &metadata),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::SEE_OTHER);

    let list = client
        .get(format!("{origin}/v1/admin/grpc"))
        .bearer_auth(owner)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list: serde_json::Value = serde_json::from_str(&list.text().await.unwrap()).unwrap();
    let record = &list["data"][0];
    assert_eq!(record["grpc_metadata"]["fixture-token"], secret);
    assert_eq!(record["reflection_enabled"], false);
    let id = record["id"].as_str().unwrap();
    let editor = format!("{dir}/{id}/edit");
    let page = client.get(&editor).bearer_auth(owner).send().await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(!page.text().await.unwrap().contains(&secret));
    let change = |credential: &str| {
        client
            .post(&editor)
            .bearer_auth(credential)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form(&[
                ("name", "Updated gRPC Fixture"),
                ("grpc_metadata", ""),
            ]))
    };
    assert_eq!(
        change(scoped).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        change(owner).send().await.unwrap().status(),
        StatusCode::SEE_OTHER
    );

    let denied = client
        .post(format!("{dir}/{id}/manage"))
        .bearer_auth(scoped)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("action=delete")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let record = client
        .get(format!("{dir}/{id}"))
        .bearer_auth(owner)
        .send()
        .await
        .unwrap();
    assert_eq!(record.status(), StatusCode::OK);
    let record: serde_json::Value = serde_json::from_str(&record.text().await.unwrap()).unwrap();
    assert_eq!(record["name"], "Updated gRPC Fixture");
    assert_eq!(record["grpc_metadata"]["fixture-token"], secret);
    assert_eq!(record["team_id"], teams[0]);

    let login_url = format!("{origin}/admin/login");
    let page = client.get(&login_url).send().await.unwrap();
    let proof = cookie(&page, "mcpgateway_csrf_token");
    let browser = client
        .post(login_url)
        .header(header::ORIGIN, origin)
        .header(header::COOKIE, format!("mcpgateway_csrf_token={proof}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form(&[
            ("email", EMAIL),
            ("password", password),
            ("csrf_token", proof),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(browser.status(), StatusCode::SEE_OTHER);
    let proof = cookie(&browser, "mcpgateway_csrf_token");
    let jwt = cookie(&browser, "jwt_token");
    let cookies = format!("jwt_token={jwt}; mcpgateway_csrf_token={proof}");
    let request = |accept| client.get(&dir).header(header::ACCEPT, accept);
    assert_eq!(
        request("text/html").send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    for (accept, expected) in [
        ("application/json", StatusCode::UNAUTHORIZED),
        ("text/html", StatusCode::OK),
    ] {
        let response = request(accept)
            .header(header::COOKIE, &cookies)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }

    let deactivate = |site: &str| {
        client
            .post(format!("{dir}/{id}/state?activate=false"))
            .header(header::ACCEPT, "text/html")
            .header(header::ORIGIN, site)
            .header(header::COOKIE, &cookies)
    };
    assert_eq!(
        deactivate(origin).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        deactivate("https://foreign.example.test")
            .header("X-CSRF-Token", proof)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = deactivate(origin)
        .header("X-CSRF-Token", proof)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let record: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(record["enabled"], false);
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn roots_dashboard_shares_the_registry_and_requires_unrestricted_admin() {
    let mut gateway = gateway_with_env(&[("ROOT_ALLOWED_SCHEMES", "[\"https\"]")]).await;
    let BrowserGateway {
        client,
        origin,
        password,
        ..
    } = &gateway;
    let login = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email":EMAIL,"password":password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let login: serde_json::Value = serde_json::from_str(&login.text().await.unwrap()).unwrap();
    let admin = login["access_token"].as_str().unwrap();
    let team = client
        .post(format!("{origin}/teams"))
        .bearer_auth(admin)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"name":"Root fixture team","visibility":"private"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(team.status(), StatusCode::CREATED);
    let team: serde_json::Value = serde_json::from_str(&team.text().await.unwrap()).unwrap();
    let tokens = format!("{origin}/tokens");
    let scoped = client
        .post(&tokens)
        .bearer_auth(admin)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({"name":"root-team-token","expires_in_days":1,"team_id":team["id"],
            "scope":{"permissions":["admin.dashboard","admin.system_config"]}})
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(scoped.status(), StatusCode::CREATED);
    let scoped: serde_json::Value = serde_json::from_str(&scoped.text().await.unwrap()).unwrap();
    let restricted = scoped["access_token"].as_str().unwrap();
    let dashboard = client
        .get(format!("{origin}/admin/?section=roots"))
        .bearer_auth(restricted)
        .send()
        .await
        .unwrap();
    assert_eq!(dashboard.status(), StatusCode::OK);
    assert!(
        !dashboard
            .text()
            .await
            .unwrap()
            .contains("id=\"roots-heading\"")
    );

    let uri = "https://example.test/research%20docs";
    let admin_roots = format!("{origin}/v1/admin/roots");
    let create = |credential| {
        client
            .post(&admin_roots)
            .bearer_auth(credential)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("uri", uri)
                    .append_pair("name", "Research")
                    .finish(),
            )
    };
    assert_eq!(
        create(restricted).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let denied = client
        .get(format!("{admin_roots}/search"))
        .bearer_auth(restricted)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let mut events = tokio::time::timeout(
        Duration::from_secs(3),
        client
            .get(format!("{origin}/roots/changes"))
            .bearer_auth(admin)
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(events.status(), StatusCode::OK);
    let response = create(admin).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/admin#roots");
    let event = tokio::time::timeout(Duration::from_secs(3), async {
        let mut buffer = Vec::new();
        while !buffer.ends_with(b"\n\n") {
            buffer.extend_from_slice(&events.chunk().await.unwrap().expect("root change event"));
        }
        let frame = std::str::from_utf8(&buffer).unwrap().trim_end();
        serde_json::from_str::<serde_json::Value>(frame.strip_prefix("data: ").unwrap()).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(
        event,
        serde_json::json!({"type":"root_added","data":{"uri":uri,"name":"Research"}})
    );
    drop(events);

    let detail = client
        .get(format!(
            "{origin}/roots/https%3A%2F%2Fexample.test%2Fresearch%2520docs"
        ))
        .bearer_auth(admin)
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    let root: serde_json::Value = serde_json::from_str(&detail.text().await.unwrap()).unwrap();
    assert_eq!(root["uri"], uri);
    assert_eq!(root["name"], "Research");
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn unified_search_keeps_owned_tools_inside_the_token_team() {
    use serde_json::{Value, json};

    let mut gateway = gateway().await;
    let BrowserGateway {
        client,
        origin,
        password,
        ..
    } = &gateway;
    let post = |path, token: Option<&str>, body: Value| {
        let request = client
            .post(format!("{origin}{path}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
        let request = match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        async move {
            let response = request.send().await.unwrap();
            let status = response.status();
            let body = response.text().await.unwrap();
            assert!(status.is_success(), "{status} {body}");
            serde_json::from_str::<Value>(&body).unwrap()
        }
    };
    let login = post(
        "/auth/email/login",
        None,
        json!({"email":EMAIL,"password":password}),
    )
    .await;
    let admin = login["access_token"].as_str().unwrap();
    let mut teams = Vec::new();
    for (team, tool) in [
        ("Search Alpha", "alpha-owned"),
        ("Search Beta", "beta-owned"),
    ] {
        let team = post(
            "/teams",
            Some(admin),
            json!({"name":team,"visibility":"private"}),
        )
        .await;
        post(
            "/tools",
            Some(admin),
            json!({"tool":{"name":tool,"url":"https://example.test/search","integration_type":"REST",
                           "request_type":"GET","input_schema":{"type":"object"},"visibility":"private"},
                   "team_id":team["id"]}),
        )
        .await;
        teams.push(team);
    }
    post(
        "/servers",
        Some(admin),
        json!({"server":{"name":"search-owned-server"},"visibility":"public"}),
    )
    .await;
    let issued = post(
        "/tokens",
        Some(admin),
        json!({"name":"search-team-token","team_id":teams[0]["id"],"expires_in_days":1,
               "scope":{"permissions":["tools.read"]}}),
    )
    .await;
    let token = issued["access_token"].as_str().unwrap();
    let endpoint = format!("{origin}/v1/search?q=owned&entity_types=tools,servers");
    let search = |url, token: &str| client.get(url).bearer_auth(token).send();
    let baseline = search(endpoint.clone(), admin).await.unwrap();
    let baseline: Value = serde_json::from_str(&baseline.text().await.unwrap()).unwrap();
    assert_eq!(baseline["count"], 3);
    let scoped = search(endpoint.clone(), token).await.unwrap();
    assert_eq!(scoped.status(), StatusCode::OK);
    let scoped: Value = serde_json::from_str(&scoped.text().await.unwrap()).unwrap();
    assert_eq!(scoped["count"], 1);
    assert_eq!(scoped["items"][0]["name"], "alpha-owned");
    assert_eq!(scoped["results"]["servers"], json!([]));
    let other_team = format!("{endpoint}&team_id={}", teams[1]["id"].as_str().unwrap());
    let scoped = search(other_team, token).await.unwrap();
    assert_eq!(scoped.status(), StatusCode::OK);
    let scoped: Value = serde_json::from_str(&scoped.text().await.unwrap()).unwrap();
    assert_eq!(scoped["count"], 0);
    let forbidden = search(format!("{origin}/v1/admin/search?q=owned"), token)
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn registry_selects_gateways_after_enforcing_team_scope() {
    use serde_json::{Value, json};

    let mut gateway = gateway().await;
    let BrowserGateway {
        client,
        origin,
        password,
        fixture,
        ..
    } = &gateway;
    let post = |path, token: Option<&str>, body: Value| {
        let request = client
            .post(format!("{origin}{path}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
        let request = match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        async move {
            let response = request.send().await.unwrap();
            let status = response.status();
            let body = response.text().await.unwrap();
            assert!(status.is_success(), "{status} {body}");
            serde_json::from_str::<Value>(&body).unwrap()
        }
    };
    let login = post(
        "/auth/email/login",
        None,
        json!({"email":EMAIL,"password":password}),
    )
    .await;
    let admin = login["access_token"].as_str().unwrap();
    let selected = post("/teams", Some(admin), json!({"name":"Registry Selected"})).await;
    let sibling = post("/teams", Some(admin), json!({"name":"Registry Sibling"})).await;
    let scoped = post("/tokens", Some(admin), json!({
        "name":"registry-read","team_id":selected["id"],"expires_in_days":1,"scope":{"permissions":["servers.read"]}
    })).await;
    let token = scoped["access_token"].as_str().unwrap();
    let pool =
        sqlx::SqlitePool::connect(&format!("sqlite://{}", fixture.0.join("mcp.db").display()))
            .await
            .unwrap();
    for (id, visibility, team) in [
        ("owned", "private", sibling["id"].as_str()),
        ("shared", "public", None),
    ] {
        sqlx::query(
            "INSERT INTO gateways
            (id,name,slug,visibility,team_id,owner_email,created_via,url,transport)
            VALUES($1,$1,$1,$2,$3,$4,'catalog','https://mcp.deepwiki.com/mcp','STREAMABLEHTTP')",
        )
        .bind(id)
        .bind(visibility)
        .bind(team)
        .bind(if team.is_some() {
            EMAIL
        } else {
            "other@example.test"
        })
        .execute(&pool)
        .await
        .unwrap();
    }
    pool.close().await;
    let url = format!("{origin}/v1/catalog?search=deepwiki&show_registered_only=true");
    let unauthenticated = client.get(&url).send().await.unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    for (token, expected) in [(admin, "owned"), (token, "shared")] {
        let response = client.get(&url).bearer_auth(token).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let result: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(result["total"], 1);
        assert_eq!(result["servers"][0]["gateway_id"], expected);
    }
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn execution_metrics_record_live_reads_and_deny_scoped_resets() {
    use serde_json::{Value, json};

    let mut service = gateway().await;
    let (client, origin) = (&service.client, &service.origin);
    let post_json = |path, token: Option<&str>, body: Value| {
        let request = client
            .post(format!("{origin}{path}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
        let request = match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        async move {
            let response = request.send().await.unwrap();
            let status = response.status();
            let body = response.text().await.unwrap();
            assert!(status.is_success(), "{status} {body}");
            serde_json::from_str::<Value>(&body).unwrap()
        }
    };
    let login = post_json(
        "/auth/email/login",
        None,
        json!({"email":EMAIL, "password":service.password}),
    )
    .await;
    let admin = login["access_token"].as_str().unwrap();
    let resource = post_json("/resources", Some(admin), json!({
        "resource":{"name":"live-metric","uri":"file:///fixture/live-metric","content":"Metrics fixture"},
        "visibility":"public"
    })).await;
    let id = resource["id"].as_str().unwrap();
    let read = client
        .get(format!("{origin}/v1/resources/{id}"))
        .bearer_auth(admin)
        .send()
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    let team = post_json("/teams", Some(admin), json!({"name":"Metric Scope"})).await;
    let token = post_json(
        "/tokens",
        Some(admin),
        json!({
            "name":"scoped-metric-operator","team_id":team["id"],"expires_in_days":1,
            "scope":{"permissions":["admin.system_config"]}
        }),
    )
    .await;
    let token = token["access_token"].as_str().unwrap();
    let metrics = format!("{origin}/v1/admin/metrics");
    let reset = format!("{metrics}/reset");
    let denied = client.post(&reset).bearer_auth(token).send().await.unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let denied = client
        .get(&metrics)
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let denied = client
        .post(&reset)
        .header(header::COOKIE, format!("jwt_token={admin}"))
        .header(header::ACCEPT, "text/html")
        .header(header::ORIGIN, origin)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let summary = || async {
        let response = client
            .get(&metrics)
            .bearer_auth(admin)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_str::<Value>(&response.text().await.unwrap()).unwrap()
    };
    let recorded = summary().await;
    assert_eq!(recorded["resources"]["totalExecutions"], 1);
    assert_eq!(recorded["resources"]["successfulExecutions"], 1);
    assert_eq!(
        recorded["topPerformers"]["resources"][0]["name"],
        "file:///fixture/live-metric"
    );
    let cleared = client.post(&reset).bearer_auth(admin).send().await.unwrap();
    assert_eq!(cleared.status(), StatusCode::OK);
    let cleared = summary().await;
    assert_eq!(cleared["resources"]["totalExecutions"], 0);
    assert_eq!(cleared["topPerformers"]["resources"], json!([]));
    service.process.kill().await.unwrap();
}

#[tokio::test]
async fn registry_registration_requires_browser_proof_and_serializes_oauth_duplicates() {
    use serde_json::{Value, json};

    let directory =
        FixtureDirectory(std::env::temp_dir().join(Uuid::new_v4().simple().to_string()));
    std::fs::create_dir(&directory.0).unwrap();
    let path = directory.0.join("catalog.yml");
    std::fs::write(
        &path,
        r#"{"catalog_servers":[{"id":"staged","name":"OAuth Fixture","description":"Fixture",
            "url":"https://example.test/mcp","auth_type":"OAuth2.1","transport":"STREAMABLEHTTP"}]}"#,
    )
    .unwrap();
    let mut gateway =
        gateway_with_env(&[("MCPGATEWAY_CATALOG_FILE", path.to_str().unwrap())]).await;
    let BrowserGateway {
        client,
        origin,
        password,
        fixture,
        ..
    } = &gateway;
    let login = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({"email":EMAIL,"password":password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let login: Value = serde_json::from_str(&login.text().await.unwrap()).unwrap();
    let token = login["access_token"].as_str().unwrap();
    let denied = client
        .post(format!("{origin}/v1/admin/mcp-registry/staged/register"))
        .header(header::COOKIE, format!("jwt_token={token}"))
        .header(header::ACCEPT, "text/html")
        .header(header::ORIGIN, origin)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(
        denied
            .text()
            .await
            .unwrap()
            .contains("CSRF validation failed")
    );

    let canary = Uuid::new_v4().to_string();
    let register = |name: &str| {
        client
            .post(format!("{origin}/v1/catalog/staged/register"))
            .bearer_auth(token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                json!({
                    "name":name,
                    "oauth_credentials":{"client_id":name,"client_secret":canary},
                })
                .to_string(),
            )
            .send()
    };
    let (first, second) = tokio::join!(register("First fixture"), register("Second fixture"));
    let mut successes = 0;
    let mut conflicts = 0;
    for response in [first.unwrap(), second.unwrap()] {
        let status = response.status();
        let body = response.text().await.unwrap();
        assert!(!body.contains(&canary));
        let data: Value = serde_json::from_str(&body).unwrap();
        match status {
            StatusCode::OK => {
                successes += 1;
                assert_eq!(data["success"], true);
                assert_eq!(data["oauth_required"], true);
            }
            StatusCode::CONFLICT => {
                conflicts += 1;
                assert_eq!(data["detail"], "Server already registered");
            }
            _ => panic!("unexpected registration status {status}"),
        }
    }
    assert_eq!((successes, conflicts), (1, 1));
    let pool =
        sqlx::SqlitePool::connect(&format!("sqlite://{}", fixture.0.join("mcp.db").display()))
            .await
            .unwrap();
    let rows = sqlx::query_as::<_, (bool, String, String, String)>(
        "SELECT enabled,auth_type,created_via,CAST(oauth_config AS TEXT) FROM gateways WHERE url=$1"
    ).bind("https://example.test/mcp").fetch_all(&pool).await.unwrap();
    assert_eq!(rows.len(), 1);
    let (enabled, auth, created_via, stored) = &rows[0];
    assert!(!enabled);
    assert_eq!(auth, "oauth");
    assert_eq!(created_via, "catalog");
    let data: Value = serde_json::from_str(stored).unwrap();
    assert!(
        data["client_secret"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(!stored.contains(&canary));
    pool.close().await;
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn disabling_legacy_api_preserves_versioned_browser_forms_and_server_sse() {
    let mut gateway = gateway_with_env(&[
        ("LEGACY_API_ENABLED", "false"),
        ("MCPGATEWAY_UI_ENABLED", "true"),
        ("ROOT_ALLOWED_SCHEMES", "[\"https\"]"),
    ])
    .await;
    let BrowserGateway {
        client,
        origin,
        password,
        ..
    } = &gateway;
    let login = format!("{origin}/v1/admin/login");
    let redirect = client.get(origin).send().await.unwrap();
    assert_eq!(redirect.headers()[header::LOCATION], "/v1/admin/");
    assert_eq!(
        client
            .get(format!("{origin}/admin/login"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let page = client.get(&login).send().await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let proof = cookie(&page, "mcpgateway_csrf_token").to_owned();
    let signed_in = client
        .post(&login)
        .header(header::ORIGIN, origin)
        .header(header::COOKIE, format!("mcpgateway_csrf_token={proof}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "email={EMAIL}&password={password}&csrf_token={proof}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), StatusCode::SEE_OTHER);
    assert_eq!(signed_in.headers()[header::LOCATION], "/v1/admin");
    let jwt = cookie(&signed_in, "jwt_token");
    let proof = cookie(&signed_in, "mcpgateway_csrf_token");
    let cookies = format!("jwt_token={jwt}; mcpgateway_csrf_token={proof}");
    let root = |proof: &str| {
        client
            .post(format!("{origin}/v1/admin/roots"))
            .header(header::ACCEPT, "text/html")
            .header(header::ORIGIN, origin)
            .header(header::COOKIE, &cookies)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "csrf_token={proof}&uri=https%3A%2F%2Fexample.test%2Fdocs"
            ))
    };
    assert_eq!(
        root("").send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let saved = root(proof).send().await.unwrap();
    assert_eq!(saved.status(), StatusCode::SEE_OTHER);
    assert_eq!(saved.headers()[header::LOCATION], "/v1/admin#roots");

    let server = client
        .post(format!("{origin}/v1/servers"))
        .bearer_auth(jwt)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"server":{"name":"Versioned stream"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(server.status(), StatusCode::CREATED);
    let server: serde_json::Value = serde_json::from_str(&server.text().await.unwrap()).unwrap();
    let id = server["id"].as_str().unwrap();
    let path = format!("{origin}/servers/{id}");
    assert_eq!(
        client
            .get(format!("{path}/sse"))
            .bearer_auth(jwt)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let mut stream = client
        .get(format!("{origin}/v1/servers/{id}/sse"))
        .bearer_auth(jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), StatusCode::OK);
    assert!(!stream.headers().contains_key("sunset"));
    let endpoint = tokio::time::timeout(Duration::from_secs(3), async {
        let mut frame = Vec::new();
        while !frame.ends_with(b"\r\n\r\n") {
            frame.extend_from_slice(&stream.chunk().await.unwrap().expect("SSE endpoint"));
        }
        std::str::from_utf8(&frame)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap()
            .to_owned()
    })
    .await
    .unwrap();
    assert!(endpoint.starts_with(&format!("{origin}/v1/servers/{id}/message?session_id=")));
    let posted = client
        .post(endpoint)
        .bearer_auth(jwt)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), StatusCode::ACCEPTED);
    drop(stream);
    gateway.process.kill().await.unwrap();
}

#[tokio::test]
async fn diagnostics_require_unrestricted_admin_and_redact_sensitive_settings() {
    let omitted = format!("fixture-{}", Uuid::new_v4().simple());
    let label = "Fixture <status>";
    let mut gateway = gateway_with_env(&[
        ("APP_NAME", label),
        ("MCPGATEWAY_DIAGNOSTICS_SECRET", &omitted),
        ("MCPGATEWAY_FIXTURE_HEADERS", &omitted),
        ("MCPGATEWAY_FIXTURE_LABEL", label),
    ])
    .await;
    let BrowserGateway {
        client,
        origin,
        password,
        ..
    } = &gateway;
    let endpoint = format!("{origin}/v1/version");
    let anonymous = client.get(&endpoint).send().await.unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert!(!anonymous.text().await.unwrap().contains("uptime_seconds"));
    let login = client
        .post(format!("{origin}/auth/email/login"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"email":EMAIL,"password":password}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let login: serde_json::Value = serde_json::from_str(&login.text().await.unwrap()).unwrap();
    let admin = login["access_token"].as_str().unwrap();
    let team = client
        .post(format!("{origin}/teams"))
        .bearer_auth(admin)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"name":"Diagnostics fixture","visibility":"private"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(team.status(), StatusCode::CREATED);
    let team: serde_json::Value = serde_json::from_str(&team.text().await.unwrap()).unwrap();
    let scoped = client
        .post(format!("{origin}/tokens"))
        .bearer_auth(admin)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({"name":"team-diagnostics","expires_in_days":1,"team_id":team["id"],
            "scope":{"permissions":["admin.dashboard","admin.system_config"]}})
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(scoped.status(), StatusCode::CREATED);
    let scoped: serde_json::Value = serde_json::from_str(&scoped.text().await.unwrap()).unwrap();
    let scoped = scoped["access_token"].as_str().unwrap();
    let denied = client
        .get(&endpoint)
        .bearer_auth(scoped)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(!denied.text().await.unwrap().contains("uptime_seconds"));

    let response = client
        .get(&endpoint)
        .bearer_auth(admin)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    let body = response.text().await.unwrap();
    assert!(!body.contains(&omitted));
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(payload["platform"]["runtime"], "Rust");
    assert_eq!(payload["database"]["reachable"], true);
    assert_eq!(payload["env"]["MCPGATEWAY_FIXTURE_LABEL"], label);

    let html = client
        .get(format!("{endpoint}?fmt=html"))
        .bearer_auth(admin)
        .send()
        .await
        .unwrap();
    assert_eq!(html.status(), StatusCode::OK);
    let html = html.text().await.unwrap();
    assert!(html.contains("Fixture &lt;status&gt;"));
    assert!(!html.contains(label));
    assert!(!html.contains(&omitted));
    gateway.process.kill().await.unwrap();
}
