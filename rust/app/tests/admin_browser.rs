// SPDX-License-Identifier: Apache-2.0

use std::{net::TcpListener, path::PathBuf, process::Stdio, time::Duration};

use reqwest::{Client, Response, StatusCode, header, redirect::Policy};
use tokio::process::Command;
use uuid::Uuid;

struct FixtureDirectory(PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn browser_login_rejects_cross_origin_and_logout_revokes_the_session() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    let fixture = FixtureDirectory(std::env::temp_dir().join(Uuid::new_v4().simple().to_string()));
    std::fs::create_dir(&fixture.0).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let origin = format!("http://127.0.0.1:{port}");
    let email = "admin@example.com";
    let password = format!("Fixture!{}", Uuid::new_v4().simple());
    let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let mut gateway = Command::new(env!("CARGO_BIN_EXE_context-forge-rs"))
        .current_dir(&fixture.0)
        .env_clear()
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("JWT_SECRET_KEY", &key)
        .env("AUTH_ENCRYPTION_SECRET", &key)
        .env("PLATFORM_ADMIN_EMAIL", email)
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
    let login_url = format!("{origin}/admin/login");
    let login = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                gateway.try_wait().unwrap().is_none(),
                "gateway exited before login"
            );
            if let Ok(response) = client.get(&login_url).send().await {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let csrf = cookie(&login, "mcpgateway_csrf_token");
    let csrf_cookie = format!("mcpgateway_csrf_token={csrf}");
    let login_form = format!("email={email}&password={password}&csrf_token={csrf}");
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

    let accepted = sign_in(&origin).send().await.unwrap();
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
            .header(header::ORIGIN, &origin)
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
    gateway.kill().await.unwrap();
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
