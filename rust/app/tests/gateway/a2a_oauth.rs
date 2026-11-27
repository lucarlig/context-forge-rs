// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn a2a_oauth_single_flight_respects_agent_scope_and_activation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let token_hits = Arc::new(AtomicUsize::new(0));
    let fixture = Running::start(
        Router::new()
            .route(
                "/token",
                post(
                    |State(hits): State<Arc<AtomicUsize>>, form: String| async move {
                        let fields: HashMap<_, _> =
                            url::form_urlencoded::parse(form.as_bytes()).collect();
                        assert_eq!(fields["grant_type"], "client_credentials");
                        assert_eq!(fields["client_secret"], "fixture-only-service-secret");
                        assert_eq!(fields["resource"], "https://fixture.example/target");
                        hits.fetch_add(1, Ordering::Relaxed);
                        Json(json!({"access_token":"fixture-only-service-token","expires_in":3600}))
                    },
                ),
            )
            .route(
                "/rpc",
                post(
                    |headers: HeaderMap, Json(message): Json<Value>| async move {
                        assert_eq!(
                            headers[header::AUTHORIZATION],
                            "Bearer fixture-only-service-token"
                        );
                        Json(json!({"jsonrpc":"2.0","id":message["id"],"result":{"ok":true}}))
                    },
                ),
            )
            .with_state(token_hits.clone()),
    )
    .await;
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::query("UPDATE roles SET permissions='[\"a2a.create\",\"a2a.read\",\"a2a.update\",\"a2a.invoke\"]' WHERE id='developer'")
        .execute(pool).await.unwrap();
    let app = Arc::new(
        GatewayService::new(
            database.clone(),
            authorizer(database.clone()),
            UpstreamClient::new(
                EgressPolicy {
                    allow_localhost: true,
                    ..EgressPolicy::default()
                },
                Duration::from_secs(4),
            ),
            Pagination::new(100, 900, None),
            CatalogRefresh::default(),
        )
        .with_credential_secret(Some("fixture-only-encryption-key")),
    );
    let gateway = Running::start(app.registration_router()).await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let owner = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let config = json!({
        "client_id":"service-fixture","client_secret":"fixture-only-service-secret",
        "token_url":fixture.url("/token"),"grant_type":"client_credentials",
        "resource":"https://fixture.example/target",
    });
    let agent = json!({
        "name":"OAuth fixture","endpoint_url":fixture.url("/rpc"),
        "protocol_binding":"jsonrpc","auth_type":"oauth","oauth_config":config,
        "passthrough_headers":["authorization"],
    });
    let mut blocked = agent.clone();
    blocked["oauth_config"]["token_url"] = json!("http://169.254.169.254/token");
    let (status, _) = send(
        &client,
        gateway.url("/a2a/"),
        json!({
            "agent":blocked,"team_id":"alpha","visibility":"team",
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, registered) = send(
        &client,
        gateway.url("/a2a/"),
        json!({
            "agent":agent,"team_id":"alpha","visibility":"team",
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{registered}");
    assert_eq!(registered["oauthConfig"]["client_secret"], "*****");
    let id = registered["id"].as_str().unwrap();
    let encoded: String =
        sqlx::query_scalar("SELECT CAST(oauth_config AS TEXT) FROM a2a_agents WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(!encoded.contains("fixture-only-service-secret"));
    assert!(encoded.contains("v2:"));
    let invoke = |bearer| {
        send(
            &client,
            gateway.url("/a2a/invoke"),
            json!({"agent_id":id,"parameters":{"query":"read"}}),
            Some(bearer),
        )
    };
    assert_eq!(invoke(&outsider).await.0, StatusCode::NOT_FOUND);
    assert_eq!(token_hits.load(Ordering::Relaxed), 0);
    let (left, right) = tokio::join!(invoke(&owner), invoke(&owner));
    assert_eq!(left.0, StatusCode::OK, "{}", left.1);
    assert_eq!(left, right);
    assert_eq!(token_hits.load(Ordering::Relaxed), 1);

    let mut invalid = config;
    invalid["token_url"] = json!(fixture.url("/different-token"));
    invalid["client_secret"] = json!("*****");
    let status = client
        .put(gateway.url(&format!("/a2a/{id}")))
        .bearer_auth(&owner)
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({"oauth_config":invalid}).to_string())
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    for active in [false, true] {
        let status = client
            .post(gateway.url(&format!("/a2a/{id}/state?activate={active}")))
            .bearer_auth(&owner)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::OK);
        let (status, body) = invoke(&owner).await;
        assert_eq!(
            status,
            if active {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            "{body}"
        );
        assert_eq!(
            token_hits.load(Ordering::Relaxed),
            if active { 2 } else { 1 }
        );
    }
}
