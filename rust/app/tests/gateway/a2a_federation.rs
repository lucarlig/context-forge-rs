// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn a2a_routes_and_mcp_tools_enforce_parent_scope_before_dispatch() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let calls = Arc::new(AtomicUsize::new(0));
    let upstream = Running::start(
        Router::new()
            .route(
                "/invoke",
                post(
                    |State(calls): State<Arc<AtomicUsize>>,
                     headers: HeaderMap,
                     Json(body): Json<Value>| async move {
                        calls.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(
                            headers.get(header::AUTHORIZATION).unwrap(),
                            "Bearer fixture-a2a-secret"
                        );
                        assert!(!headers.contains_key("x-vault-tokens"));
                        assert!(!headers.contains_key("x-unlisted"));
                        Json(json!({"query":body["parameters"]["query"]}))
                    },
                ),
            )
            .with_state(calls.clone()),
    )
    .await;
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::query(
        "UPDATE roles SET permissions = '[\"a2a.create\",\"a2a.read\",\"a2a.invoke\",\"servers.use\",\"tools.read\",\"tools.execute\"]' WHERE id = 'developer'",
    )
    .execute(pool)
    .await
    .unwrap();
    let service = |enabled| {
        Arc::new(
            GatewayService::new(
                database.clone(),
                authorizer(database.clone()),
                UpstreamClient::new(
                    EgressPolicy {
                        allow_localhost: true,
                        ..EgressPolicy::default()
                    },
                    Duration::from_secs(3),
                ),
                Pagination::new(100, 900, None),
                CatalogRefresh::default(),
            )
            .with_a2a_settings(enabled, Duration::from_secs(3))
            .with_credential_secret(Some("fixture-only-encryption-key")),
        )
    };
    let app = service(true);
    let gateway = Running::start(
        app.registration_router()
            .merge(app.mcp_router(true, ProtocolMode::Auto)),
    )
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap();
    let member = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let (status, created) = send(&client,gateway.url("/a2a/"),json!({
        "agent":{
            "name":"fixture-agent","endpoint_url":upstream.url("/invoke"),
            "protocol_binding":"http_json","auth_type":"bearer","auth_token":"fixture-a2a-secret",
            "passthrough_headers":["authorization","x-vault-tokens"],
        },
        "team_id":"alpha","visibility":"team",
    }),Some(&member)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["authValue"], "*****");
    let id = created["id"].as_str().unwrap();
    let stored: String = sqlx::query_scalar("SELECT auth_value FROM a2a_agents WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(!stored.contains("fixture-a2a-secret"));
    sqlx::query("UPDATE tools SET visibility = 'public' WHERE integration_type = 'A2A'")
        .execute(pool)
        .await
        .unwrap();
    let (status, detail) = send(
        &client,
        gateway.url("/a2a/invoke"),
        json!({
            "agent_id":id,"parameters":{"query":"outside team"},
        }),
        Some(&outsider),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{detail}");
    let rpc_call = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"a2a-fixture-agent","arguments":{"query":"scoped"},
    }});
    let (_, denied) = send(
        &client,
        gateway.url("/mcp/"),
        rpc_call.clone(),
        Some(&outsider),
    )
    .await;
    assert!(
        denied["error"].is_object() || denied["result"]["isError"] == true,
        "{denied}"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    let (status, result) = send_with_headers(
        &client,
        gateway.url("/a2a/fixture-agent/invoke"),
        json!({"parameters":{"query":"scoped"}}),
        Some(&member),
        &[
            ("x-vault-tokens", "fixture-vault-token"),
            ("x-unlisted", "unlisted"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["query"], "scoped");
    sqlx::query("UPDATE a2a_agents SET passthrough_headers = 'null' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE tools SET auth_type = 'bearer', auth_value = 'legacy copy' WHERE integration_type = 'A2A'")
        .execute(pool)
        .await
        .unwrap();
    let (_, result) = send(&client, gateway.url("/mcp/"), rpc_call, Some(&member)).await;
    assert_eq!(result["result"]["isError"], false, "{result}");
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    sqlx::query("UPDATE a2a_agents SET uaid = 'uaid:fixture' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    let (status, _) = send(
        &client,
        gateway.url("/a2a/invoke"),
        json!({"agent_id":id}),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    sqlx::raw_sql(
        "UPDATE a2a_agents SET uaid = NULL;
         CREATE TABLE a2a_agent_plugin_bindings
            (team_id TEXT, agent_name TEXT, plugin_id TEXT, mode TEXT);
         INSERT INTO a2a_agent_plugin_bindings VALUES ('alpha', '*', 'fixture-policy', 'enforce');",
    )
    .execute(pool)
    .await
    .unwrap();
    let (status, _) = send(
        &client,
        gateway.url("/a2a/invoke"),
        json!({"agent_id":id}),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    let disabled = Running::start(service(false).registration_router()).await;
    let (status, result) = send(
        &client,
        disabled.url("/a2a/invoke"),
        json!({"agent_id":id}),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(result["detail"]["error"], "a2a_disabled");
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}
