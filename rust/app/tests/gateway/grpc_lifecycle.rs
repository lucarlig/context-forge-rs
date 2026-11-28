// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn grpc_writes_check_team_scope_and_reject_stale_reflection() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::query(
        "INSERT INTO grpc_services (id, name, slug, target, owner_email, team_id, visibility, reachable)
         VALUES ('grpc', 'gRPC', 'grpc', $1, 'member@example.test', 'alpha', 'team', TRUE)",
    )
    .bind(upstream.local_addr().unwrap().to_string())
    .execute(pool)
    .await
    .unwrap();
    sqlx::raw_sql(
        "UPDATE roles SET permissions = '[\"admin.grpc\",\"tools.read\",\"tools.execute\"]'
            WHERE id = 'developer';
         INSERT INTO tools (id, name, original_name, custom_name, custom_name_slug, integration_type,
                grpc_service_id, input_schema, visibility, team_id, owner_email)
            VALUES ('grpc-tool', 'grpc-echo', 'fixture.Echo.Call', 'grpc-echo', 'grpc-echo',
                'gRPC', 'grpc', '{}', 'team', 'alpha', 'member@example.test');
         INSERT INTO servers (id, name, visibility) VALUES ('grpc-server', 'gRPC server', 'public');
         INSERT INTO server_tool_association (server_id, tool_id) VALUES ('grpc-server', 'grpc-tool');
         INSERT INTO tool_metrics (tool_id, response_time, is_success) VALUES ('grpc-tool', 0.25, TRUE);",
    )
    .execute(pool)
    .await
    .unwrap();
    let service = Arc::new(
        GatewayService::new(
            database.clone(),
            authorizer(database.clone()),
            UpstreamClient::new(
                EgressPolicy {
                    allow_localhost: true,
                    ..EgressPolicy::default()
                },
                Duration::from_secs(5),
            ),
            Pagination::new(100, 900, None),
            CatalogRefresh::default(),
        )
        .with_grpc_settings(GrpcSettings {
            enabled: true,
            admin_enabled: true,
            timeout: Duration::from_secs(3),
            ..GrpcSettings::default()
        }),
    );
    let gateway = Running::start(service.registration_router()).await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let member = token("member", json!(["alpha"]), json!({}));
    for (credential, total) in [(&outsider, 0), (&member, 1)] {
        let response = client
            .get(gateway.url("/admin/grpc"))
            .bearer_auth(credential)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(page["pagination"]["total_items"], total);
    }
    for route in ["state", "reflect", "delete"] {
        let response = client
            .post(gateway.url(&format!("/admin/grpc/grpc/{route}")))
            .bearer_auth(&outsider)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), upstream.accept())
            .await
            .is_err()
    );

    let refresh = client
        .post(gateway.url("/admin/grpc/grpc/reflect"))
        .bearer_auth(&member);
    let refreshing = tokio::spawn(async move { refresh.send().await.unwrap().status() });
    let (socket, _) = tokio::time::timeout(Duration::from_secs(2), upstream.accept())
        .await
        .unwrap()
        .unwrap();
    let result = client
        .put(gateway.url("/admin/grpc/grpc"))
        .bearer_auth(&member)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "description":"New revision",
                "visibility":"private",
                "owner_email":"outsider@example.test",
                "team_id":"beta"
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    let record: Value = serde_json::from_slice(&result.bytes().await.unwrap()).unwrap();
    assert_eq!(record["description"], "New revision");
    assert_eq!(record["team_id"], "alpha");
    assert_eq!(record["owner_email"], "member@example.test");
    assert_eq!(record["visibility"], "private");
    drop(socket);
    assert_eq!(refreshing.await.unwrap(), StatusCode::CONFLICT);
    let stored: (bool, String) = sqlx::query_as(
        "SELECT s.reachable, t.visibility FROM grpc_services s
         JOIN tools t ON t.grpc_service_id = s.id WHERE s.id = 'grpc'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(stored, (true, "private".to_owned()));
    let deleted = client
        .post(gateway.url("/admin/grpc/grpc/delete"))
        .bearer_auth(&member)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let remaining: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM grpc_services), (SELECT COUNT(*) FROM tools),
                (SELECT COUNT(*) FROM server_tool_association), (SELECT COUNT(*) FROM tool_metrics)",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(remaining, (0, 0, 0, 0));
}
