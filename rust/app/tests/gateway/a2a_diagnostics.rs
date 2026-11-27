// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn a2a_diagnostics_classify_errors_and_keep_team_metrics_private() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let hits = Arc::new(AtomicUsize::new(0));
    let fixture = Running::start(
        Router::new()
            .route("/agent", post(|State(hits): State<Arc<AtomicUsize>>, Json(body): Json<Value>| async move {
                hits.fetch_add(1, Ordering::Relaxed);
                Json(json!({"jsonrpc":"2.0","id":body["id"],"error":{"code":-32001,"message":"fixture rejection"}}))
            }))
            .with_state(hits.clone()),
    ).await;
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::raw_sql(
        "UPDATE roles SET permissions='[\"a2a.read\",\"a2a.invoke\"]' WHERE id='developer';
         INSERT INTO a2a_agents (id,name,slug,endpoint_url,visibility,team_id,owner_email)
            VALUES ('public','Public','public','https://fixture.example','public',NULL,'member@example.test'),
                   ('team','Team','team','https://fixture.example','team','alpha','member@example.test'),
                   ('private','Private','private','https://fixture.example','private',NULL,'member@example.test');
         INSERT INTO a2a_agent_metrics (a2a_agent_id,timestamp,response_time,is_success,interaction_type)
            VALUES ('public','2020-01-02 09:01:00',0.75,TRUE,'query'),
                   ('public','2020-01-02 10:25:00',50,FALSE,'query'),
                   ('private',CURRENT_TIMESTAMP,0.5,TRUE,'query');
         INSERT INTO a2a_agent_metrics_hourly (a2a_agent_id,agent_name,hour_start,interaction_type,total_count,
             success_count,failure_count,min_response_time,max_response_time,avg_response_time)
            VALUES ('public','Public','2020-01-02 10:00:00','query',2,2,0,1.0,2.0,1.5);",
    ).execute(pool).await.unwrap();
    sqlx::query("UPDATE a2a_agents SET endpoint_url=$1 WHERE id='team'")
        .bind(fixture.url("/agent"))
        .execute(pool)
        .await
        .unwrap();
    let service = Arc::new(GatewayService::new(
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
    ));
    let gateway = Running::start(service.registration_router()).await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap();
    let owner = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let reader = token(
        "member",
        json!(["alpha"]),
        json!({"permissions":["a2a.read"]}),
    );
    let path = gateway.url("/v1/a2a/team/test");
    for (credential, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(outsider.as_str()), StatusCode::NOT_FOUND),
        (Some(reader.as_str()), StatusCode::FORBIDDEN),
    ] {
        let (status, body) = send(&client, path.clone(), json!({}), credential).await;
        assert_eq!(status, expected, "{body}");
        if expected == StatusCode::NOT_FOUND {
            assert_eq!(body["detail"]["error_type"], "not_found");
        }
    }
    assert_eq!(hits.load(Ordering::Relaxed), 0);
    let (status, body) = send(&client, path, json!({"query":"fixture"}), Some(&owner)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["error"]["code"], -32001);
    assert_eq!(hits.load(Ordering::Relaxed), 1);

    for (credential, agents, events, failures) in [(&outsider, 1, 3, 0), (&owner, 3, 5, 1)] {
        let response = client
            .get(gateway.url("/v1/a2a/metrics"))
            .bearer_auth(credential)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(body["totalAgents"], agents);
        assert_eq!(body["totalInteractions"], events);
        assert_eq!(body["failedInteractions"], failures);
        assert_eq!(body["maxResponseTime"], 2.0);
        if agents == 1 {
            assert_eq!(body["avgResponseTime"], 1.25);
        }
    }
    let metric: (String, bool, String) = sqlx::query_as(
        "SELECT interaction_type,is_success,error_message FROM a2a_agent_metrics WHERE a2a_agent_id='team'",
    ).fetch_one(pool).await.unwrap();
    assert_eq!(
        metric,
        (
            "test".into(),
            false,
            "A2A agent returned a JSON-RPC error".into()
        )
    );
}
