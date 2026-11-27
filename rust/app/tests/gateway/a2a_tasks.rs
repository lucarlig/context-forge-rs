// SPDX-License-Identifier: Apache-2.0

use super::*;
use tokio::sync::Notify;

#[derive(Default)]
struct TaskFixture {
    entered: Notify,
    released: Notify,
    hits: AtomicUsize,
}

#[tokio::test]
async fn a2a_task_writes_require_ownership_and_late_replies_preserve_cancellation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fixture = Arc::new(TaskFixture::default());
    let upstream = Running::start(
        Router::new()
            .route(
                "/agent",
                post(
                    |State(fixture): State<Arc<TaskFixture>>, Json(request): Json<Value>| async move {
                        fixture.hits.fetch_add(1, Ordering::Relaxed);
                        if let Some(task) = request["params"]["message"].get("taskId") {
                            assert_eq!(task.as_str(), Some("work"));
                            assert_eq!(request["params"]["message"]["contextId"], "stored-context");
                            fixture.entered.notify_one();
                            fixture.released.notified().await;
                        }
                        Json(json!({
                            "jsonrpc":"2.0","id":request["id"],
                            "result":{"id":"work","contextId":"stored-context","status":{"state":"TASK_STATE_WORKING"}}
                        }))
                    },
                ),
            )
            .with_state(fixture.clone()),
    )
    .await;
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!();
    };
    sqlx::query(
        "UPDATE roles SET permissions = '[\"a2a.create\",\"a2a.read\",\"a2a.invoke\"]' WHERE id = 'developer'",
    )
    .execute(pool)
    .await
    .unwrap();
    let app = Arc::new(
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
        .with_a2a_settings(true, Duration::from_secs(5)),
    );
    let gateway = Running::start(app.registration_router()).await;
    let owner = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(6))
        .build()
        .unwrap();
    let (status, agent) = send(&client,gateway.url("/a2a/"),json!({
        "agent":{"name":"task-agent","endpoint_url":upstream.url("/agent"),"protocol_binding":"jsonrpc"},
    }),Some(&owner)).await;
    assert_eq!(status, StatusCode::CREATED, "{agent}");
    let agent_id = agent["id"].as_str().unwrap();
    let root = format!("/a2a/{agent_id}/tasks");
    let (status, _) = send(
        &client,
        gateway.url("/a2a/invoke"),
        json!({
            "agent_id":agent_id,"parameters":{"query":"new task"},
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for path in [&root, &format!("{root}/work")] {
        let status = client
            .get(gateway.url(path))
            .bearer_auth(&outsider)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    for action in ["messages", "cancel"] {
        let (status, _) = send(
            &client,
            gateway.url(&format!("{root}/work/{action}")),
            json!({"text":"outside owner"}),
            Some(&outsider),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    assert_eq!(fixture.hits.load(Ordering::Relaxed), 1);

    let follow_up = client
        .post(gateway.url(&format!("{root}/work/messages")))
        .bearer_auth(&owner)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({"message":{"parts":[{"kind":"fixture-secret","text":"fixture-secret"}]}})
                .to_string(),
        );
    let in_flight = tokio::spawn(async move { follow_up.send().await.unwrap() });
    tokio::time::timeout(Duration::from_secs(2), fixture.entered.notified())
        .await
        .unwrap();
    let (status, canceled) = send(
        &client,
        gateway.url(&format!("{root}/work/cancel")),
        json!({}),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(canceled["status"]["state"], "canceled");
    fixture.released.notify_one();
    assert_eq!(in_flight.await.unwrap().status(), StatusCode::OK);

    let (status,state) = sqlx::query_as::<_,(String,String)>(
        "SELECT state,CAST(completed_at AS TEXT) FROM a2a_tasks WHERE a2a_agent_id=$1 AND task_id='work'",
    ).bind(agent_id).fetch_one(pool).await.unwrap();
    assert_eq!(status, "canceled");
    assert!(!state.is_empty());
    let continuation: String = sqlx::query_scalar(
        "SELECT CAST(payload AS TEXT) FROM a2a_task_events WHERE a2a_agent_id=$1 AND task_id='work'",
    ).bind(agent_id).fetch_one(pool).await.unwrap();
    assert!(!continuation.contains("fixture-secret"));
    let continuation: Value = serde_json::from_str(&continuation).unwrap();
    assert_eq!(continuation["parts"], json!([{"kind":"text","length":14}]));
    assert_eq!(continuation["state"], "canceled");
    assert_eq!(fixture.hits.load(Ordering::Relaxed), 2);
}
