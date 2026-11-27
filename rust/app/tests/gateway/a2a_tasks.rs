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

#[tokio::test]
async fn a2a_push_configs_are_scoped_and_concurrent_retries_share_one_row() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let webhook = format!("http://{}/webhook", listener.local_addr().unwrap());
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!();
    };
    sqlx::raw_sql(
        "UPDATE roles SET permissions = '[\"a2a.read\",\"a2a.update\"]' WHERE id = 'developer';
         INSERT INTO a2a_agents (id,name,slug,endpoint_url,owner_email)
            VALUES ('owned','Owned','owned','https://agent.invalid','member@example.test'),
                   ('other','Other','other','https://agent.invalid','outsider@example.test');
         INSERT INTO a2a_tasks (id,a2a_agent_id,task_id)
            VALUES ('t1','owned','shared'),('t2','other','shared');",
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
        .with_credential_secret(Some("fixture-only-webhook-encryption-key")),
    );
    let gateway = Running::start(app.registration_router()).await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(6))
        .build()
        .unwrap();
    let owner = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let path = "/v1/a2a/owned/tasks/shared/pushNotificationConfigs";
    let first_url = gateway.url(path);
    let input = json!({"webhook_url":webhook,"auth_token":"fixture-only-webhook-token","events":["completed"]});
    for (credential, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(outsider.as_str()), StatusCode::NOT_FOUND),
    ] {
        let (status, _) = send(&client, first_url.clone(), input.clone(), credential).await;
        assert_eq!(status, expected);
    }
    let (status, _) = send(
        &client,
        first_url.clone(),
        json!({
            "webhook_url":"http://169.254.169.254/callback",
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (left, right) = tokio::join!(
        send(&client, first_url.clone(), input.clone(), Some(&owner)),
        send(&client, first_url.clone(), input, Some(&owner)),
    );
    let mut statuses = [left.0, right.0];
    statuses.sort_unstable();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::CREATED]);
    assert_eq!(left.1, right.1);
    assert!(left.1.get("auth_token").is_none());
    let id = left.1["id"].as_str().unwrap();
    let ciphertext: String =
        sqlx::query_scalar("SELECT auth_token FROM a2a_push_notification_configs WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(!ciphertext.contains("fixture-only-webhook-token"));
    let wrong_target = gateway.url(&format!(
        "/a2a/other/tasks/shared/pushNotificationConfigs/{id}"
    ));
    let deleted = client
        .delete(wrong_target)
        .bearer_auth(&outsider)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NOT_FOUND);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM a2a_push_notification_configs")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}
