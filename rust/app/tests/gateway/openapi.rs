// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn openapi_generation_checks_create_permission_and_shares_in_flight_downloads() {
    let fetched = Arc::new(AtomicUsize::new(0));
    let upstream = Running::start(
        Router::new()
            .route(
                "/openapi.json",
                get(|State(fetched): State<Arc<AtomicUsize>>| async move {
                    fetched.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Json(json!({
                        "paths": {"/items/{id}": {"post": {
                            "requestBody": {"content":{"application/json":{
                                "schema":{"$ref":"#/components/schemas/Item"}
                            }}}
                        }}},
                        "components":{"schemas":{"Item":{"type":"object"}}}
                    }))
                }),
            )
            .with_state(fetched.clone()),
    )
    .await;
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    let service = Arc::new(GatewayService::new(
        database.clone(),
        authorizer(database.clone()),
        UpstreamClient::new(
            EgressPolicy {
                allow_localhost: true,
                ..EgressPolicy::default()
            },
            Duration::from_secs(5),
        ),
        Pagination::new(10, 900, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(service.registration_router()).await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let route = gateway.url("/v1/tools/generate-schemas-from-openapi");
    let arguments = json!({"url":upstream.url("/items/{id}"),"request_type":"POST"});
    let admin = token("admin", Value::Null, json!({}));
    let (status, _) = send(&client, route.clone(), arguments.clone(), Some(&admin)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(fetched.load(Ordering::Relaxed), 0);

    sqlx::raw_sql(
        "INSERT INTO roles (id,name,scope,permissions,created_by) VALUES
            ('openapi-writer','openapi-writer','global','[\"tools.create\"]','admin@example.test');
         INSERT INTO user_roles (id,user_email,role_id,scope,granted_by) VALUES
            ('openapi-admin','admin@example.test','openapi-writer','global','admin@example.test');",
    )
    .execute(pool)
    .await
    .unwrap();
    let first = send(&client, route.clone(), arguments.clone(), Some(&admin));
    let second = send(&client, route, arguments, Some(&admin));
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first, second);
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert_eq!(first.1["input_schema"], json!({"type":"object"}));
    assert!(first.1["output_schema"].is_null());
    assert_eq!(fetched.load(Ordering::Relaxed), 1);
}
