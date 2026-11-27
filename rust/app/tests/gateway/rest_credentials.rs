// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn rest_tools_can_only_inherit_signing_credentials_on_the_linked_origin() {
    let upstream = Running::start(
        Router::new()
            .route(
                "/mcp",
                post(
                    |state: State<Arc<UpstreamStats>>,
                     mut headers: HeaderMap,
                     request: Json<Value>| async move {
                        let authorization = headers.remove(header::AUTHORIZATION).unwrap();
                        assert!(
                            authorization
                                .to_str()
                                .unwrap()
                                .starts_with("AWS4-HMAC-SHA256")
                        );
                        fixture_mcp(state, headers, request).await
                    },
                ),
            )
            .with_state(Arc::new(UpstreamStats::default())),
    )
    .await;
    let unrelated_requests = Arc::new(AtomicUsize::new(0));
    let unrelated = Running::start(
        Router::new()
            .route(
                "/call",
                post(|State(hits): State<Arc<AtomicUsize>>| async move {
                    hits.fetch_add(1, Ordering::Relaxed);
                    Json(json!({"received":true}))
                }),
            )
            .with_state(unrelated_requests.clone()),
    )
    .await;
    let database = database().await;
    let service = Arc::new(
        GatewayService::new(
            database.clone(),
            authorizer(database),
            UpstreamClient::new(
                EgressPolicy {
                    allow_localhost: true,
                    ..EgressPolicy::default()
                },
                Duration::from_secs(5),
            )
            .with_connect_mode(ConnectMode::Legacy),
            Pagination::new(100, 900, None),
            CatalogRefresh::default(),
        )
        .with_credential_secret(Some("linked-rest-test-credential-envelope")),
    );
    let gateway = Running::start(
        service
            .registration_router()
            .merge(service.mcp_router(true, ProtocolMode::Auto)),
    )
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let (status, registered) = send(
        &client,
        gateway.url("/gateways"),
        json!({
            "name":"signed-peer","url":upstream.url("/mcp"),"transport":"STREAMABLEHTTP",
            "visibility":"public","auth_type":"sigv4","sigv4_config":{
                "access_key_id":"FixtureGatewaySigning","secret_access_key":"t".repeat(40),
                "region":"us-east-1","service":"s3"
            }
        }),
        Some(&admin),
    )
    .await;
    assert!(status.is_success(), "{registered}");
    let (status, tool) = send(
        &client,
        gateway.url("/tools"),
        json!({"tool":{
            "name":"linked-api","url":unrelated.url("/call"),"integration_type":"REST",
            "request_type":"POST","gateway_id":registered["id"],"auth_type":"sigv4"
        }}),
        Some(&admin),
    )
    .await;
    assert!(status.is_success(), "{tool}");
    let (status, response) = send(
        &client,
        gateway.url("/mcp/"),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":tool["name"],"arguments":{}}}),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("must share the linked gateway's origin")),
        "{response}"
    );
    assert_eq!(unrelated_requests.load(Ordering::Relaxed), 0);
}
