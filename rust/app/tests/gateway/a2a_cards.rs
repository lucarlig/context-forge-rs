// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn a2a_card_credentials_stay_on_origin_and_extended_reads_require_ownership() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let foreign = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let endpoint = format!("http://{}/rpc", foreign.local_addr().unwrap());
    let card_provider = Running::start(
        Router::new().route(
            "/card.json",
            get(move |headers: HeaderMap| {
                let endpoint = endpoint.clone();
                async move {
                    assert_eq!(headers[header::AUTHORIZATION], "Bearer fixture-card-auth");
                    Json(json!({"name":"card", "capabilities":{"extendedAgentCard":true},
                        "supportedInterfaces":[{"url":endpoint,"protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}))
                }
            }),
        ),
    )
    .await;
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::raw_sql(
        "UPDATE roles SET permissions='[\"a2a.create\",\"a2a.read\",\"a2a.update\"]' WHERE id='developer';
         INSERT INTO a2a_agents (id,name,slug,endpoint_url,owner_email,visibility,team_id)
            VALUES ('owned','Owned','owned','https://agent.invalid','member@example.test','public',NULL),
                   ('hidden','Hidden','hidden','https://agent.invalid','member@example.test','team','alpha');
         INSERT INTO a2a_agent_cards (id,a2a_agent_id,version,kind,card,detected_version,source_url)
            VALUES ('card-1','owned',1,'public','{\"name\":\"public fixture\"}','1.0','https://agent.invalid/card'),
                   ('card-2','owned',2,'extended','{\"name\":\"protected fixture\"}','1.0','https://agent.invalid/card');
         UPDATE a2a_agents SET skills='[{\"id\":\"shared\"}]' WHERE id='owned';
         UPDATE a2a_agents SET skills='[{\"id\":\"team-only\"}]',
            capabilities='{\"streaming\":true,\"defaultInputModes\":[\"image/png\"]}' WHERE id='hidden';
         INSERT INTO servers (id,name,visibility) VALUES ('a2a-server','Virtual agent','public');
         INSERT INTO server_interfaces (id,server_id,protocol,binding,version)
            VALUES ('a2a-interface','a2a-server','a2a-jsonrpc','https://gateway.invalid/agent','1.0');
         INSERT INTO server_a2a_association VALUES ('a2a-server','owned'), ('a2a-server','hidden');",
    ).execute(pool).await.unwrap();
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
            .with_a2a_settings(enabled, Duration::from_secs(3)),
        )
    };
    let gateway = Running::start(service(true).registration_router()).await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap();
    let owner = token("member", json!(["alpha"]), json!({}));
    let other = token("outsider", json!(["beta"]), json!({}));
    let reader = token(
        "member",
        json!(["alpha"]),
        json!({"permissions":["a2a.read"]}),
    );
    let (status, discovered) = send(
        &client,
        gateway.url("/a2a/fetch-card"),
        json!({
            "base_url":card_provider.url("/card.json"),
            "headers":{"Authorization":"Bearer fixture-card-auth"},
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(discovered["extendedOutcome"], "unavailable");
    assert!(!discovered.to_string().contains("fixture-card-auth"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), foreign.accept())
            .await
            .is_err()
    );

    let stored = |suffix| gateway.url(&format!("/a2a/owned/stored-card{suffix}"));
    let status = client
        .get(stored(""))
        .bearer_auth(&other)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::OK);
    let extended = stored("/extended");
    for (credential, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(other.as_str()), StatusCode::NOT_FOUND),
        (Some(reader.as_str()), StatusCode::FORBIDDEN),
        (Some(owner.as_str()), StatusCode::OK),
    ] {
        let request = client.get(&extended);
        let request = match credential {
            Some(credential) => request.bearer_auth(credential),
            None => request,
        };
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), expected);
    }
    let status = client
        .get(gateway.url("/a2a/hidden/card"))
        .bearer_auth(&other)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::NOT_FOUND);
    let virtual_card = gateway.url("/v1/a2a/a2a-server/card");
    for (credential, visible_skills, streaming) in [
        (&owner, json!([{"id":"team-only"},{"id":"shared"}]), true),
        (&other, json!([{"id":"shared"}]), false),
    ] {
        let response = client
            .get(&virtual_card)
            .bearer_auth(credential)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        let card: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(card["skills"], visible_skills);
        assert_eq!(card["capabilities"]["streaming"], streaming);
    }
    let disabled = Running::start(service(false).registration_router()).await;
    let status = client
        .get(disabled.url("/a2a/owned/card"))
        .bearer_auth(&owner)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::NOT_FOUND);
}
