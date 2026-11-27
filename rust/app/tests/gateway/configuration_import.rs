// SPDX-License-Identifier: Apache-2.0

use super::*;
use context_forge_rs::gateway::RootSettings;

#[tokio::test]
async fn configuration_import_scopes_ownership_and_reports_partial_results() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::raw_sql(
        "
        INSERT INTO email_teams (id,name,slug,created_by,is_personal) VALUES
            ('personal-beta','Own Team','own-team','outsider@example.test',TRUE);
        INSERT INTO email_team_members (id,team_id,user_email) VALUES
            ('own-b','personal-beta','outsider@example.test');
        INSERT INTO roles (id,name,scope,permissions,created_by) VALUES
            ('team-import','team-import','team','[\"admin.import\"]','admin@example.test'),
            ('global-import','global-import','global','[\"admin.import\"]','admin@example.test');
        INSERT INTO user_roles (id,user_email,role_id,scope,scope_id,granted_by) VALUES
            ('team-import-b','outsider@example.test','team-import','team','beta','admin@example.test'),
            ('global-import-a','member@example.test','global-import','global',NULL,'admin@example.test');
        INSERT INTO tools (id,name,original_name,custom_name,custom_name_slug,
            integration_type,request_type,url,visibility,owner_email,team_id,input_schema)
        VALUES ('fixture','fixture-shared','fixture-shared','fixture-shared','fixture-shared',
            'REST','GET','https://example.org/original','public','member@example.test','alpha','{\"type\":\"object\"}');
    ",
    )
    .execute(pool)
    .await
    .unwrap();
    let service = Arc::new(
        GatewayService::new(
            database.clone(),
            authorizer(database.clone()),
            UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(2)),
            Pagination::new(10, 60, None),
            CatalogRefresh::default(),
        )
        .with_root_settings(
            RootSettings {
                network_schemes: ["https".to_owned()].into_iter().collect(),
                ..Default::default()
            },
            CancellationToken::new(),
        )
        .unwrap(),
    );
    let gateway = Running::start(service.registration_router()).await;
    let client = Client::new();
    let admin = token("admin", Value::Null, json!({}));
    let member = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta", "personal-beta"]), json!({}));
    let payload = |entities: Value, strategy: &str, dry_run: bool| {
        json!({
            "import_data":{"version":"2025-11-25","exported_at":"2026-11-27T00:00:00Z","entities":entities},
            "conflict_strategy":strategy,"dry_run":dry_run
        })
    };
    let tool = |name: &str, url: &str| {
        json!({
            "name":name,"url":url,"integration_type":"REST","request_type":"GET",
            "owner_email":"member@example.test","team_id":"alpha","visibility":"public",
        })
    };
    let mut data = payload(
        json!({"tools":[tool("fixture-shared","https://example.org/revised")]}),
        "update",
        false,
    );
    assert_eq!(
        send(&client, gateway.url("/v1/import"), data.clone(), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &client,
            gateway.url("/v1/import"),
            data.clone(),
            Some(&outsider)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    sqlx::query(
        "INSERT INTO user_roles (id,user_email,role_id,scope,granted_by) VALUES
        ('global-import-b','outsider@example.test','global-import','global','admin@example.test')",
    )
    .execute(pool)
    .await
    .unwrap();

    data["import_data"]["entities"]["tools"]
        .as_array_mut()
        .unwrap()
        .push(tool("imported", "https://example.org/new"));
    let (status, imported) = send(&client, gateway.url("/v1/import"), data, Some(&outsider)).await;
    assert_eq!(status, StatusCode::OK, "{imported}");
    assert_eq!(
        imported["progress"],
        json!({"total":2,"processed":1,"created":1,"updated":0,"skipped":0,"failed":1})
    );
    assert_eq!(
        imported["errors"],
        json!(["Permission denied: cannot update tool fixture-shared"])
    );
    let imported_id = imported["import_id"].as_str().unwrap();
    let imported_ownership: (String,String,String,String,String) = sqlx::query_as(
        "SELECT owner_email,team_id,visibility,created_via,import_batch_id FROM tools WHERE original_name='imported'",
    ).fetch_one(pool).await.unwrap();
    assert_eq!(
        imported_ownership,
        (
            "outsider@example.test".into(),
            "personal-beta".into(),
            "team".into(),
            "import".into(),
            imported_id.into()
        )
    );
    let original_url: String = sqlx::query_scalar("SELECT url FROM tools WHERE id='fixture'")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(original_url, "https://example.org/original");
    let detail = |id: &str| gateway.url(&format!("/import/status/{id}"));
    assert_eq!(
        client
            .get(detail(imported_id))
            .bearer_auth(&member)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let reported = client
        .get(detail(imported_id))
        .bearer_auth(&outsider)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reported).unwrap(),
        imported
    );

    let entities = json!({
        "tools":[tool("fixture-shared", "https://example.org/revised")],
        "roots":[{"uri":"https://example.org/workspace","name":"Workspace"}],
    });
    let (status, denied_root) = send(
        &client,
        gateway.url("/v1/import"),
        payload(entities.clone(), "update", true),
        Some(&outsider),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied_root}");
    let (status, preview) = send(
        &client,
        gateway.url("/v1/import"),
        payload(entities.clone(), "update", true),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["progress"]["total"], 2);
    assert_eq!(preview["progress"]["created"], 0);
    assert_eq!(
        preview["warnings"],
        json!(["Would import root", "Would import tool: fixture-shared"])
    );
    let mut selected = payload(entities, "update", false);
    selected["selected_entities"] = json!({"tools":[]});
    let (status, updated) = send(&client, gateway.url("/import"), selected, Some(&member)).await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(
        updated["progress"],
        json!({"total":1,"processed":1,"created":0,"updated":1,"skipped":0,"failed":0})
    );
    let row: (String, String, String) =
        sqlx::query_as("SELECT url,owner_email,team_id FROM tools WHERE id='fixture'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        row,
        (
            "https://example.org/revised".into(),
            "member@example.test".into(),
            "alpha".into()
        )
    );
    let roots = client
        .get(gateway.url("/v1/roots"))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&roots).unwrap(), json!([]));

    let (status, added_root) = send(
        &client,
        gateway.url("/import"),
        payload(
            json!({"roots":[{"uri":"https://example.org/workspace","name":"Workspace"}]}),
            "update",
            false,
        ),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{added_root}");
    assert_eq!(added_root["progress"]["created"], 1);
    for (strategy, outcome) in [
        ("skip", "skipped"),
        ("fail", "failed"),
        ("rename", "created"),
    ] {
        let (status, response) = send(
            &client,
            gateway.url("/v1/import"),
            payload(
                json!({"tools":[tool("fixture-shared","https://example.org/conflict")]}),
                strategy,
                false,
            ),
            Some(&admin),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{strategy}: {response}");
        assert_eq!(response["progress"][outcome], 1, "{strategy}: {response}");
    }
    let (status, cleanup) = send(
        &client,
        gateway.url("/v1/import/cleanup?max_age_hours=0"),
        json!({}),
        Some(&outsider),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cleanup}");
    assert_eq!(cleanup["removed_count"], 1);
    assert_eq!(
        client
            .get(detail(imported_id))
            .bearer_auth(&admin)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}
