// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn import_resources_and_prompts_through_the_scoped_catalog() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::raw_sql(
        r#"
        UPDATE roles SET permissions = '["prompts.create","resources.create"]' WHERE id='developer';
        INSERT INTO email_teams (id,name,slug,created_by,is_personal) VALUES
            ('personal-alpha','Personal Alpha','personal-alpha','member@example.test',TRUE),
            ('personal-beta','Personal Beta','personal-beta','outsider@example.test',TRUE);
        INSERT INTO email_team_members (id,team_id,user_email) VALUES
            ('personal-a','personal-alpha','member@example.test'),
            ('personal-b','personal-beta','outsider@example.test');
        INSERT INTO roles (id,name,scope,permissions,created_by) VALUES
            ('catalog-import','catalog-import','global','["admin.import"]','admin@example.test');
        INSERT INTO user_roles (id,user_email,role_id,scope,granted_by) VALUES
            ('import-a','member@example.test','catalog-import','global','admin@example.test'),
            ('import-b','outsider@example.test','catalog-import','global','admin@example.test');
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
    let service = Arc::new(GatewayService::new(
        database.clone(),
        authorizer(database.clone()),
        UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(2)),
        Pagination::new(10, 60, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(service.registration_router()).await;
    let client = Client::builder().no_proxy().build().unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let owner = token("member", json!(["alpha", "personal-alpha"]), json!({}));
    let delegate = token("outsider", json!(["beta", "personal-beta"]), json!({}));
    let (status, original_prompt) = send(
        &client,
        gateway.url("/v1/prompts"),
        json!({"prompt":{"name":"greet","template":"Hi {{ person }}"},"team_id":"alpha"}),
        Some(&owner),
    )
    .await;
    assert!(status.is_success(), "{original_prompt}");
    let (status, original_resource) = send(
        &client,
        gateway.url("/v1/resources"),
        json!({"resource":{"uri":"fixture://notes/shared","name":"Shared","content":"Original"},"team_id":"alpha"}),
        Some(&owner),
    )
    .await;
    assert!(status.is_success(), "{original_resource}");

    let revised_prompt = json!({
        "name":"greet","template":"# User:\nHello {{ person }}","display_name":"Greeting",
        "input_schema":{"type":"object","properties":{"person":{"description":"Person name","type":"string"}},"required":["person"]},
        "visibility":"team","team_id":"beta","owner_email":"outsider@example.test"
    });
    let revised_resource = json!({
        "uri":"fixture://notes/shared","name":"Revised","content":"New text",
        "gateway_id":"injected-gateway","visibility":"team","team_id":"beta","owner_email":"outsider@example.test"
    });
    let both = json!({"prompts":[revised_prompt],"resources":[revised_resource]});
    let import = async |entities: Value, strategy: &str, dry_run: bool, credential: &str| {
        let (status, result) = send(
            &client,
            gateway.url("/v1/import"),
            json!({
                "import_data":{"version":"2025-11-25","exported_at":"2026-11-27T00:00:00Z","entities":entities},
                "conflict_strategy":strategy,"dry_run":dry_run
            }),
            Some(credential),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["status"], "completed");
        result
    };
    let get = async |path: &str| {
        let response = client
            .get(gateway.url(path))
            .bearer_auth(&admin)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice::<Value>(&response.bytes().await.unwrap()).unwrap()
    };
    let resource_path = format!(
        "/v1/resources/{}",
        original_resource["id"].as_str().unwrap()
    );
    let result = import(both.clone(), "update", true, &owner).await;
    assert_eq!(
        result["warnings"],
        json!([
            "Would import resource: fixture://notes/shared",
            "Would import prompt: greet"
        ])
    );
    assert_eq!(result["progress"]["processed"], 0);
    assert_eq!(get(&resource_path).await["text"], "Original");

    let mut partial = both.clone();
    partial["resources"].as_array_mut().unwrap().push(json!({
        "uri":"fixture://notes/new","name":"New","content":"Imported text","team_id":"alpha",
        "owner_email":"member@example.test","visibility":"public","gateway_id":"injected-gateway"
    }));
    partial["prompts"].as_array_mut().unwrap().push(json!({
        "name":"exported","original_name":"source","custom_name":"local","display_name":"Local prompt",
        "template":"Text from an export", "team_id":"alpha","owner_email":"member@example.test"
    }));
    let result = import(partial, "update", false, &delegate).await;
    assert_eq!(
        result["progress"],
        json!({"total":4,"processed":2,"created":2,"updated":0,"skipped":0,"failed":2})
    );
    assert_eq!(
        result["errors"],
        json!([
            "Permission denied: cannot update resource fixture://notes/shared",
            "Permission denied: cannot update prompt greet"
        ])
    );
    assert_eq!(get(&resource_path).await["text"], "Original");
    let resources = get("/v1/resources?limit=0").await;
    let fresh = resources
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "New")
        .unwrap();
    assert_eq!(fresh["ownerEmail"], "outsider@example.test");
    assert_eq!(fresh["teamId"], "personal-beta");
    assert_eq!(fresh["visibility"], "team");
    assert!(fresh["gatewayId"].is_null());
    assert_eq!(fresh["createdVia"], "import");
    assert_eq!(fresh["importBatchId"], result["import_id"]);
    let fresh_id = fresh["id"].as_str().unwrap();
    assert_eq!(
        get(&format!("/v1/resources/{fresh_id}")).await["text"],
        "Imported text"
    );

    let result = import(both.clone(), "skip", false, &owner).await;
    assert_eq!(result["progress"]["skipped"], 2);
    assert_eq!(result["warnings"], json!([]));
    let result = import(both.clone(), "fail", false, &owner).await;
    assert_eq!(
        result["errors"],
        json!([
            "Resource URI conflict: fixture://notes/shared",
            "Prompt name conflict: greet"
        ])
    );
    let result = import(both.clone(), "update", false, &owner).await;
    assert_eq!(result["progress"]["updated"], 2);
    let result = import(both, "rename", false, &owner).await;
    assert_eq!(result["progress"]["created"], 2);
    assert_eq!(result["warnings"], json!([]));

    let uri = get(&resource_path).await;
    assert_eq!(uri["text"], "New text");
    let resource = get(&format!("{resource_path}/info")).await;
    assert_eq!(resource["name"], "Revised");
    assert_eq!(resource["ownerEmail"], "member@example.test");
    assert_eq!(resource["teamId"], "alpha");
    assert_eq!(resource["visibility"], "public");
    assert_eq!(resource["modifiedVia"], "import");
    let prompts = get("/v1/prompts?limit=0").await;
    let prompts = prompts.as_array().unwrap();
    let original = prompts
        .iter()
        .find(|item| item["id"] == original_prompt["id"])
        .unwrap();
    assert_eq!(original["displayName"], "Greeting");
    assert_eq!(original["ownerEmail"], "member@example.test");
    assert_eq!(original["teamId"], "alpha");
    assert_eq!(original["visibility"], "public");
    assert_eq!(
        original["arguments"],
        json!([{"name":"person","description":"Person name","required":true}])
    );
    let renamed = prompts
        .iter()
        .find(|item| {
            item["customName"]
                .as_str()
                .is_some_and(|name| name.starts_with("greet_imported_"))
        })
        .unwrap();
    assert_eq!(renamed["originalName"], "greet");
    let fresh_prompt = prompts.iter().find(|item| item["name"] == "local").unwrap();
    assert_eq!(fresh_prompt["originalName"], "source");
    assert_eq!(fresh_prompt["customName"], "local");
    assert_eq!(fresh_prompt["displayName"], "Local prompt");
    assert_eq!(fresh_prompt["ownerEmail"], "outsider@example.test");
    assert_eq!(fresh_prompt["teamId"], "personal-beta");
    let (status, reply) = send(
        &client,
        gateway.url(&format!(
            "/v1/prompts/{}",
            original_prompt["id"].as_str().unwrap()
        )),
        json!({"person":"Reader"}),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["messages"][0]["content"]["text"], "Hello Reader");
}
