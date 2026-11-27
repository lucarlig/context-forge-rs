// SPDX-License-Identifier: Apache-2.0

use super::*;

const REFERENCE: &str =
    include_str!("../../../replay/export-import/import/virtual-servers.expected.json");

#[tokio::test]
async fn configuration_import_restores_only_visible_virtual_server_tool_links() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::raw_sql("
        INSERT INTO email_teams (id,name,slug,created_by,is_personal) VALUES
            ('admin-private','Personal','personal','admin@example.test',TRUE);
        INSERT INTO email_team_members (id,team_id,user_email,role) VALUES
            ('admin-own','admin-private','admin@example.test','owner');
        INSERT INTO roles (id,name,scope,permissions,created_by) VALUES
            ('server-importer','server-importer','global','[\"admin.import\"]','admin@example.test');
        INSERT INTO user_roles (id,user_email,role_id,scope,granted_by) VALUES
            ('member-import','member@example.test','server-importer','global','admin@example.test');
        INSERT INTO servers (id,name,description,visibility,owner_email,team_id) VALUES
            ('outsider-server','public-elsewhere','original','public','outsider@example.test','beta');
        INSERT INTO tools (id,name,original_name,custom_name,custom_name_slug,visibility,
            owner_email,team_id,input_schema) VALUES
            ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','fixture-import-server-tool','fixture-import-server-tool',
             'fixture-import-server-tool','fixture-import-server-tool','public','member@example.test','alpha','{}'),
            ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','fixture-private-tool','fixture-private-tool',
             'fixture-private-tool','fixture-private-tool','private','outsider@example.test','beta','{}');
    ").execute(pool).await.unwrap();
    let service = Arc::new(GatewayService::new(
        database.clone(),
        authorizer(database.clone()),
        UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(2)),
        Pagination::new(10, 60, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(service.registration_router()).await;
    let client = Client::new();
    let admin = token("admin", Value::Null, json!({}));
    let expected: Value = serde_json::from_str(REFERENCE).unwrap();
    let post = |fields, strategy| {
        json!({
            "import_data":{
                "version":"2025-03-26","exported_at":"2026-01-01T00:00:00Z",
                "entities":{"servers":[fields]}
            },
            "conflict_strategy":strategy
        })
    };
    let cases = [
        (
            json!({
                "name":"fixture-import-server","description":"original","instructions":"fixture instructions",
                "tool_ids":["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","fixture-import-server-tool","missing-tool",
                            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
                "id":"someone-elses-id","team_id":"beta","owner_email":"outsider@example.test","visibility":"public"
            }),
            "update",
            Some("create"),
        ),
        (
            json!({
                "name":"fixture-import-server","description":"updated","tool_ids":["fixture-import-server-tool"]
            }),
            "update",
            Some("update_name"),
        ),
        (
            json!({"name":"fixture-import-server","instructions":null,"tool_ids":[]}),
            "update",
            Some("update_empty"),
        ),
        (json!({"name":"fixture-import-server"}), "skip", None),
        (json!({"name":"fixture-import-server"}), "fail", None),
    ];
    let mut original_id = None;
    for (index, (fields, strategy, state)) in cases.into_iter().enumerate() {
        let (status, import) = send(
            &client,
            gateway.url("/v1/import"),
            post(fields, strategy),
            Some(&admin),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(import["progress"], expected["progress"][index], "{import}");
        if let Some(state) = state {
            let (id, name, instructions, description, visibility, owner, team, provenance): (
                String,
                String,
                Option<String>,
                String,
                String,
                String,
                String,
                String,
            ) = sqlx::query_as(
                "SELECT id,name,instructions,description,visibility,owner_email,team_id,created_via
                    FROM servers WHERE name='fixture-import-server'",
            )
            .fetch_one(pool)
            .await
            .unwrap();
            assert_eq!(original_id.get_or_insert(id.clone()), &id);
            assert_eq!(
                (owner.as_str(), team.as_str(), provenance.as_str()),
                ("admin@example.test", "admin-private", "import")
            );
            let links: Vec<String> = sqlx::query_scalar(
                "SELECT tools.original_name
                FROM server_tool_association JOIN tools ON tools.id=tool_id WHERE server_id=$1",
            )
            .bind(&id)
            .fetch_all(pool)
            .await
            .unwrap();
            assert_eq!(
                json!({"name":name,"instructions":instructions,"description":description,
                              "visibility":visibility,"links":links}),
                expected[state]
            );
        }
    }

    let importer = token("member", json!(["alpha"]), json!({}));
    let (status, denied) = send(
        &client,
        gateway.url("/v1/import"),
        post(
            json!({"name":"public-elsewhere","description":"replacement"}),
            "update",
        ),
        Some(&importer),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(denied["progress"]["failed"], 1);
    let description: String =
        sqlx::query_scalar("SELECT description FROM servers WHERE id='outsider-server'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(description, "original");
}
