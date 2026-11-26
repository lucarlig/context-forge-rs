// SPDX-License-Identifier: Apache-2.0

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use context_forge_rs::{
    access::Authorizer,
    config::Settings,
    database::Database,
    gateway::{CatalogRefresh, GatewayService, Pagination},
    jwt::{JwtConfig, JwtVerifier},
    mcp::ProtocolMode,
    upstream::{ConnectMode, EgressPolicy, UpstreamClient},
};
use jiff::Timestamp;
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::Client;
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

const KEY: &[u8] = &[0x36; 32];
const PROTOCOL: &str = "2025-11-25";
const LIST: &str = include_str!("../../replay/mcp-legacy/rust/app-cases/http/03-tools-list.body");
const CALL: &str = include_str!("../../replay/mcp-legacy/rust/app-cases/http/04-tools-call.body");

struct Running {
    address: SocketAddr,
    shutdown: JoinHandle<()>,
}

impl Running {
    async fn start(router: Router) -> Self {
        let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self { address, shutdown }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown.abort();
    }
}

#[derive(Default)]
struct UpstreamStats {
    initialized: AtomicUsize,
    calls: AtomicUsize,
}

async fn fixture_mcp(
    State(stats): State<Arc<UpstreamStats>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    assert!(!headers.contains_key(header::AUTHORIZATION));
    let method = request["method"].as_str().unwrap();
    let id = &request["id"];
    if method != "initialize" {
        assert_eq!(headers["mcp-protocol-version"], PROTOCOL);
    }
    let result = match method {
        "initialize" => json!({
            "protocolVersion":PROTOCOL, "capabilities":{"tools":{"listChanged":false}},
            "serverInfo":{"name":"fixture upstream","version":"1"}
        }),
        "notifications/initialized" => {
            stats.initialized.fetch_add(1, Ordering::Relaxed);
            return StatusCode::ACCEPTED.into_response();
        }
        "tools/list" => {
            let list: Value = serde_json::from_str(LIST).unwrap();
            let mut tool = list["result"]["tools"][0].clone();
            tool["name"] = json!("echo");
            json!({"tools":[tool]})
        }
        "tools/call" => {
            stats.calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(request["params"]["name"], "echo");
            assert_eq!(request["params"]["arguments"], json!({"message":"hello"}));
            serde_json::from_str::<Value>(CALL).unwrap()["result"].clone()
        }
        _ => panic!("unexpected upstream method {method}"),
    };
    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
}

async fn database() -> Database {
    let database = Database::from_settings(&Settings {
        host: "127.0.0.1".into(),
        port: 4444,
        database_url: "sqlite:///:memory:".into(),
        db_pool_size: 1,
        db_pool_timeout: Duration::from_secs(1),
        sqlite_busy_timeout: Duration::from_secs(5),
        redis: None,
    })
    .unwrap();
    database.migrate_identity().await.unwrap();
    database.migrate_catalog().await.unwrap();
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::raw_sql("
        INSERT INTO email_users (id,email,is_admin) VALUES
            ('admin','admin@example.test',TRUE), ('member','member@example.test',FALSE), ('outsider','outsider@example.test',FALSE);
        INSERT INTO email_teams (id,name,slug,created_by) VALUES
            ('alpha','Alpha','alpha','admin@example.test'), ('beta','Beta','beta','admin@example.test');
        INSERT INTO email_team_members (id,team_id,user_email) VALUES
            ('a','alpha','member@example.test'), ('b','beta','outsider@example.test');
        INSERT INTO roles (id,name,scope,permissions,created_by) VALUES
            ('developer','developer','team','[\"servers.use\",\"tools.read\",\"tools.execute\"]','admin@example.test');
        INSERT INTO user_roles (id,user_email,role_id,scope,scope_id,granted_by) VALUES
            ('a','member@example.test','developer','team','alpha','admin@example.test'),
            ('b','outsider@example.test','developer','team','beta','admin@example.test');
    ").execute(pool).await.unwrap();
    database
}

fn token(subject: &str, teams: Value, scopes: Value) -> String {
    let now = Timestamp::now().as_second();
    let claims = json!({
        "sub":subject, "iss":"mcpgateway", "aud":"mcpgateway-api", "exp":now+60, "iat":now,
        "jti":uuid::Uuid::new_v4().simple().to_string(), "is_admin":subject=="admin",
        "token_use":"api", "teams":teams, "scopes":scopes,
    });
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(KEY).unwrap(),
    )
    .unwrap()
}

async fn send(
    client: &Client,
    url: String,
    payload: Value,
    credential: Option<&str>,
) -> (StatusCode, Value) {
    send_with_headers(client, url, payload, credential, &[]).await
}

async fn send_with_headers(
    client: &Client,
    url: String,
    payload: Value,
    credential: Option<&str>,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut request = client
        .post(url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(payload.to_string());
    if let Some(credential) = credential {
        request = request.bearer_auth(credential);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let body = response.bytes().await.unwrap();
    let parsed = serde_json::from_slice(&body).unwrap_or_else(|error| {
        panic!("HTTP {status}: {error}: {}", String::from_utf8_lossy(&body))
    });
    (status, parsed)
}

fn modern_request(method: &str, id: u32, mut params: Value) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}

#[tokio::test]
async fn registration_discovery_invocation_and_team_gates_work_over_http() {
    let database = database().await;
    let stats = Arc::new(UpstreamStats::default());
    let upstream = Running::start(
        Router::new()
            .route("/nested/mcp/", post(fixture_mcp))
            .with_state(stats.clone()),
    )
    .await;
    let authorizer = Arc::new(Authorizer::new(
        database.clone(),
        Some(
            JwtVerifier::new(JwtConfig {
                key: KEY,
                ..JwtConfig::default()
            })
            .unwrap(),
        ),
        true,
    ));
    let service = Arc::new(GatewayService::new(
        database.clone(),
        authorizer,
        UpstreamClient::new(
            EgressPolicy {
                allow_localhost: true,
                ..Default::default()
            },
            Duration::from_secs(5),
        )
        .with_connect_mode(ConnectMode::Legacy),
        Pagination::new(1, 900, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(
        service
            .registration_router()
            .merge(service.mcp_router(false, ProtocolMode::Auto)),
    )
    .await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let admin = token("admin", Value::Null, json!({}));
    let member = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let read_only = token(
        "member",
        json!(["alpha"]),
        json!({"permissions":["tools.read"]}),
    );
    let endpoint = upstream.url("/nested/mcp/");
    let payload = json!({"name":"fixture-echo","url":endpoint,"transport":"STREAMABLEHTTP","visibility":"public"});
    assert_eq!(
        send(&client, gateway.url("/gateways"), payload.clone(), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &client,
            gateway.url("/gateways"),
            payload.clone(),
            Some(&member)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(stats.initialized.load(Ordering::Relaxed), 0);
    let (status, registered) = send(
        &client,
        gateway.url("/v1/mcp-servers"),
        payload.clone(),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{registered}");
    assert_eq!(registered["ownerEmail"], "admin@example.test");
    assert_eq!(registered["toolCount"], 0);
    assert_eq!(registered["capabilities"]["tools"]["listChanged"], false);
    let list = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
    let call = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
        "name":"fixture-echo-echo","arguments":{"message":"hello"}
    }});
    assert_eq!(
        send(&client, gateway.url("/mcp/"), list.clone(), None).await,
        (StatusCode::OK, serde_json::from_str::<Value>(LIST).unwrap())
    );
    assert_eq!(
        send(&client, gateway.url("/mcp"), call.clone(), None).await,
        (StatusCode::OK, serde_json::from_str::<Value>(CALL).unwrap())
    );
    assert_eq!(
        send(&client, gateway.url("/gateways"), payload, Some(&admin))
            .await
            .0,
        StatusCode::CONFLICT
    );

    let payload = json!({"name":"team-fixture","url":endpoint,"transport":"STREAMABLEHTTP","visibility":"team","teamId":"alpha"});
    let (status, registered) =
        send(&client, gateway.url("/v1/gateways/"), payload, Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{registered}");
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::raw_sql(
        "
        INSERT INTO servers (id,name,team_id,owner_email,visibility)
            VALUES ('alpha-server','Alpha server','alpha','admin@example.test','team');
        INSERT INTO server_tool_association (server_id,tool_id)
            SELECT 'alpha-server',id FROM tools WHERE name='team-fixture-echo';
    ",
    )
    .execute(pool)
    .await
    .unwrap();
    let (_, page) = send(&client, gateway.url("/mcp/"), list.clone(), Some(&member)).await;
    let next_cursor = page["result"]["nextCursor"]
        .as_str()
        .expect("member sees two tools");
    let continued =
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":next_cursor}});
    let (_, next) = send(
        &client,
        gateway.url("/mcp/"),
        continued.clone(),
        Some(&member),
    )
    .await;
    assert!(next["result"]["nextCursor"].is_null());
    assert_ne!(
        page["result"]["tools"][0]["name"],
        next["result"]["tools"][0]["name"]
    );
    let (_, next) = send(&client, gateway.url("/mcp/"), continued, Some(&outsider)).await;
    assert_eq!(next["error"]["code"], -32602);
    let (_, public) = send(&client, gateway.url("/mcp/"), list.clone(), Some(&outsider)).await;
    assert_eq!(public, serde_json::from_str::<Value>(LIST).unwrap());
    let virtual_url = gateway.url("/servers/alpha-server/mcp/");
    let (status, page) = send(&client, virtual_url.clone(), list.clone(), Some(&member)).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["result"]["tools"][0]["name"], "team-fixture-echo");
    assert_eq!(
        send(&client, virtual_url.clone(), list, Some(&outsider))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let mut call = call;
    call["params"]["name"] = json!("team-fixture-echo");
    let (_, denied) = send(&client, virtual_url.clone(), call.clone(), Some(&read_only)).await;
    assert_eq!(denied["error"], json!({"code":0,"message":"Access denied"}));
    assert_eq!(
        send(&client, virtual_url.clone(), call, Some(&member)).await,
        (StatusCode::OK, serde_json::from_str::<Value>(CALL).unwrap())
    );
    assert_eq!(stats.calls.load(Ordering::Relaxed), 2);

    sqlx::raw_sql(
        r#"UPDATE gateways SET refresh_interval_seconds = 120 WHERE name = 'team-fixture';
           UPDATE servers SET instructions = 'Use the alpha echo tool.' WHERE id = 'alpha-server';
           UPDATE tools SET input_schema = json_set(
               input_schema, '$.properties.message."x-mcp-header"', 'Message'
           ) WHERE name = 'team-fixture-echo';"#,
    )
    .execute(pool)
    .await
    .unwrap();

    let modern = [("mcp-protocol-version", "2026-07-28")];
    let discover_headers = [modern[0], ("mcp-method", "server/discover")];
    let discover = modern_request("server/discover", 10, json!({}));
    let (status, response) = send_with_headers(
        &client,
        gateway.url("/v1/virtual-servers/alpha-server/mcp"),
        discover.clone(),
        Some(&member),
        &discover_headers,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        response["result"]["supportedVersions"],
        json!(["2026-07-28"])
    );
    assert_eq!(response["result"]["cacheScope"], "private");
    assert_eq!(response["result"]["ttlMs"], 120_000);
    assert_eq!(
        response["result"]["instructions"],
        "Use the alpha echo tool."
    );

    let (status, refused) = send_with_headers(
        &client,
        gateway.url("/mcp/"),
        discover.clone(),
        None,
        &[
            discover_headers[0],
            discover_headers[1],
            ("mcp-method", "tools/list"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"]["code"], -32020);

    let response = client
        .get(gateway.url("/mcp/"))
        .header(modern[0].0, modern[0].1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()[header::ALLOW], "POST, DELETE");

    let scoped_list = modern_request("tools/list", 11, json!({}));
    let list_headers = [modern[0], ("mcp-method", "tools/list")];
    let (_, response) = send_with_headers(
        &client,
        virtual_url.clone(),
        scoped_list.clone(),
        Some(&member),
        &list_headers,
    )
    .await;
    assert_eq!(response["result"]["tools"][0]["name"], "team-fixture-echo");
    assert_eq!(response["result"]["ttlMs"], 120_000);
    assert_eq!(
        send_with_headers(
            &client,
            virtual_url.clone(),
            scoped_list,
            Some(&outsider),
            &list_headers,
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );

    let call = modern_request(
        "tools/call",
        12,
        json!({
            "name":"team-fixture-echo","arguments":{"message":"hello"}
        }),
    );
    let call_headers = [
        modern[0],
        ("mcp-method", "tools/call"),
        ("mcp-name", "team-fixture-echo"),
        ("mcp-param-message", "hello"),
    ];
    let (status, response) = send_with_headers(
        &client,
        virtual_url.clone(),
        call.clone(),
        Some(&member),
        &call_headers,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        response["result"]["structuredContent"],
        json!({"result":"echo: hello"})
    );
    assert_eq!(response["result"]["resultType"], "complete");

    let (status, response) = send_with_headers(
        &client,
        virtual_url.clone(),
        call.clone(),
        Some(&member),
        &call_headers[..3],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], -32020);
    let (_, denied) =
        send_with_headers(&client, virtual_url, call, Some(&read_only), &call_headers).await;
    assert_eq!(denied["error"], json!({"code":0,"message":"Access denied"}));
    assert_eq!(stats.calls.load(Ordering::Relaxed), 3);

    let legacy = Running::start(service.mcp_router(false, ProtocolMode::Legacy)).await;
    let (status, refusal) = send_with_headers(
        &client,
        legacy.url("/mcp"),
        discover.clone(),
        None,
        &discover_headers,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(refusal["error"]["code"], -32022);
    assert_eq!(
        refusal["error"]["data"]["supported"],
        json!(["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
    );

    let secure = Running::start(service.mcp_router(true, ProtocolMode::Auto)).await;
    let (status, refusal) = send_with_headers(
        &client,
        secure.url("/mcp/"),
        discover,
        None,
        &discover_headers,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        refusal["detail"],
        "Authentication required for MCP endpoints"
    );
}
