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
    mcp::{HttpOptions, ProtocolMode, SessionSettings},
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

fn authorizer(database: Database) -> Arc<Authorizer> {
    Arc::new(Authorizer::new(
        database,
        Some(
            JwtVerifier::new(JwtConfig {
                key: KEY,
                ..JwtConfig::default()
            })
            .unwrap(),
        ),
        true,
    ))
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
    let authorizer = authorizer(database.clone());
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

#[tokio::test]
async fn legacy_session_lifecycle_binds_owner_and_virtual_server() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!();
    };
    sqlx::query(
        "INSERT INTO servers (id, name, visibility) VALUES ('fixture', 'Fixture', 'public')",
    )
    .execute(pool)
    .await
    .unwrap();
    let service = Arc::new(GatewayService::new(
        database.clone(),
        authorizer(database),
        UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(5)),
        Pagination::new(100, 900, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(service.mcp_router_with_sessions(
        true,
        ProtocolMode::Auto,
        Some(SessionSettings::default()),
    ))
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let owner = token("member", json!(["alpha"]), json!({}));
    let renewed = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let post = |path, credential: Option<&str>, session: Option<&str>, body: Value| {
        let mut request = client
            .post(gateway.url(path))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header("mcp-protocol-version", PROTOCOL)
            .body(body.to_string());
        if let Some(credential) = credential {
            request = request.bearer_auth(credential);
        }
        if let Some(session) = session {
            request = request.header("mcp-session-id", session);
        }
        request
    };
    let response = post(
        "/mcp/",
        Some(&owner),
        None,
        json!({
            "jsonrpc":"2.0", "id":1, "method":"initialize",
            "params":{"protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}
        }),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(uuid::Uuid::parse_str(&session).is_ok());
    let notification = post(
        "/mcp/",
        Some(&owner),
        Some(&session),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(notification.status(), StatusCode::ACCEPTED);
    assert!(notification.bytes().await.unwrap().is_empty());

    let ping = |path, credential, session| {
        post(
            path,
            credential,
            session,
            json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
        )
    };
    let owner_reply = ping("/mcp", Some(&renewed), Some(&session))
        .send()
        .await
        .unwrap();
    assert_eq!(owner_reply.status(), StatusCode::OK);
    assert_eq!(owner_reply.headers()["mcp-session-id"], session);
    assert_eq!(
        serde_json::from_slice::<Value>(&owner_reply.bytes().await.unwrap()).unwrap(),
        json!({"jsonrpc":"2.0","id":2,"result":{}})
    );

    for (path, credential, session, status) in [
        (
            "/mcp/",
            Some(&outsider),
            Some(&session),
            StatusCode::FORBIDDEN,
        ),
        (
            "/servers/fixture/mcp/",
            Some(&renewed),
            Some(&session),
            StatusCode::FORBIDDEN,
        ),
        ("/mcp/", None, Some(&session), StatusCode::UNAUTHORIZED),
        ("/mcp/", Some(&renewed), None, StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(
            ping(
                path,
                credential.map(String::as_str),
                session.map(String::as_str)
            )
            .send()
            .await
            .unwrap()
            .status(),
            status,
        );
    }

    let delete = |credential| {
        client
            .delete(gateway.url("/mcp/"))
            .bearer_auth(credential)
            .header("mcp-session-id", &session)
    };
    assert_eq!(
        delete(&outsider).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let get = |credential, path, accept| {
        client
            .get(gateway.url(path))
            .bearer_auth(credential)
            .header(header::ACCEPT, accept)
            .header("mcp-session-id", &session)
    };
    let missing = client
        .get(gateway.url("/mcp/"))
        .bearer_auth(&owner)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(missing.headers()[header::ALLOW], "POST, DELETE");
    for (credential, path, accept, status) in [
        (
            &owner,
            "/mcp/",
            "text/event-stream;q=0",
            StatusCode::NOT_ACCEPTABLE,
        ),
        (
            &outsider,
            "/mcp/",
            "text/event-stream",
            StatusCode::FORBIDDEN,
        ),
        (
            &owner,
            "/servers/fixture/mcp/",
            "text/event-stream",
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            get(credential, path, accept).send().await.unwrap().status(),
            status
        );
    }
    let mut stream = get(&renewed, "/mcp/", "Text/Event-Stream")
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), StatusCode::OK);
    assert_eq!(
        stream.headers()[header::CONTENT_TYPE],
        "text/event-stream; charset=utf-8"
    );
    let conflict = get(&owner, "/mcp", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(conflict.headers()[header::RETRY_AFTER], "1");

    let response = delete(&renewed).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&response.bytes().await.unwrap()).unwrap(),
        json!({"jsonrpc":"2.0","result":{}})
    );
    assert_eq!(
        ping("/mcp/", Some(&renewed), Some(&session))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
    );
    assert_eq!(
        delete(&owner).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    assert!(stream.chunk().await.unwrap().is_none());
    assert_eq!(
        get(&owner, "/mcp/", "text/event-stream")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn legacy_cancellation_targets_the_originating_session_and_upstream_request() {
    check_legacy_cancellation(true).await;
}

#[tokio::test]
async fn legacy_sse_post_opens_before_tool_completion_and_delivers_cancellation() {
    check_legacy_cancellation(false).await;
}

async fn check_legacy_cancellation(json_response: bool) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
    let upstream = Running::start(
        Router::new().route(
            "/mcp",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                let events = events.clone();
                async move {
                    let method = body["method"].as_str().unwrap();
                    let id = &body["id"];
                    if method != "initialize" {
                        assert_eq!(headers["mcp-session-id"], "upstream-session");
                    }
                    let result = match method {
                        "initialize" => {
                            return (
                                [("mcp-session-id", "upstream-session")],
                                Json(json!({
                                    "jsonrpc":"2.0", "id":id, "result":{
                                        "protocolVersion":PROTOCOL, "capabilities":{"tools":{}},
                                        "serverInfo":{"name":"fixture","version":"1"}
                                    }
                                })),
                            )
                                .into_response();
                        }
                        "notifications/initialized" => return StatusCode::ACCEPTED.into_response(),
                        "tools/list" => {
                            json!({"tools":[{"name":"hold","inputSchema":{"type":"object"}}]})
                        }
                        "tools/call" => {
                            events.send(("call", id.clone())).unwrap();
                            std::future::pending::<Value>().await
                        }
                        "notifications/cancelled" => {
                            events
                                .send(("cancel", body["params"]["requestId"].clone()))
                                .unwrap();
                            return StatusCode::ACCEPTED.into_response();
                        }
                        _ => panic!("unexpected upstream method {method}"),
                    };
                    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
                }
            })
            .delete(|| async { StatusCode::OK }),
        ),
    )
    .await;
    let database = database().await;
    let service = Arc::new(GatewayService::new(
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
    ));
    let gateway = Running::start(service.registration_router().merge(
        service.mcp_router_with_options(
            true,
            ProtocolMode::Legacy,
            HttpOptions {
                json_response,
                sessions: Some(SessionSettings::default()),
            },
        ),
    ))
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let (status, body) = send(
        &client,
        gateway.url("/gateways"),
        json!({"name":"cancel-fixture","url":upstream.url("/mcp"),"transport":"STREAMABLEHTTP","visibility":"public"}),
        Some(&admin),
    ).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let owner = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let request = |credential: &str, body: Value| {
        client
            .post(gateway.url("/mcp/"))
            .bearer_auth(credential)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
    };
    let mut sessions = Vec::new();
    for id in [1, 2] {
        let response = request(&owner, json!({
            "jsonrpc":"2.0", "id":id, "method":"initialize",
            "params":{"protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}
        })).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        if !json_response {
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "text/event-stream"
            );
        }
        sessions.push(response.headers()["mcp-session-id"].clone());
    }
    let mut call = tokio::spawn(
        request(
            &owner,
            json!({
                "jsonrpc":"2.0", "id":"in-flight", "method":"tools/call",
                "params":{"name":"cancel-fixture-hold","arguments":{}}
            }),
        )
        .header("mcp-session-id", sessions[0].clone())
        .send(),
    );
    let ("call", upstream_id) = tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("upstream tool call must start before cancellation");
    };
    assert!(upstream_id.is_number());
    let stream = if json_response {
        None
    } else {
        let response = tokio::time::timeout(Duration::from_secs(1), &mut call)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        assert_eq!(response.headers()["mcp-session-id"], sessions[0]);
        Some(response)
    };

    for (credential, session, expected) in [
        (&outsider, &sessions[0], StatusCode::FORBIDDEN),
        (&owner, &sessions[1], StatusCode::ACCEPTED),
        (&owner, &sessions[0], StatusCode::ACCEPTED),
    ] {
        let notification = request(credential, json!({
            "jsonrpc":"2.0", "method":"notifications/cancelled", "params":{"requestId":"in-flight"}
        })).header("mcp-session-id", session.clone()).send().await.unwrap();
        assert_eq!(notification.status(), expected);
        if session == sessions[1] || credential == &outsider {
            assert!(received.try_recv().is_err());
        }
    }
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), received.recv())
            .await
            .unwrap()
            .unwrap(),
        ("cancel", upstream_id)
    );
    let cancelled = match stream {
        Some(stream) => stream,
        None => call.await.unwrap().unwrap(),
    };
    assert_eq!(cancelled.status(), StatusCode::OK);
    let body = cancelled.text().await.unwrap();
    let data = if json_response {
        body.as_str()
    } else {
        assert!(body.lines().any(|line| line == "event: message"));
        body.lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap()
    };
    assert_eq!(
        serde_json::from_str::<Value>(data).unwrap(),
        json!({"jsonrpc":"2.0","id":"in-flight","error":{"code":-32800,"message":"Request cancelled"}})
    );
}

async fn next_sse_message(
    response: &mut reqwest::Response,
    buffered: &mut Vec<u8>,
) -> (Option<String>, Value) {
    let mut id = None;
    loop {
        while let Some(end) = buffered.iter().position(|&byte| byte == b'\n') {
            let line: Vec<u8> = buffered.drain(..=end).collect();
            if line.trim_ascii().is_empty() {
                id = None;
            }
            if let Some(value) = line.strip_prefix(b"id:") {
                id = Some(std::str::from_utf8(value.trim_ascii()).unwrap().to_owned());
            }
            if let Some(data) = line.strip_prefix(b"data:").map(<[u8]>::trim_ascii)
                && !data.is_empty()
            {
                return (id, serde_json::from_slice(data).unwrap());
            }
        }
        let bytes = response.chunk().await.unwrap().expect("next SSE frame");
        buffered.extend_from_slice(&bytes);
    }
}

async fn fixture_progress(
    State(release): State<Arc<tokio::sync::Semaphore>>,
    Json(body): Json<Value>,
) -> Response {
    let id = &body["id"];
    let result = match body["method"].as_str().unwrap() {
        "initialize" => json!({
            "protocolVersion":PROTOCOL, "capabilities":{"tools":{}},
            "serverInfo":{"name":"progress fixture","version":"1"}
        }),
        "notifications/initialized" => return StatusCode::ACCEPTED.into_response(),
        "tools/list" => json!({"tools":[{"name":"hold","inputSchema":{"type":"object"}}]}),
        "tools/call" => {
            let token = body["params"]["_meta"]["progressToken"].clone();
            let waiting = body["params"]["arguments"]["wait"] == true;
            if waiting {
                assert!(
                    token.is_number(),
                    "outbound request is missing a progress token"
                );
            }
            let frames = [json!("foreign"), token].into_iter().map(|token| {
                Ok::<_, std::convert::Infallible>(
                    axum::response::sse::Event::default().json_data(json!({
                        "jsonrpc":"2.0", "method":"notifications/progress",
                        "params":{"progressToken":token,"progress":1,"total":2,"message":"working"}
                    })).unwrap()
                )
            });
            let final_result = json!({
                "jsonrpc":"2.0","id":id,
                "result":{"content":[{"type":"text","text":"done"}],"isError":false}
            });
            use futures_util::{StreamExt, stream};
            let events = stream::iter(frames).chain(stream::once(async move {
                if waiting {
                    release.acquire().await.unwrap().forget();
                }
                Ok(axum::response::sse::Event::default()
                    .json_data(final_result)
                    .unwrap())
            }));
            return axum::response::Sse::new(events).into_response();
        }
        unexpected => panic!("unexpected upstream method {unexpected}"),
    };
    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
}

#[tokio::test]
async fn tool_progress_streams_before_completion_on_legacy_and_modern_mcp() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let upstream = Running::start(
        Router::new()
            .route("/mcp", post(fixture_progress))
            .with_state(release.clone()),
    )
    .await;
    let database = database().await;
    let service = Arc::new(GatewayService::new(
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
    ));
    let legacy = Running::start(service.registration_router().merge(
        service.mcp_router_with_options(
            false,
            ProtocolMode::Legacy,
            HttpOptions {
                json_response: false,
                sessions: Some(SessionSettings::default()),
            },
        ),
    ))
    .await;
    let modern = Running::start(service.mcp_router(false, ProtocolMode::Auto)).await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let (status, registration) = send(&client, legacy.url("/gateways"), json!({
         "name":"progress-fixture", "url":upstream.url("/mcp"), "transport":"STREAMABLEHTTP", "visibility":"public"
    }), Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{registration}");

    let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}
    }});
    let legacy_post = |value: Value| {
        client
            .post(legacy.url("/mcp/"))
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, "application/json")
            .header("mcp-protocol-version", PROTOCOL)
            .body(value.to_string())
    };
    let response = legacy_post(initialize).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()["mcp-session-id"].clone();
    assert_eq!(
        legacy_post(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .header("mcp-session-id", &session)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED,
    );

    let modern_post = |accept, wait| {
        let mut request = modern_request(
            "tools/call",
            2,
            json!({"name":"progress-fixture-hold","arguments":{"wait":wait}}),
        );
        request["params"]["_meta"]["progressToken"] = json!("client-token");
        client
            .post(modern.url("/mcp/"))
            .header(header::ACCEPT, accept)
            .header(header::CONTENT_TYPE, "application/json")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "progress-fixture-hold")
            .body(request.to_string())
    };
    let requests = [
        (Some(session.clone()), legacy_post(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"progress-fixture-hold","arguments":{"wait":true},"_meta":{"progressToken":"client-token"}
        }})).header("mcp-session-id", session)),
        (None, modern_post("application/json, text/event-stream", true)),
    ];
    for (resumable, request) in requests {
        let mut response = request.send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream")
        );
        let mut buffered = Vec::new();
        let (cursor, progress) = next_sse_message(&mut response, &mut buffered).await;
        assert_eq!(
            progress,
            json!({
                "jsonrpc":"2.0","method":"notifications/progress",
                "params":{"progressToken":"client-token","progress":1.0,"total":2.0,"message":"working"}
            })
        );
        if let Some(session) = resumable {
            let cursor = cursor.expect("stateful progress has a replay cursor");
            let reconnect = || {
                client
                    .get(legacy.url("/mcp/"))
                    .header(header::ACCEPT, "text/event-stream")
                    .header("mcp-session-id", &session)
                    .header("last-event-id", &cursor)
            };
            let still_open = reconnect().send().await.unwrap();
            assert_eq!(still_open.status(), StatusCode::CONFLICT);
            assert_eq!(still_open.headers()[header::RETRY_AFTER], "1");
            drop(response);
            response = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let reconnect = reconnect().send().await.unwrap();
                    if reconnect.status() != StatusCode::CONFLICT {
                        break reconnect;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            buffered.clear();
        }
        release.add_permits(1);
        let (_, result) = next_sse_message(&mut response, &mut buffered).await;
        assert_eq!(result["id"], 2);
        assert_eq!(result["result"]["content"][0]["text"], "done");
    }

    let response = modern_post("application/json", false).send().await.unwrap();
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["result"]["content"][0]["text"], "done");
}

#[tokio::test]
async fn stream_resumption_never_reads_another_session_or_authorization_scope() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = database().await;
    let service = Arc::new(GatewayService::new(
        database.clone(),
        authorizer(database.clone()),
        UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(5)),
        Pagination::new(100, 900, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(service.mcp_router_with_options(
        true,
        ProtocolMode::Legacy,
        HttpOptions {
            json_response: false,
            sessions: Some(SessionSettings::default()),
        },
    ))
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let owner = token("member", json!(["alpha"]), json!({}));
    let renewal = token("member", json!(["alpha"]), json!({}));
    let limited = token(
        "member",
        json!(["alpha"]),
        json!({"permissions": ["servers.use"]}),
    );
    let other = token("outsider", json!(["beta"]), json!({}));
    let post = |body: Value| {
        client
            .post(gateway.url("/mcp/"))
            .bearer_auth(&owner)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, "application/json")
            .header("mcp-protocol-version", PROTOCOL)
            .body(body.to_string())
    };
    let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}
    }});
    let mut sessions = Vec::new();
    for _ in 0..2 {
        let response = post(initialize.clone()).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        sessions.push(response.headers()["mcp-session-id"].clone());
        assert!(
            response
                .text()
                .await
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .starts_with("id:")
        );
    }

    let mut cursors = Vec::new();
    let calls = [
        json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"unknown"}}),
    ];
    for call in calls {
        let response = post(call)
            .header("mcp-session-id", &sessions[0])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.unwrap();
        let (priming, terminal) = body.split_once("\n\n").unwrap();
        assert!(priming.lines().any(|line| line.trim_end() == "data:"));
        let cursor = priming
            .lines()
            .find_map(|line| line.strip_prefix("id: "))
            .unwrap()
            .to_owned();
        assert!(terminal.lines().any(|line| line.starts_with("id: ")));
        cursors.push(cursor);
    }

    let get = |credential, session: &axum::http::HeaderValue, cursor: &str| {
        client
            .get(gateway.url("/mcp/"))
            .bearer_auth(credential)
            .header(header::ACCEPT, "text/event-stream")
            .header("mcp-session-id", session.clone())
            .header("last-event-id", cursor)
    };
    for credential in [&limited, &other] {
        let response = get(credential, &sessions[0], &cursors[0])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let mut foreign = get(&renewal, &sessions[1], &cursors[0])
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::OK);
    let response = get(&renewal, &sessions[0], &cursors[0])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    let replies: Vec<Value> = body
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|data| serde_json::from_str(data).unwrap())
        .collect();
    assert_eq!(replies, [json!({"jsonrpc":"2.0","id":2,"result":{}})]);
    assert!(
        tokio::time::timeout(Duration::from_millis(75), foreign.chunk())
            .await
            .is_err()
    );
    let Database::Sqlite(pool) = database else {
        unreachable!()
    };
    sqlx::query(
        "UPDATE roles SET permissions = '[\"servers.use\",\"tools.read\"]' WHERE id = 'developer'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let response = get(&renewal, &sessions[0], &cursors[1])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
