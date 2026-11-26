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
    gateway::{GatewayService, Pagination},
    jwt::{JwtConfig, JwtVerifier},
    upstream::{EgressPolicy, UpstreamClient},
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
    let mut request = client
        .post(url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(payload.to_string());
    if let Some(credential) = credential {
        request = request.bearer_auth(credential);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let body = response.bytes().await.unwrap();
    let parsed = serde_json::from_slice(&body).unwrap_or_else(|error| {
        panic!("HTTP {status}: {error}: {}", String::from_utf8_lossy(&body))
    });
    (status, parsed)
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
        ),
        Pagination::new(1, 900, None),
    ));
    let gateway = Running::start(
        service
            .registration_router()
            .merge(service.mcp_router(false)),
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
        send(&client, virtual_url, call, Some(&member)).await,
        (StatusCode::OK, serde_json::from_str::<Value>(CALL).unwrap())
    );
    assert_eq!(stats.calls.load(Ordering::Relaxed), 2);
}
