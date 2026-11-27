// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response, Sse, sse::Event},
    routing::{get, post},
};
use context_forge_rs::{
    access::Authorizer,
    config::{RedisSettings, Settings},
    database::Database,
    gateway::{CatalogRefresh, GatewayService, Pagination},
    jwt::{JwtConfig, JwtVerifier},
    mcp::{
        HttpOptions, ListenSettings, ProtocolMode, RedisSessionDirectory, SessionSettings,
        SseBackend, SseSettings, WebSocketSettings,
    },
    upstream::{ConnectMode, EgressPolicy, UpstreamClient},
};
use futures_util::{StreamExt, stream};
use jiff::Timestamp;
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::Client;
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const KEY: &[u8] = &[0x36; 32];
const PROTOCOL: &str = "2025-11-25";
const LIST: &str = include_str!("../../replay/mcp-legacy/rust/app-cases/http/03-tools-list.body");
const CALL: &str = include_str!("../../replay/mcp-legacy/rust/app-cases/http/04-tools-call.body");

type SseFixtureSessions = Arc<Mutex<HashMap<String, tokio::sync::mpsc::Sender<Value>>>>;

async fn open_upstream_sse(State(sessions): State<SseFixtureSessions>) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    let (sender, receiver) = tokio::sync::mpsc::channel(16);
    sessions.lock().unwrap().insert(id.clone(), sender);
    let endpoint = stream::iter([Ok::<_, Infallible>(
        Event::default()
            .event("endpoint")
            .data(format!("/message/{id}")),
    )]);
    let events = stream::unfold(receiver, |mut receiver| async move {
        let message: Value = receiver.recv().await?;
        Some((
            Ok(Event::default().event("message").data(message.to_string())),
            receiver,
        ))
    });
    Sse::new(endpoint.chain(events)).into_response()
}

async fn message_upstream_sse(
    State(sessions): State<SseFixtureSessions>,
    Path(session): Path<String>,
    Json(request): Json<Value>,
) -> StatusCode {
    let method = request["method"].as_str().unwrap();
    if method == "notifications/initialized" {
        return StatusCode::ACCEPTED;
    }
    let result = match method {
        "initialize" => json!({"protocolVersion":PROTOCOL,"capabilities":{"tools":{}},
            "serverInfo":{"name":"SSE fixture","version":"1"}}),
        "tools/list" => json!({"tools":[{"name":"echo","inputSchema":{
            "type":"object","properties":{"message":{"type":"string"}},"required":["message"]
        }}]}),
        "tools/call" => {
            json!({"content":[{"type":"text","text":request["params"]["arguments"]["message"]}]})
        }
        _ => panic!("unexpected SSE method {method}"),
    };
    let sender = sessions.lock().unwrap().get(&session).unwrap().clone();
    sender
        .send(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
        .await
        .unwrap();
    StatusCode::ACCEPTED
}

#[tokio::test]
async fn registration_invokes_sse_upstream_and_rejects_cross_origin_message_endpoint() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let upstream = Running::start(
        Router::new()
            .route("/sse", get(open_upstream_sse))
            .route("/message/{session}", post(message_upstream_sse))
            .route(
                "/wrong-origin",
                get(|| async {
                    Sse::new(stream::iter([Ok::<_, Infallible>(
                        Event::default()
                            .event("endpoint")
                            .data("http://127.0.0.1:1/message"),
                    )]))
                }),
            )
            .with_state(SseFixtureSessions::default()),
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
        ),
        Pagination::new(100, 900, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(
        service
            .registration_router()
            .merge(service.mcp_router(false, ProtocolMode::Auto)),
    )
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let register = async |name: &str, path: &str| {
        send(
            &client,
            gateway.url("/gateways"),
            json!({"name":name,"url":upstream.url(path),"visibility":"public"}),
            Some(&admin),
        )
        .await
    };
    let (status, denied) = register("wrong", "/wrong-origin").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(denied["message"], "Gateway URL is invalid or disallowed");
    let (status, registration) = register("legacy", "/sse").await;
    assert_eq!(status, StatusCode::OK, "{registration}");
    assert_eq!(registration["transport"], "SSE");
    let (status, reply) = send(
        &client,
        gateway.url("/mcp/"),
        json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"legacy-echo","arguments":{"message":"echo over SSE"}}
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["result"]["content"][0]["text"], "echo over SSE");
}

#[tokio::test]
async fn registration_encrypts_bearer_credentials_and_uses_them_for_mcp_requests() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let upstream = Running::start(Router::new().route(
        "/mcp",
        post(async |headers: HeaderMap, Json(message): Json<Value>| {
            assert_eq!(headers[header::AUTHORIZATION], "Bearer upstream-fixture");
            if message["method"] == "notifications/initialized" {
                return StatusCode::ACCEPTED.into_response();
            }
            let result = match message["method"].as_str().unwrap() {
                "initialize" => {
                    json!({"protocolVersion":PROTOCOL,"capabilities":{"tools":{},"resources":{}},
                    "serverInfo":{"name":"Authenticated fixture","version":"1"}})
                }
                "tools/list" => json!({"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}),
                "tools/call" => {
                    assert!(!headers.contains_key("x-forwarded-user-id"));
                    assert_eq!(message["params"]["_meta"]["user"], json!({
                        "id":"admin@example.test", "email":"admin@example.test", "auth_method":"jwt", "is_admin":true
                    }));
                    let name = message["params"]["name"].as_str().unwrap();
                    assert!(matches!(name, "echo" | "fresh"));
                    json!({"content":[{"type":"text","text":format!("Authorized tool: {name}")}]})
                }
                "resources/list" => {
                    json!({"resources":[{"name":"note","uri":"fixture://auth/note"}]})
                }
                "resources/templates/list" => json!({"resourceTemplates":[]}),
                "resources/read" => {
                    json!({"contents":[{"uri":"fixture://auth/note","text":"Authorized resource"}]})
                }
                method => panic!("unexpected upstream request {method}"),
            };
            Json(json!({"jsonrpc":"2.0","id":message["id"],"result":result})).into_response()
        }),
    ))
    .await;
    let database = database().await;
    let service = Arc::new(
        GatewayService::new(
            database.clone(),
            authorizer(database.clone()),
            UpstreamClient::new(
                EgressPolicy {
                    allow_localhost: true,
                    ..EgressPolicy::default()
                },
                Duration::from_secs(4),
            )
            .with_connect_mode(ConnectMode::Legacy),
            Pagination::new(100, 900, None),
            CatalogRefresh::default(),
        )
        .with_credential_secret(Some("synthetic encryption key for the gateway test"))
        .with_direct_proxy(Some(Duration::from_secs(4))),
    );
    let app = Running::start(
        service
            .registration_router()
            .merge(service.mcp_router(false, ProtocolMode::Legacy)),
    )
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({"is_admin":true}));
    let mut registration = json!({"name":"protected","url":upstream.url("/mcp"),"transport":"STREAMABLEHTTP",
        "gatewayMode":"direct_proxy","authType":"bearer","authToken":"upstream-fixture","identityPropagation":{"enabled":true,"mode":"meta"}});
    let (status, response) = send(
        &client,
        app.url("/gateways"),
        registration.clone(),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["authType"], "bearer");
    assert_eq!(response["authValue"], "*****");
    assert_eq!(response["authToken"], "*****");
    assert_eq!(response["gatewayMode"], "direct_proxy");
    let gateway_id = response["id"].as_str().unwrap();
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    let encrypted = sqlx::query_scalar::<_, String>(
        "SELECT CAST(auth_value AS TEXT) FROM gateways WHERE name = 'protected'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(
        serde_json::from_str::<Value>(&encrypted)
            .unwrap()
            .is_string()
    );
    assert!(!encrypted.contains("upstream-fixture"));
    registration["name"] = "duplicate".into();
    let (status, _) = send(&client, app.url("/gateways"), registration, Some(&admin)).await;
    assert_eq!(status, StatusCode::CONFLICT);

    for (method, params, text) in [
        (
            "tools/call",
            json!({"name":"protected-echo","arguments":{},"_meta":{"user":{"id":"caller-supplied"}}}),
            "Authorized tool: echo",
        ),
        (
            "resources/read",
            json!({"uri":"fixture://auth/note"}),
            "Authorized resource",
        ),
    ] {
        let (status, result) = send(
            &client,
            app.url("/mcp"),
            json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
            Some(&admin),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(result["result"].to_string().contains(text), "{result}");
    }
    let reply = client.post(app.url("/mcp"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .header("x-context-forge-gateway-id", gateway_id)
        .bearer_auth(&admin)
        .body(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fresh","arguments":{}}}).to_string())
        .send().await.unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    let reply: Value = serde_json::from_slice(&reply.bytes().await.unwrap()).unwrap();
    assert_eq!(
        reply["result"]["content"][0]["text"],
        "Authorized tool: fresh"
    );
}

#[tokio::test]
async fn websocket_relay_requires_header_authentication_and_returns_rpc_errors() {
    use futures_util::SinkExt;
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{
            Error as WebSocketError, Message, client::IntoClientRequest,
            protocol::frame::coding::CloseCode,
        },
    };

    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = database().await;
    let service = Arc::new(GatewayService::new(
        database.clone(),
        authorizer(database),
        UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(5)),
        Pagination::new(100, 900, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(service.websocket_router(WebSocketSettings {
        enabled: true,
        require_auth: true,
        shutdown: CancellationToken::new(),
    }))
    .await;
    let url = format!("ws://{}/ws", gateway.address);
    let admin = token("admin", Value::Null, json!({}));
    for url in [url.clone(), format!("{url}?token={admin}")] {
        let Err(WebSocketError::Http(response)) = connect_async(url).await else {
            panic!("expected WebSocket handshake to be denied");
        };
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let mut request = url.into_client_request().unwrap();
    request.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {admin}").parse().unwrap(),
    );
    let (mut socket, response) = connect_async(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    socket.send(Message::Text("{".into())).await.unwrap();
    let reply: Value =
        serde_json::from_str(&socket.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(
        reply,
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})
    );
    for (method, expected) in [
        ("ping", json!({"jsonrpc":"2.0","id":1,"result":{}})),
        (
            "other/method",
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found: other/method","data":{}}}),
        ),
    ] {
        socket
            .send(Message::Text(
                json!({"jsonrpc":"2.0","id":1,"method":method})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let reply: Value =
            serde_json::from_str(&socket.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap();
        assert_eq!(reply, expected);
    }
    socket
        .send(Message::Binary(vec![1, 2].into()))
        .await
        .unwrap();
    let Some(Ok(Message::Close(Some(frame)))) = socket.next().await else {
        panic!("expected a close frame for binary data");
    };
    assert_eq!(frame.code, CloseCode::Error);
}

#[tokio::test]
async fn legacy_sse_routes_messages_to_the_bound_virtual_server_and_owner() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::query("INSERT INTO servers (id, name, visibility) VALUES ('v', 'Virtual', 'public')")
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
    let gateway = Running::start(service.legacy_sse_router(
        true,
        SseSettings {
            keepalive: None,
            ..SseSettings::default()
        },
    ))
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let owner = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let url = gateway.url("/servers/v/sse");
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut stream = client.get(url).bearer_auth(&owner).send().await.unwrap();
    assert_eq!(stream.status(), StatusCode::OK);
    assert_eq!(stream.headers()[header::CONTENT_TYPE], "text/event-stream");
    let mut endpoint_frame = Vec::new();
    while !endpoint_frame.ends_with(b"\r\n\r\n") {
        endpoint_frame.extend_from_slice(&stream.chunk().await.unwrap().expect("endpoint frame"));
    }
    let endpoint = std::str::from_utf8(&endpoint_frame)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap()
        .to_owned();
    assert!(endpoint.starts_with(&gateway.url("/servers/v/message?session_id=")));
    assert!(
        std::str::from_utf8(&endpoint_frame)
            .unwrap()
            .contains("retry: 5000")
    );

    let ping = json!({"jsonrpc":"2.0","id":"ping","method":"ping"});
    let (status, denied) = send(&client, endpoint.clone(), ping.clone(), Some(&outsider)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(denied["detail"], "Session access denied");
    let wrong_path = endpoint.replace("/servers/v/message", "/message");
    let (status, _) = send(&client, wrong_path, ping.clone(), Some(&owner)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, reply) = send(&client, endpoint.clone(), json!({
        "jsonrpc":"2.0","id":"init","method":"initialize",
        "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}
    }), Some(&owner)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(reply, json!({"status":"success"}));

    let mut buffered = Vec::new();
    let (_, init) = next_sse_message(&mut stream, &mut buffered).await;
    assert_eq!(init["id"], "init");
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(
        init["result"]["capabilities"]["resources"]["subscribe"],
        true
    );
    for method in [
        "notifications/initialized",
        "notifications/tools/list_changed",
        "notifications/resources/list_changed",
        "notifications/prompts/list_changed",
    ] {
        let (_, reply) = next_sse_message(&mut stream, &mut buffered).await;
        assert_eq!(reply["method"], method);
    }
    let (status, _) = send(&client, endpoint.clone(), ping.clone(), Some(&owner)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (_, reply) = next_sse_message(&mut stream, &mut buffered).await;
    assert_eq!(reply, json!({"jsonrpc":"2.0","id":"ping","result":{}}));
    drop(stream);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (status, _) = send(&client, endpoint.clone(), ping.clone(), Some(&owner)).await;
            if status == StatusCode::NOT_FOUND {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the message endpoint closes with its stream");
}

#[tokio::test]
async fn legacy_sse_workers_share_database_sessions() {
    verify_shared_legacy_sse(|| SseBackend::Database).await;
}

#[tokio::test]
#[ignore = "requires a disposable Redis or Valkey database in REDIS_URL"]
async fn legacy_sse_workers_share_redis_sessions() {
    let redis = RedisSettings {
        url: std::env::var("REDIS_URL").unwrap(),
        connect_timeout: Duration::from_secs(2),
        response_timeout: Duration::from_secs(2),
    };
    verify_shared_legacy_sse(|| {
        SseBackend::Redis(Arc::new(RedisSessionDirectory::new(&redis).unwrap()))
    })
    .await;
}

async fn verify_shared_legacy_sse(backend: impl Fn() -> SseBackend) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = database().await;
    database.migrate_legacy_sse().await.unwrap();
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::query("INSERT INTO servers (id, name, visibility) VALUES ('v', 'Virtual', 'public')")
        .execute(pool)
        .await
        .unwrap();
    let worker = || {
        let service = Arc::new(GatewayService::new(
            database.clone(),
            authorizer(database.clone()),
            UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(5)),
            Pagination::new(100, 900, None),
            CatalogRefresh::default(),
        ));
        service.legacy_sse_router(
            true,
            SseSettings {
                backend: backend(),
                keepalive: None,
                ..SseSettings::default()
            },
        )
    };
    let first = Running::start(worker()).await;
    let second = Running::start(worker()).await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let owner = token("member", json!(["alpha"]), json!({}));
    let outsider = token("outsider", json!(["beta"]), json!({}));
    let mut stream = client
        .get(first.url("/servers/v/sse"))
        .bearer_auth(&owner)
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), StatusCode::OK);
    let mut frame = Vec::new();
    while !frame.ends_with(b"\r\n\r\n") {
        frame.extend_from_slice(&stream.chunk().await.unwrap().expect("endpoint frame"));
    }
    let endpoint = std::str::from_utf8(&frame)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    let remote = endpoint.replacen(&first.url(""), &second.url(""), 1);
    let ping = json!({"jsonrpc":"2.0","id":"ping","method":"ping"});
    let (status, _) = send(&client, remote.clone(), ping.clone(), Some(&outsider)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let wrong = remote.replace("/servers/v/message", "/message");
    let (status, _) = send(&client, wrong, ping.clone(), Some(&owner)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = send(&client, remote.clone(), ping.clone(), Some(&owner)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body, json!({"status":"success"}));
    let (_, reply) = next_sse_message(&mut stream, &mut Vec::new()).await;
    assert_eq!(reply, json!({"jsonrpc":"2.0","id":"ping","result":{}}));
    drop(stream);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (status, _) = send(&client, remote.clone(), ping.clone(), Some(&owner)).await;
            if status == StatusCode::NOT_FOUND {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the other worker sees the session close");
}

const WATCHED_RESOURCE: &str = "fixture://notes/watched";

#[derive(Default)]
struct ResourceStreamFixture {
    opened: AtomicUsize,
    release: CancellationToken,
    closed: CancellationToken,
}

async fn modern_resource_fixture(
    State(fixture): State<Arc<ResourceStreamFixture>>,
    Json(request): Json<Value>,
) -> Response {
    let id = &request["id"];
    let mut result = match request["method"].as_str().unwrap() {
        "server/discover" => json!({
            "supportedVersions":["2026-07-28"],
            "capabilities":{"resources":{"subscribe":true}}
        }),
        "tools/list" => json!({"tools":[]}),
        "resources/list" => json!({"resources":[{"name":"watched","uri":WATCHED_RESOURCE}]}),
        "resources/templates/list" => json!({"resourceTemplates":[]}),
        "subscriptions/listen" => {
            let notifications = &request["params"]["notifications"];
            assert_eq!(
                notifications["resourceSubscriptions"],
                json!([WATCHED_RESOURCE])
            );
            fixture.opened.fetch_add(1, Ordering::SeqCst);
            let disconnected = fixture.closed.clone().drop_guard();
            let frame = |method: &str, mut params: Value| {
                params["_meta"] = json!({"io.modelcontextprotocol/subscriptionId":id});
                Ok::<Event, Infallible>(
                    Event::default().event("message").data(
                        json!({
                            "jsonrpc":"2.0","method":method,"params":params
                        })
                        .to_string(),
                    ),
                )
            };
            let unrequested = frame(
                "notifications/resources/updated",
                json!({"uri":"fixture://notes/unrequested"}),
            );
            let frames = stream::once(std::future::ready(frame(
                "notifications/subscriptions/acknowledged",
                json!({"notifications":notifications}),
            )))
            .chain(stream::once(async move {
                fixture.release.cancelled().await;
                unrequested
            }))
            .chain(stream::once(std::future::ready(frame(
                "notifications/resources/updated",
                json!({"uri":WATCHED_RESOURCE}),
            ))))
            .chain(stream::pending())
            .map(move |event| {
                let _ = &disconnected;
                event
            });
            return Sse::new(frames).into_response();
        }
        method => panic!("unexpected upstream method {method}"),
    };
    result["resultType"] = json!("complete");
    result["ttlMs"] = json!(0);
    result["cacheScope"] = json!("private");
    result["_meta"] =
        json!({"io.modelcontextprotocol/serverInfo":{"name":"fixture","version":"1"}});
    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
}

#[tokio::test]
async fn modern_resource_subscriptions_share_scoped_upstream_watches() {
    const METHOD: &str = "subscriptions/listen";
    const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fixture = Arc::new(ResourceStreamFixture::default());
    let upstream = Running::start(
        Router::new()
            .route("/mcp", post(modern_resource_fixture))
            .with_state(fixture.clone()),
    )
    .await;
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::query("INSERT INTO servers (id, name, visibility) VALUES ('v', 'Virtual', 'public')")
        .execute(pool)
        .await
        .unwrap();
    let service = Arc::new(GatewayService::new(
        database.clone(),
        authorizer(database),
        UpstreamClient::new(
            EgressPolicy {
                allow_localhost: true,
                ..EgressPolicy::default()
            },
            Duration::from_secs(5),
        ),
        Pagination::new(100, 900, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(
        service
            .registration_router()
            .merge(service.mcp_router(false, ProtocolMode::Auto)),
    )
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let (status, registration) = send(&client, gateway.url("/gateways"), json!({
        "name":"resource-fixture","url":upstream.url("/mcp"),"visibility":"public","transport":"STREAMABLEHTTP"
    }), Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{registration}");
    let listen = |path: &str, id| {
        client.post(gateway.url(path))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", METHOD)
            .body(modern_request(METHOD, id, json!({"notifications":{
                "resourceSubscriptions":[WATCHED_RESOURCE,"fixture://absent",WATCHED_RESOURCE]
            }})).to_string())
    };
    let mut scoped = listen("/servers/v/mcp/", 30).send().await.unwrap();
    let (_, ack) = next_sse_message(&mut scoped, &mut Vec::new()).await;
    assert_eq!(ack["params"]["notifications"], json!({}));
    drop(scoped);

    let mut first = listen("/mcp/", 31).send().await.unwrap();
    let mut second = listen("/mcp/", 32).send().await.unwrap();
    let mut first_buffer = Vec::new();
    let mut second_buffer = Vec::new();
    for (response, buffered, id) in [
        (&mut first, &mut first_buffer, 31),
        (&mut second, &mut second_buffer, 32),
    ] {
        let (_, ack) = next_sse_message(response, buffered).await;
        assert_eq!(ack["params"]["_meta"][SUBSCRIPTION_ID], id);
        assert_eq!(
            ack["params"]["notifications"]["resourceSubscriptions"],
            json!([WATCHED_RESOURCE])
        );
    }
    fixture.release.cancel();
    for (response, buffered, id) in [
        (&mut first, &mut first_buffer, 31),
        (&mut second, &mut second_buffer, 32),
    ] {
        let (_, update) = next_sse_message(response, buffered).await;
        assert_eq!(update["method"], "notifications/resources/updated");
        assert_eq!(update["params"]["uri"], WATCHED_RESOURCE);
        assert_eq!(update["params"]["_meta"][SUBSCRIPTION_ID], id);
    }
    assert_eq!(fixture.opened.load(Ordering::SeqCst), 1);
    drop(first);
    assert!(!fixture.closed.is_cancelled());
    drop(second);
    tokio::time::timeout(Duration::from_secs(3), fixture.closed.cancelled())
        .await
        .expect("the upstream stream closes when the last subscriber leaves");
}

#[tokio::test]
async fn modern_catalog_subscription_streams_registration_and_tears_down() {
    const METHOD: &str = "subscriptions/listen";
    const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";
    let _ = rustls::crypto::ring::default_provider().install_default();
    let upstream = Running::start(Router::new().route("/mcp", post(catalog_fixture))).await;
    let database = database().await;
    let shutdown = tokio_util::sync::CancellationToken::new();
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
        .with_listen_settings(ListenSettings {
            max_anonymous: 1,
            shutdown: shutdown.clone(),
            ..ListenSettings::default()
        }),
    );
    let gateway = Running::start(
        service
            .registration_router()
            .merge(service.mcp_router(false, ProtocolMode::Auto)),
    )
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let listen = |accept: &str| {
        client.post(gateway.url("/mcp/"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, accept)
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", METHOD)
            .body(modern_request(METHOD, 31, json!({"notifications":{
                "toolsListChanged":true,"resourcesListChanged":true,"promptsListChanged":true,
                "resourceSubscriptions":["fixture://absent"],"unknownNotification":true
            }})).to_string())
    };
    assert_eq!(
        listen("application/json").send().await.unwrap().status(),
        StatusCode::NOT_ACCEPTABLE
    );
    let mut stream = listen("application/json, text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), StatusCode::OK);
    assert_eq!(stream.headers()[header::CONTENT_TYPE], "text/event-stream");
    let mut buffered = Vec::new();
    let (_, ack) = next_sse_message(&mut stream, &mut buffered).await;
    assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
    assert_eq!(ack["params"]["_meta"][SUBSCRIPTION_ID], 31);
    assert_eq!(
        ack["params"]["notifications"],
        json!({
            "toolsListChanged":true,"resourcesListChanged":true,"promptsListChanged":true
        })
    );

    let limited = listen("application/json, text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::OK);
    let reply: Value = serde_json::from_slice(&limited.bytes().await.unwrap()).unwrap();
    assert_eq!(
        reply["error"],
        json!({"code":-32603,"message":"Subscription limit reached"})
    );

    let admin = token("admin", Value::Null, json!({}));
    let (status, registration) = send(&client, gateway.url("/gateways"), json!({
        "name":"catalog","url":upstream.url("/mcp"),"visibility":"public","transport":"STREAMABLEHTTP"
    }), Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{registration}");
    for method in [
        "notifications/prompts/list_changed",
        "notifications/resources/list_changed",
        "notifications/tools/list_changed",
    ] {
        let (_, change) = next_sse_message(&mut stream, &mut buffered).await;
        assert_eq!(change["method"], method);
        assert_eq!(change["params"]["_meta"][SUBSCRIPTION_ID], 31);
    }

    shutdown.cancel();
    let (_, cancelled) = next_sse_message(&mut stream, &mut buffered).await;
    assert_eq!(cancelled["method"], "notifications/cancelled");
    assert_eq!(cancelled["params"]["requestId"], 31);
    assert_eq!(cancelled["params"]["_meta"][SUBSCRIPTION_ID], 31);
    let (_, completed) = next_sse_message(&mut stream, &mut buffered).await;
    assert_eq!(completed["id"], 31);
    assert_eq!(completed["result"]["resultType"], "complete");
    assert_eq!(completed["result"]["_meta"][SUBSCRIPTION_ID], 31);
    assert!(stream.chunk().await.unwrap().is_none());
}

#[tokio::test]
async fn legacy_logging_changes_the_process_filter_with_scoped_permission() {
    use tracing_subscriber::{filter::LevelFilter, reload};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = database().await;
    let (_layer, handle) = reload::Layer::new(LevelFilter::INFO);
    let service = Arc::new(
        GatewayService::new(
            database.clone(),
            authorizer(database),
            UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(5)),
            Pagination::new(100, 900, None),
            CatalogRefresh::default(),
        )
        .with_logging_filter(handle.clone()),
    );
    let gateway = Running::start(service.mcp_router(false, ProtocolMode::Auto)).await;
    let client = Client::builder().no_proxy().build().unwrap();
    let restricted = token("admin", Value::Null, json!({"permissions":["tools.read"]}));
    let rpc = async |level: &str, token: Option<&str>| {
        send(
            &client,
            gateway.url("/mcp/"),
            json!({"jsonrpc":"2.0","id":1,"method":"logging/setLevel","params":{"level":level}}),
            token,
        )
        .await
    };

    let (status, reply) = rpc("debug", Some(&restricted)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["error"], json!({"code":0,"message":"Access denied"}));
    assert_eq!(
        handle.with_current(|level| *level).unwrap(),
        LevelFilter::INFO
    );

    for (wire, expected) in [
        ("debug", LevelFilter::DEBUG),
        ("notice", LevelFilter::INFO),
        ("warning", LevelFilter::WARN),
        ("alert", LevelFilter::ERROR),
    ] {
        let (status, reply) = rpc(wire, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reply["result"], json!({}));
        assert_eq!(handle.with_current(|level| *level).unwrap(), expected);
    }
    let (status, reply) = rpc("DEBUG", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        reply["error"],
        json!({"code":-32602,"message":"Invalid request parameters","data":""})
    );
    assert_eq!(
        handle.with_current(|level| *level).unwrap(),
        LevelFilter::ERROR
    );

    let (_, reply) = send(
        &client,
        gateway.url("/mcp/"),
        json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{
            "protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}
        }}),
        None,
    )
    .await;
    assert_eq!(reply["result"]["capabilities"]["logging"], json!({}));

    let (status, reply) = send_with_headers(
        &client,
        gateway.url("/mcp/"),
        modern_request("logging/setLevel", 3, json!({"level":"debug"})),
        None,
        &[
            ("mcp-method", "logging/setLevel"),
            ("mcp-protocol-version", "2026-07-28"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        reply["error"],
        json!({"code":-32601,"message":"Method not found","data":"logging/setLevel"})
    );
    assert_eq!(
        handle.with_current(|level| *level).unwrap(),
        LevelFilter::ERROR
    );
}

async fn catalog_fixture(Json(request): Json<Value>) -> Response {
    let params = &request["params"];
    let result = match request["method"].as_str().unwrap() {
        "initialize" => json!({"protocolVersion":PROTOCOL,
            "capabilities":{"resources":{},"prompts":{},"completions":{}}, "serverInfo":{"name":"catalog fixture","version":"1"}
        }),
        "notifications/initialized" => return StatusCode::ACCEPTED.into_response(),
        "tools/list" => {
            return Json(json!({"jsonrpc":"2.0","id":request["id"],
            "error":{"code":-32601,"message":"Method not found"}}))
            .into_response();
        }
        "resources/list" if params["cursor"] == "next" => json!({"resources":[
            {"name":"second","uri":"fixture://notes/second"}
        ]}),
        "resources/list" => json!({"resources":[
            {"name":"first","uri":"fixture://notes/first","mimeType":"text/plain"}
        ],"nextCursor":"next"}),
        "resources/templates/list" => json!({"resourceTemplates":[
            {"name":"note","uriTemplate":"fixture://notes/{name}"}
        ]}),
        "prompts/list" => json!({"prompts":[{"name":"greet","arguments":[
            {"name":"who","required":true}
        ]}]}),
        "resources/read"
            if params["uri"] == "fixture://notes/ask" && params["requestState"].is_null() =>
        {
            json!({
                "resultType":"input_required","requestState":"sealed","inputRequests":{"ask":{
                    "method":"elicitation/create","params":{"mode":"form","message":"What is your name?",
                        "requestedSchema":{"type":"object","properties":{"who":{"type":"string"}}}}
                }}
            })
        }
        "resources/read" if params["requestState"] == "sealed" => json!({"contents":[
            {"uri":params["uri"],"text":params["inputResponses"]["ask"]["content"]["who"]}
        ]}),
        "resources/read" => json!({"contents":[
            {"uri":params["uri"],"text":"Resource contents","mimeType":"text/plain"}
        ]}),
        "prompts/get" => {
            assert_eq!(params["name"], "greet");
            let who = params["arguments"]["who"].as_str().unwrap();
            json!({"messages":[{"role":"user","content":{"type":"text","text":format!("Hello {who}")}}]})
        }
        "completion/complete" => {
            assert_eq!(params["ref"], json!({"type":"ref/prompt","name":"greet"}));
            assert_eq!(params["context"]["arguments"]["conversation"], "example");
            json!({"completion":{"values":["World"],"total":2}})
        }
        unknown => panic!("unexpected upstream method {unknown}"),
    };
    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result})).into_response()
}

#[tokio::test]
async fn registration_discovers_and_serves_federated_resources_and_prompts() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let upstream = Running::start(Router::new().route("/mcp", post(catalog_fixture))).await;
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
    let gateway = Running::start(
        service
            .registration_router()
            .merge(service.mcp_router(false, ProtocolMode::Auto)),
    )
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let (status, registration) = send(&client, gateway.url("/gateways"), json!({
        "name":"fixture","url":upstream.url("/mcp"),"visibility":"public","transport":"STREAMABLEHTTP"
    }), Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{registration}");
    for (method, key, expected) in [
        (
            "resources/list",
            "resources",
            vec!["fixture-first", "fixture-second"],
        ),
        (
            "resources/templates/list",
            "resourceTemplates",
            vec!["fixture-note"],
        ),
        ("prompts/list", "prompts", vec!["fixture-greet"]),
    ] {
        let (status, reply) = send(
            &client,
            gateway.url("/mcp/"),
            json!({"jsonrpc":"2.0","id":1,"method":method}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        let mut names = reply["result"][key]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, expected);
    }
    for uri in [
        "fixture://notes/first",
        "fixture://notes/from-template?view=1",
    ] {
        let (_, reply) = send(
            &client,
            gateway.url("/mcp/"),
            json!({
                "jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":uri}
            }),
            None,
        )
        .await;
        assert_eq!(
            reply["result"]["contents"],
            json!([
                {"uri":uri,"text":"Resource contents","mimeType":"text/plain"}
            ])
        );
    }
    let (_, reply) = send(&client, gateway.url("/mcp/"), json!({
        "jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"fixture-greet","arguments":{"who":"World"}}
    }), None).await;
    assert_eq!(
        reply["result"]["messages"][0]["content"]["text"],
        "Hello World"
    );
    let (_, reply) = send(
        &client,
        gateway.url("/mcp/"),
        json!({
            "jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"greet"}
        }),
        None,
    )
    .await;
    assert_eq!(
        reply["error"],
        json!({"code":-32602,"message":"Unknown prompt: greet"})
    );

    let (status, reply) = send_with_headers(
        &client,
        gateway.url("/mcp/"),
        modern_request(
            "completion/complete",
            5,
            json!({
                "ref":{"type":"ref/prompt","name":"fixture-greet"},
                "argument":{"name":"who","value":"Wo"},
                "context":{"arguments":{"conversation":"example"}}
            }),
        ),
        None,
        &[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "completion/complete"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["result"]["resultType"], "complete");
    assert_eq!(
        reply["result"]["completion"],
        json!({"values":["World"],"total":2,"hasMore":true})
    );

    let (status, reply) = send_with_headers(
        &client,
        gateway.url("/mcp/"),
        modern_request(
            "completion/complete",
            6,
            json!({
                "ref":{"type":"ref/prompt","name":"fixture-greet"},
                "argument":{"name":"who","value":"Wo"},
                "context":{"arguments":{"conversation":1}}
            }),
        ),
        None,
        &[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "completion/complete"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply["error"],
        json!({"code":-32602,"message":"Invalid request parameters","data":""})
    );

    let ask = "fixture://notes/ask";
    let read = async |mut body: Value, elicitation| {
        if elicitation {
            body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
                json!({"elicitation":{}});
        }
        send_with_headers(
            &client,
            gateway.url("/mcp/"),
            body,
            None,
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "resources/read"),
                ("mcp-name", ask),
            ],
        )
        .await
    };
    let (status, _) = read(
        modern_request("resources/read", 5, json!({"uri":ask})),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, asked) = read(
        modern_request("resources/read", 5, json!({"uri":ask})),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{asked}");
    assert_eq!(asked["result"]["resultType"], "input_required");
    let (_, complete) = read(modern_request("resources/read", 6, json!({
        "uri":ask,"requestState":asked["result"]["requestState"],"inputResponses":{"ask":{"action":"accept","content":{"who":"Ada"}}}
    })), true).await;
    assert_eq!(complete["result"]["contents"][0]["text"], "Ada");
    assert_eq!(complete["result"]["cacheScope"], "private");
}

#[tokio::test]
async fn catalog_metadata_lists_scoped_resources_templates_and_prompts() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let database = database().await;
    let Database::Sqlite(pool) = &database else {
        unreachable!()
    };
    sqlx::raw_sql(r#"
        INSERT INTO servers (id, name, visibility) VALUES ('v', 'Virtual', 'public');
        INSERT INTO resources (id, uri, uri_template, name, mime_type, visibility, team_id) VALUES
            ('r1', 'fixture://notes/first', NULL, 'First', 'text/plain', 'public', NULL),
            ('r2', 'fixture://notes/team', NULL, 'Team', 'text/plain', 'team', 'alpha'),
            ('r3', 'fixture://notes/last', NULL, 'Last', 'text/plain', 'public', NULL),
            ('t1', 'fixture://notes/{name}', 'fixture://notes/{name}', 'Note', 'text/plain', 'public', NULL);
        INSERT INTO server_resource_association (server_id, resource_id) VALUES ('v', 'r3');
        UPDATE resources SET binary_content = x'0001ff' WHERE id = 'r3';
        INSERT INTO prompts (id,name,original_name,custom_name,custom_name_slug,argument_schema,template)
            VALUES ('p1','greet','greet','greet','greet','{"properties":{"who":{"name":"who","type":"string","enum":["World","Else"]}},"required":["who"]}',
                '# User:
Hello {{ who }}
# Assistant:
Greetings');
    "#).execute(pool).await.unwrap();
    let service = Arc::new(GatewayService::new(
        database.clone(),
        authorizer(database),
        UpstreamClient::new(EgressPolicy::default(), Duration::from_secs(5)),
        Pagination::new(1, 900, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(service.mcp_router(false, ProtocolMode::Auto)).await;
    let client = Client::builder().no_proxy().build().unwrap();
    let legacy = async |path: &str, method: &str, params: Value| {
        send(
            &client,
            gateway.url(path),
            json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
            None,
        )
        .await
    };
    let (status, reply) = legacy("/mcp/", "resources/list", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["result"]["resources"][0]["name"], "First");
    let cursor = reply["result"]["nextCursor"].as_str().unwrap();
    let (_, reply) = legacy("/mcp/", "resources/list", json!({"cursor":cursor})).await;
    assert_eq!(
        reply["result"]["resources"],
        json!([
            {"uri":"fixture://notes/last","name":"Last","mimeType":"text/plain"}
        ])
    );
    let (_, reply) = legacy(
        "/mcp/",
        "resources/templates/list",
        json!({"cursor":cursor}),
    )
    .await;
    assert_eq!(reply["error"]["code"], -32602);
    let (_, reply) = legacy("/servers/v/mcp/", "resources/list", json!({})).await;
    assert_eq!(reply["result"]["resources"][0]["name"], "Last");
    let (_, reply) = legacy("/mcp/", "resources/templates/list", json!({})).await;
    assert_eq!(
        reply["result"]["resourceTemplates"][0]["uriTemplate"],
        "fixture://notes/{name}"
    );
    let (status, reply) = send_with_headers(
        &client,
        gateway.url("/mcp/"),
        modern_request("prompts/list", 2, json!({})),
        None,
        &[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "prompts/list"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        reply["result"]["prompts"],
        json!([{"name":"greet","arguments":[{"name":"who","description":"","required":true}]}])
    );
    assert_eq!(reply["result"]["cacheScope"], "private");
    let (_, reply) = legacy(
        "/servers/v/mcp/",
        "resources/read",
        json!({"uri":"fixture://notes/last"}),
    )
    .await;
    assert_eq!(reply["result"]["contents"][0]["blob"], "AAH/");
    let (_, reply) = legacy(
        "/servers/v/mcp/",
        "resources/read",
        json!({"uri":"fixture://notes/first"}),
    )
    .await;
    assert_eq!(
        reply["error"]["message"],
        "Unknown resource: fixture://notes/first"
    );
    let (_, reply) = legacy(
        "/mcp/",
        "prompts/get",
        json!({"name":"greet","arguments":{"who":"World"}}),
    )
    .await;
    assert_eq!(
        reply["result"]["messages"],
        json!([
            {"role":"user","content":{"type":"text","text":"Hello World"}},
            {"role":"assistant","content":{"type":"text","text":"Greetings"}}
        ])
    );
    let (_, reply) = legacy("/mcp/", "prompts/get", json!({"name":"greet"})).await;
    assert_eq!(reply["error"]["message"], "Missing required arguments: who");
    let (_, reply) = legacy(
        "/mcp/",
        "prompts/get",
        json!({"name":"greet","arguments":{"who":"Neither"}}),
    )
    .await;
    assert_eq!(
        reply["error"],
        json!({"code":0,"message":"Failed to process prompt: An unexpected error occurred"})
    );

    let (_, reply) = legacy(
        "/mcp/",
        "completion/complete",
        json!({"ref":{"type":"ref/prompt","name":"greet"},"argument":{"name":"who","value":"w"}}),
    )
    .await;
    assert_eq!(
        reply["result"]["completion"],
        json!({"values":["World"],"total":1,"hasMore":false})
    );
    let (_, reply) = legacy(
        "/mcp/",
        "completion/complete",
        json!({"ref":{"type":"ref/resource","uri":"fixture://notes/{name}"},"argument":{"name":"name","value":"notes/"}}),
    )
    .await;
    assert_eq!(
        reply["result"]["completion"],
        json!({"values":["fixture://notes/first","fixture://notes/last","fixture://notes/{name}"],"total":3,"hasMore":false})
    );
}

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
    for request in [
        ping("/mcp/", Some(&renewed), None),
        client.delete(gateway.url("/mcp/")).bearer_auth(&renewed),
    ] {
        let error = request.send().await.unwrap();
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        let discarded_id = error.headers()["mcp-session-id"].to_str().unwrap();
        assert!(uuid::Uuid::parse_str(discarded_id).is_ok());
        let reuse = ping("/mcp/", Some(&renewed), None)
            .header("mcp-session-id", discarded_id)
            .send()
            .await
            .unwrap();
        assert_eq!(reuse.status(), StatusCode::NOT_FOUND);
    }

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
        "notifications/initialized" | "notifications/cancelled" => {
            return StatusCode::ACCEPTED.into_response();
        }
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
async fn modern_tool_input_round_trips_preserve_capabilities_and_request_state() {
    const MODERN: &str = "2026-07-28";
    const CLIENT_CAPS: &str = "io.modelcontextprotocol/clientCapabilities";
    let _ = rustls::crypto::ring::default_provider().install_default();
    let question = json!({"method":"elicitation/create","params":{
        "mode":"form","message":"What color?",
        "requestedSchema":{"type":"object","properties":{"color":{"type":"string"}}}
    }});
    let reply_question = question.clone();
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let upstream_calls = calls.clone();
    let upstream = Running::start(Router::new().route("/mcp", post(
        async move |headers: HeaderMap, Json(body): Json<Value>| {
            assert_eq!(headers["mcp-protocol-version"], MODERN);
            let params = &body["params"];
            let result = match body["method"].as_str().unwrap() {
                "server/discover" => json!({"supportedVersions":[MODERN],"capabilities":{"tools":{}}}),
                "tools/list" => json!({"tools":[{"name":"color","inputSchema":{"type":"object"}}]}),
                "tools/call" => {
                    assert_eq!(headers["mcp-name"], "color");
                    assert_eq!(params["name"], "color");
                    upstream_calls.lock().unwrap().push(params.clone());
                    if params["arguments"]["strict"] == true {
                        return (StatusCode::BAD_REQUEST, Json(json!({
                            "jsonrpc":"2.0","id":body["id"],"error":{
                                "code":-32021,"message":"Fixture requires form support",
                                "data":{"requiredCapabilities":{"elicitation":{"form":{}}}}
                            }
                        }))).into_response();
                    }
                    if params["requestState"] == "sealed" {
                        let color = &params["inputResponses"]["color"]["content"]["color"];
                        json!({"resultType":"complete","content":[{"type":"text","text":color}],"isError":false})
                    } else {
                        json!({"resultType":"input_required","inputRequests":{"color":reply_question},"requestState":"sealed"})
                    }
                }
                unknown => panic!("unexpected upstream method {unknown}"),
            };
            Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result})).into_response()
        }
    ))).await;
    let database = database().await;
    let service = Arc::new(GatewayService::new(
        database.clone(),
        authorizer(database),
        UpstreamClient::new(
            EgressPolicy {
                allow_localhost: true,
                ..EgressPolicy::default()
            },
            Duration::from_secs(4),
        ),
        Pagination::new(100, 900, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(
        service
            .registration_router()
            .merge(service.mcp_router(false, ProtocolMode::Auto)),
    )
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let (status, registration) = send(&client, gateway.url("/gateways"), json!({
        "name":"fixture","url":upstream.url("/mcp"),"visibility":"public","transport":"STREAMABLEHTTP"
    }), Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{registration}");
    let modern = |id: &str, capabilities: Value, state: Option<&Value>| {
        let mut params = json!({"name":"fixture-color","arguments":{"strict":id == "strict"},"_meta":{
            "io.modelcontextprotocol/protocolVersion":MODERN, CLIENT_CAPS:capabilities
        }});
        if let Some(state) = state {
            params["requestState"] = json!("sealed");
            params["inputResponses"] = state.clone();
        }
        client
            .post(gateway.url("/mcp/"))
            .header("mcp-protocol-version", MODERN)
            .header("mcp-method", "tools/call")
            .header("mcp-name", "fixture-color")
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params}).to_string(),
            )
    };
    let reply_body = async |reply: reqwest::Response| {
        serde_json::from_slice::<Value>(&reply.bytes().await.unwrap()).unwrap()
    };
    for caps in [json!({}), json!({"elicitation":{"url":{}}})] {
        let reply = modern("undeclared", caps, None).send().await.unwrap();
        assert_eq!(reply.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            reply_body(reply).await["error"],
            json!({
                "code":-32021,"message":"Client did not declare the form elicitation capability required by tool 'fixture-color'",
                "data":{"requiredCapabilities":{"elicitation":{"form":{}}}}
            })
        );
    }
    let reply = modern(
        "declared",
        json!({"elicitation":{},"extensions":{"fixture":{}}}),
        None,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    let response = reply_body(reply).await;
    let result = &response["result"];
    assert_eq!(result["resultType"], "input_required");
    assert_eq!(result["inputRequests"]["color"], question);
    assert_eq!(result["requestState"], "sealed");
    let responses = json!({"color":{"action":"accept","content":{"color":"blue"}}});
    let reply = modern(
        "continue",
        json!({"elicitation":{"form":{}}}),
        Some(&responses),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    let response = reply_body(reply).await;
    let result = &response["result"];
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["content"][0]["text"], "blue");

    let reply = client.post(gateway.url("/mcp/"))
        .header("mcp-protocol-version", PROTOCOL)
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({"jsonrpc":"2.0","id":"legacy","method":"tools/call","params":{"name":"fixture-color"}}).to_string())
        .send().await.unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(
        reply_body(reply).await["result"],
        json!({
            "content":[{"type":"text","text":"MCP server error: Elicitation not supported"}],"isError":true
        })
    );
    let reply = modern("strict", json!({}), None).send().await.unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    let response = reply_body(reply).await;
    let result = &response["result"];
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["isError"], true);
    assert_eq!(result["_meta"]["io.contextforge/errorCode"]["code"], -32021);
    assert_eq!(
        result["content"][0]["text"],
        "MCP server error: Fixture requires form support"
    );

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 6);
    assert_eq!(calls[0]["_meta"][CLIENT_CAPS], json!({}));
    assert_eq!(
        calls[1]["_meta"][CLIENT_CAPS],
        json!({"elicitation":{"url":{}}})
    );
    assert_eq!(calls[2]["_meta"][CLIENT_CAPS], json!({"elicitation":{}}));
    assert_eq!(
        calls[3]["_meta"][CLIENT_CAPS],
        json!({"elicitation":{"form":{}}})
    );
    assert_eq!(calls[3]["requestState"], "sealed");
    assert_eq!(calls[3]["inputResponses"], responses);
    assert_eq!(calls[4]["_meta"][CLIENT_CAPS], json!({}));
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

#[derive(Default)]
struct PassiveFixture {
    initialized: AtomicUsize,
    gets: AtomicUsize,
    called: std::sync::Mutex<Vec<(String, Value)>>,
    callbacks: std::sync::Mutex<Vec<Value>>,
    deleted: std::sync::Mutex<Vec<String>>,
    release_get: tokio::sync::Notify,
    ended: tokio::sync::Notify,
}

fn passive_log(data: &Value) -> axum::response::sse::Event {
    axum::response::sse::Event::default()
        .json_data(json!({
            "jsonrpc":"2.0","method":"notifications/message",
            "params":{"level":"info","logger":"passive","data":data}
        }))
        .unwrap()
}

async fn passive_fixture(
    State(fixture): State<Arc<PassiveFixture>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let id = &body["id"];
    let result = match body["method"].as_str() {
        None => {
            assert_eq!(headers["mcp-session-id"], "upstream-2");
            assert_eq!(headers["mcp-protocol-version"], PROTOCOL);
            fixture.callbacks.lock().unwrap().push(body);
            return StatusCode::ACCEPTED.into_response();
        }
        Some("initialize") => {
            let generation = fixture.initialized.fetch_add(1, Ordering::Relaxed) + 1;
            return (
                [("mcp-session-id", format!("upstream-{generation}"))],
                Json(json!({"jsonrpc":"2.0", "id":id, "result":{
                    "protocolVersion":PROTOCOL, "capabilities":{"tools":{}},
                    "serverInfo":{"name":"passive fixture","version":"1"}
                }})),
            )
                .into_response();
        }
        Some("notifications/initialized") => return StatusCode::ACCEPTED.into_response(),
        Some("tools/list") => json!({"tools":[{"name":"log","inputSchema":{"type":"object"}}]}),
        Some("tools/call") => {
            let upstream_id = headers["mcp-session-id"].to_str().unwrap().to_owned();
            fixture
                .called
                .lock()
                .unwrap()
                .push((upstream_id, id.clone()));
            let mut events: Vec<_> = body["params"]["arguments"]["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(passive_log)
                .collect();
            if body["params"]["arguments"]["callbacks"] == true {
                for request in [
                    json!({"jsonrpc":"2.0","id":"roots","method":"roots/list"}),
                    json!({"jsonrpc":"2.0","id":"sample","method":"sampling/createMessage",
                        "params":{"messages":[],"maxTokens":100}}),
                    json!({"jsonrpc":"2.0","id":"elicit","method":"elicitation/create",
                        "params":{"message":"Fixture","requestedSchema":{"type":"object","properties":{}}}}),
                ] {
                    events.push(
                        axum::response::sse::Event::default()
                            .json_data(request)
                            .unwrap(),
                    );
                }
            }
            events.push(
                axum::response::sse::Event::default()
                    .json_data(json!({
                        "jsonrpc":"2.0","id":id,"result":{"content":[],"isError":false}
                    }))
                    .unwrap(),
            );
            return axum::response::Sse::new(futures_util::stream::iter(
                events.into_iter().map(Ok::<_, std::convert::Infallible>),
            ))
            .into_response();
        }
        unexpected => panic!("unexpected upstream method {unexpected:?}"),
    };
    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
}

async fn upstream_passive(
    State(fixture): State<Arc<PassiveFixture>>,
    headers: HeaderMap,
) -> Response {
    use futures_util::{StreamExt, stream};
    assert_eq!(headers["mcp-session-id"], "upstream-2");
    assert_eq!(headers["mcp-protocol-version"], PROTOCOL);
    assert_eq!(headers[header::ACCEPT], "text/event-stream");
    let number = fixture.gets.fetch_add(1, Ordering::Relaxed);
    if number == 0 {
        assert!(!headers.contains_key("last-event-id"));
        let frames = stream::once(async move {
            fixture.release_get.notified().await;
            Ok::<_, std::convert::Infallible>(
                axum::response::sse::Event::default()
                    .json_data(json!({"jsonrpc":"2.0","id":57,"method":"ping"}))
                    .unwrap(),
            )
        })
        .chain(stream::iter([
            Ok(passive_log(&json!("G")).id("upstream-G")),
        ]));
        return axum::response::Sse::new(frames).into_response();
    }
    assert_eq!(number, 1);
    assert_eq!(headers["last-event-id"], "upstream-G");
    let response = stream::iter([Ok::<_, std::convert::Infallible>(
        passive_log(&json!("H")).id("upstream-H"),
    )])
    .chain(stream::pending());
    axum::response::Sse::new(response).into_response()
}

async fn end_passive_fixture(
    State(fixture): State<Arc<PassiveFixture>>,
    headers: HeaderMap,
) -> StatusCode {
    fixture
        .deleted
        .lock()
        .unwrap()
        .push(headers["mcp-session-id"].to_str().unwrap().to_owned());
    fixture.ended.notify_one();
    StatusCode::OK
}

#[tokio::test]
async fn passive_stream_follows_upstream_get_reconnects_and_replays_notifications() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fixture = Arc::new(PassiveFixture::default());
    let upstream = Running::start(
        Router::new()
            .route(
                "/mcp",
                post(passive_fixture)
                    .get(upstream_passive)
                    .delete(end_passive_fixture),
            )
            .with_state(fixture.clone()),
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
            Duration::from_secs(4),
        )
        .with_connect_mode(ConnectMode::Legacy),
        Pagination::new(100, 900, None),
        CatalogRefresh::default(),
    ));
    let gateway = Running::start(service.registration_router().merge(
        service.mcp_router_with_sessions(
            true,
            ProtocolMode::Legacy,
            Some(SessionSettings::default()),
        ),
    ))
    .await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let (status, result) = send(&client, gateway.url("/gateways"), json!({
        "name":"passive","url":upstream.url("/mcp"),"visibility":"public","transport":"STREAMABLEHTTP"
    }), Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{result}");

    let owner = token("member", json!(["alpha"]), json!({}));
    let restricted = token(
        "member",
        json!(["alpha"]),
        json!({"permissions":["servers.use"]}),
    );
    let post = |message: Value| {
        client
            .post(gateway.url("/mcp/"))
            .bearer_auth(&owner)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .header("mcp-protocol-version", PROTOCOL)
            .body(message.to_string())
    };
    let initialized = post(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}
    }})).send().await.unwrap();
    assert_eq!(initialized.status(), StatusCode::OK);
    let session = initialized.headers()["mcp-session-id"].clone();
    let notify = |id, messages: &[&str]| {
        post(json!({
            "jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":"passive-log","arguments":{"messages":messages,"callbacks":id == 2}}
        }))
        .header("mcp-session-id", &session)
    };
    let get = |credential, cursor: Option<&str>| {
        let mut request = client
            .get(gateway.url("/mcp/"))
            .bearer_auth(credential)
            .header(header::ACCEPT, "text/event-stream")
            .header("mcp-session-id", &session);
        if let Some(cursor) = cursor {
            request = request.header("last-event-id", cursor);
        }
        request
    };

    let mut listener = get(&owner, None).send().await.unwrap();
    assert_eq!(listener.status(), StatusCode::OK);
    assert_eq!(
        notify(2, &["A", "B"]).send().await.unwrap().status(),
        StatusCode::OK
    );
    let mut buffered = Vec::new();
    let (cursor, first) = next_sse_message(&mut listener, &mut buffered).await;
    let (_, second) = next_sse_message(&mut listener, &mut buffered).await;
    assert_eq!(first["method"], "notifications/message");
    assert_eq!(first["params"]["data"], "A");
    assert_eq!(second["params"]["data"], "B");
    // The upstream GET remains active after the tool has returned.
    fixture.release_get.notify_one();
    for expected in ["G", "H"] {
        let (_, event) = next_sse_message(&mut listener, &mut buffered).await;
        assert_eq!(event["params"]["data"], expected);
    }
    assert_eq!(
        *fixture.callbacks.lock().unwrap(),
        [
            json!({"jsonrpc":"2.0","id":"roots","error":{"code":-32600,"message":"List roots not supported"}}),
            json!({"jsonrpc":"2.0","id":"sample","error":{"code":-32600,"message":"Sampling not supported"}}),
            json!({"jsonrpc":"2.0","id":"elicit","error":{"code":-32600,"message":"Elicitation not supported"}}),
            json!({"jsonrpc":"2.0","id":57,"result":{}}),
        ]
    );
    let cursor = cursor.unwrap();
    assert_eq!(
        get(&restricted, Some(&cursor))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN,
    );
    drop(listener);

    for (cursor, expected) in [(Some(cursor.as_str()), "B"), (Some("unknown"), "C")] {
        let mut listener = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let response = get(&owner, cursor).send().await.unwrap();
                if response.status() != StatusCode::CONFLICT {
                    break response;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(listener.status(), StatusCode::OK);
        if cursor == Some("unknown") {
            assert_eq!(
                notify(3, &["C"]).send().await.unwrap().status(),
                StatusCode::OK
            );
        }
        buffered.clear();
        let (_, event) = next_sse_message(&mut listener, &mut buffered).await;
        assert_eq!(event["params"]["data"], expected);
    }
    assert_eq!(
        fixture.initialized.load(Ordering::Relaxed),
        2,
        "discovery and one associated session"
    );
    let calls = fixture.called.lock().unwrap().clone();
    assert_eq!(
        calls,
        [
            ("upstream-2".to_owned(), json!(2)),
            ("upstream-2".to_owned(), json!(3))
        ]
    );
    let deleted = client
        .delete(gateway.url("/mcp/"))
        .bearer_auth(&owner)
        .header("mcp-session-id", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if fixture
                .deleted
                .lock()
                .unwrap()
                .iter()
                .any(|id| id == "upstream-2")
            {
                break;
            }
            fixture.ended.notified().await;
        }
    })
    .await
    .expect("downstream DELETE should close the upstream session");
}

#[tokio::test]
#[ignore = "requires a disposable Redis or Valkey database in REDIS_URL"]
async fn redis_affinity_relays_posts_and_replays_passive_events_after_worker_loss() {
    use context_forge_rs::{config::RedisSettings, mcp::RedisSessionDirectory};
    use tokio_util::sync::CancellationToken;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let fixture = Arc::new(PassiveFixture::default());
    let upstream = Running::start(
        Router::new()
            .route(
                "/mcp",
                post(passive_fixture)
                    .get(upstream_passive)
                    .delete(end_passive_fixture),
            )
            .with_state(fixture),
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
            Duration::from_secs(4),
        )
        .with_connect_mode(ConnectMode::Legacy),
        Pagination::new(100, 900, None),
        CatalogRefresh::default(),
    ));
    let redis_settings = RedisSettings {
        url: std::env::var("REDIS_URL").unwrap(),
        connect_timeout: Duration::from_secs(2),
        response_timeout: Duration::from_secs(2),
    };
    let shutdown = CancellationToken::new();
    let _stop = shutdown.clone().drop_guard();
    let owner_shutdown = shutdown.child_token();
    let router = |worker_shutdown: CancellationToken| {
        service.mcp_router_with_options(
            true,
            ProtocolMode::Legacy,
            HttpOptions {
                json_response: false,
                sessions: Some(SessionSettings {
                    redis: Some(Arc::new(
                        RedisSessionDirectory::new(&redis_settings).unwrap(),
                    )),
                    shutdown: worker_shutdown,
                    affinity_forward_timeout: Duration::from_secs(4),
                    affinity_forward_concurrency: 1,
                    ..SessionSettings::default()
                }),
            },
        )
    };
    let first = Running::start(
        service
            .registration_router()
            .merge(router(owner_shutdown.clone())),
    )
    .await;
    let second = Running::start(router(shutdown.clone())).await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let (status, result) = send(&client, first.url("/gateways"), json!({
        "name":"passive","url":upstream.url("/mcp"),"visibility":"public","transport":"STREAMABLEHTTP"
    }), Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let owner = token("member", json!(["alpha"]), json!({}));
    let other = token("outsider", json!(["beta"]), json!({}));
    let post = |gateway: &Running, message: Value| {
        client
            .post(gateway.url("/mcp/"))
            .bearer_auth(&owner)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, "application/json")
            .header("mcp-protocol-version", PROTOCOL)
            .body(message.to_string())
    };
    let initialize = || {
        post(
            &first,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}
            }}),
        )
    };
    let initialized = initialize().send().await.unwrap();
    assert_eq!(initialized.status(), StatusCode::OK);
    let session = initialized.headers()["mcp-session-id"].clone();

    let mut ping = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let response = post(&second, json!({"jsonrpc":"2.0","id":2,"method":"ping"}))
                .header("mcp-session-id", &session)
                .send()
                .await
                .unwrap();
            if response.status() != StatusCode::SERVICE_UNAVAILABLE {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(ping.status(), StatusCode::OK);
    assert_eq!(ping.headers()[header::CONTENT_TYPE], "text/event-stream");
    let mut buffered = Vec::new();
    let (_, result) = next_sse_message(&mut ping, &mut buffered).await;
    assert_eq!(result, json!({"jsonrpc":"2.0","id":2,"result":{}}));

    let get = |credential: &str, id: &HeaderValue| {
        client
            .get(second.url("/mcp/"))
            .bearer_auth(credential)
            .header(header::ACCEPT, "text/event-stream")
            .header("mcp-session-id", id)
    };
    assert_eq!(
        get(&other, &session).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut passive = get(&owner, &session).send().await.unwrap();
    assert_eq!(passive.status(), StatusCode::OK);
    let tool = post(
        &second,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"passive-log","arguments":{"messages":["A","B"]}
        }}),
    )
    .header("mcp-session-id", &session)
    .send()
    .await
    .unwrap();
    assert_eq!(tool.status(), StatusCode::OK);
    assert!(tool.text().await.unwrap().contains("\"id\":3"));
    buffered.clear();
    let (cursor, first_frame) = next_sse_message(&mut passive, &mut buffered).await;
    let (_, second_frame) = next_sse_message(&mut passive, &mut buffered).await;
    assert_eq!(first_frame["params"]["data"], "A");
    assert_eq!(second_frame["params"]["data"], "B");
    let cursor = cursor.unwrap();
    drop(passive);

    let resume = || {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let response = get(&owner, &session)
                    .header("last-event-id", &cursor)
                    .send()
                    .await
                    .unwrap();
                if response.status() != StatusCode::CONFLICT {
                    break response;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    };
    let mut passive = resume().await.unwrap();
    assert_eq!(passive.status(), StatusCode::OK);
    buffered.clear();
    let (_, event) = next_sse_message(&mut passive, &mut buffered).await;
    assert_eq!(event["params"]["data"], "B");
    drop(passive);
    let restricted = token(
        "member",
        json!(["alpha"]),
        json!({"permissions":["servers.use"]}),
    );
    assert_eq!(
        get(&restricted, &session)
            .header("last-event-id", &cursor)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    let initialized = initialize().send().await.unwrap();
    assert_eq!(initialized.status(), StatusCode::OK);
    let disposable = initialized.headers()["mcp-session-id"].clone();
    let mut passive = get(&owner, &disposable)
        .header("last-event-id", &cursor)
        .send()
        .await
        .unwrap();
    assert_eq!(passive.status(), StatusCode::OK);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), passive.chunk())
            .await
            .is_err()
    );
    let deleted = client
        .delete(second.url("/mcp/"))
        .bearer_auth(&owner)
        .header("mcp-session-id", &disposable)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&deleted.text().await.unwrap()).unwrap()["result"],
        json!({})
    );
    assert!(passive.chunk().await.unwrap().is_none());
    let response = post(&first, json!({"jsonrpc":"2.0","id":4,"method":"ping"}))
        .header("mcp-session-id", &disposable)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    owner_shutdown.cancel();
    drop(first);
    let mut passive = resume().await.unwrap();
    assert_eq!(passive.status(), StatusCode::OK);
    buffered.clear();
    let (_, event) = next_sse_message(&mut passive, &mut buffered).await;
    assert_eq!(event["params"]["data"], "B");
}

#[tokio::test]
#[ignore = "requires a disposable Redis or Valkey database in REDIS_URL"]
async fn redis_affinity_orders_forwarded_posts_until_the_session_lock_timeout() {
    use context_forge_rs::{config::RedisSettings, mcp::RedisSessionDirectory};
    use tokio_util::sync::CancellationToken;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let upstream = Running::start(
        Router::new()
            .route("/mcp", post(fixture_progress))
            .with_state(release.clone()),
    )
    .await;
    let database = database().await;
    let gateway = Arc::new(GatewayService::new(
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
    let settings = RedisSettings {
        url: std::env::var("REDIS_URL").unwrap(),
        connect_timeout: Duration::from_secs(2),
        response_timeout: Duration::from_secs(2),
    };
    let shutdown = CancellationToken::new();
    let _stop = shutdown.clone().drop_guard();
    let router = || {
        gateway.mcp_router_with_options(
            false,
            ProtocolMode::Legacy,
            HttpOptions {
                json_response: false,
                sessions: Some(SessionSettings {
                    redis: Some(Arc::new(RedisSessionDirectory::new(&settings).unwrap())),
                    affinity_forward_concurrency: 2,
                    affinity_session_lock_timeout: Duration::from_millis(600),
                    shutdown: shutdown.clone(),
                    ..SessionSettings::default()
                }),
            },
        )
    };
    let first = Running::start(gateway.registration_router().merge(router())).await;
    let second = Running::start(router()).await;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let admin = token("admin", Value::Null, json!({}));
    let (status, registration) = send(&client, first.url("/gateways"), json!({
        "name":"queue","url":upstream.url("/mcp"),"visibility":"public","transport":"STREAMABLEHTTP"
    }), Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{registration}");
    let post = |worker: &Running, body: Value| {
        client
            .post(worker.url("/mcp/"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL)
            .body(body.to_string())
    };
    let initialized = post(&first, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}
    }})).send().await.unwrap();
    assert_eq!(initialized.status(), StatusCode::OK);
    let session = initialized.headers()["mcp-session-id"].clone();

    let call = |id: &str, wait: bool| {
        post(
            &second,
            json!({
                "jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                    "name":"queue-hold","arguments":{"wait":wait},"_meta":{"progressToken":id}
                }
            }),
        )
        .header("mcp-session-id", &session)
    };
    let mut holding = call("held", true).send().await.unwrap();
    assert_eq!(holding.status(), StatusCode::OK);
    let mut buffered = Vec::new();
    let (_, progress) = next_sse_message(&mut holding, &mut buffered).await;
    assert_eq!(progress["params"]["progressToken"], "held");
    let mut queued = Box::pin(call("queued", false).send());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut queued)
            .await
            .is_err()
    );
    let mut queued = tokio::time::timeout(Duration::from_secs(3), queued)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(queued.status(), StatusCode::OK);
    let mut queued_buffer = Vec::new();
    let queued_progress = next_sse_message(&mut queued, &mut queued_buffer);
    let mut queued_progress = Box::pin(queued_progress);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut queued_progress)
            .await
            .is_err()
    );
    release.add_permits(1);
    let (_, result) = next_sse_message(&mut holding, &mut buffered).await;
    assert_eq!(result["id"], "held");
    let (_, progress) = queued_progress.await;
    assert_eq!(progress["params"]["progressToken"], "queued");
    assert!(queued.text().await.unwrap().contains("\"id\":\"queued\""));

    let mut holding = call("cancelled", true).send().await.unwrap();
    assert_eq!(holding.status(), StatusCode::OK);
    buffered.clear();
    let (_, progress) = next_sse_message(&mut holding, &mut buffered).await;
    assert_eq!(progress["params"]["progressToken"], "cancelled");
    let cancel = post(&second, json!({"jsonrpc":"2.0","method":"notifications/cancelled", "params":{"requestId":"cancelled"}}))
        .header("mcp-session-id", &session).send().await.unwrap();
    assert_eq!(cancel.status(), StatusCode::ACCEPTED);
    let (_, cancelled) = next_sse_message(&mut holding, &mut buffered).await;
    assert_eq!(cancelled["error"]["code"], -32800);
}
