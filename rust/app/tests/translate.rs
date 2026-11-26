// SPDX-License-Identifier: Apache-2.0

use std::{net::TcpListener, process::Stdio, time::Duration};

use reqwest::{Client, Response, StatusCode};
use serde_json::{Value, json};
use tokio::{
    process::Command,
    time::{sleep, timeout},
};

#[tokio::test]
async fn remote_translator_preserves_streamable_http_session_headers() {
    use axum::{Json, Router, http::HeaderMap, routing::post};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let upstream = Router::new().route("/mcp", post(async |headers: HeaderMap, Json(message): Json<Value>| {
            assert_eq!(headers["authorization"], "Bearer fixture");
            let result = if message["method"] == "initialize" {
                assert!(!headers.contains_key("mcp-session-id"));
                json!({"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}})
            } else {
                assert_eq!(message["method"], "ping");
                assert_eq!(headers["mcp-session-id"], "fixture-session");
                assert_eq!(headers["mcp-protocol-version"], "2025-11-25");
                json!({"session":"preserved"})
            };
            ([("mcp-session-id", "fixture-session")], Json(json!({"jsonrpc":"2.0","id":message["id"],"result":result})))
        }));
        axum::serve(listener, upstream).await.unwrap();
    });
    let child = r#"sh -c '
        printf "%s\n" "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}}"
        IFS= read -r initialization || exit 1
        printf "%s\n" "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}"
        IFS= read -r reply || exit 1
        printf "fixture-reply %s\n" "$reply" >&2
    '"#;
    let output = timeout(
        Duration::from_secs(5),
        Command::new(env!("CARGO_BIN_EXE_context-forge-translate"))
            .args([
                "--connect-streamable-http",
                &base_url,
                "--oauth2Bearer",
                "fixture",
                "--stdioCommand",
                child,
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("remote bridge exits with its stdio child")
    .unwrap();
    server.abort();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    let reply = stderr
        .lines()
        .find_map(|line| line.strip_prefix("fixture-reply "))
        .expect("child got the reply");
    assert_eq!(
        serde_json::from_str::<Value>(reply).unwrap(),
        json!({
            "jsonrpc":"2.0","id":2,"result":{"session":"preserved"}
        })
    );
}

#[tokio::test]
async fn translator_correlates_stdio_replies_across_http_and_sse_clients() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let child_fixture = r#"awk 'match($0, /"id":[0-9]+/) {
        id = substr($0, RSTART + 5, RLENGTH - 5);
        message = ($0 ~ /"method":"first"/) ? "first" : "second";
        printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"message\":\"%s\"}}\n", id, message);
        fflush();
    }'"#;
    let mut translator = Command::new(env!("CARGO_BIN_EXE_context-forge-translate"))
        .args([
            "--stdio",
            child_fixture,
            "--expose-streamable-http",
            "--expose-sse",
            "--keepAlive",
            "0",
            "--port",
            &address.port().to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let root = format!("http://{address}");
    wait_for_translator(&client, &root).await;

    let call = |method: &str| json!({"jsonrpc":"2.0","id":"shared-id","method":method});
    let post = |url: &str, method: &str| {
        client
            .post(url)
            .header("content-type", "application/json")
            .body(call(method).to_string())
            .send()
    };
    let mcp = format!("{root}/mcp");
    let (first, second) = tokio::join!(post(&mcp, "first"), post(&mcp, "second"));
    for (reply, message) in [(first.unwrap(), "first"), (second.unwrap(), "second")] {
        assert_eq!(reply.status(), StatusCode::OK);
        let reply: Value = serde_json::from_slice(&reply.bytes().await.unwrap()).unwrap();
        assert_eq!(
            reply,
            json!({"jsonrpc":"2.0","id":"shared-id","result":{"message":message}})
        );
    }

    let mut first = client.get(format!("{root}/sse")).send().await.unwrap();
    let mut second = client.get(format!("{root}/sse")).send().await.unwrap();
    let mut first_buffer = Vec::new();
    let mut second_buffer = Vec::new();
    let first_url = next_data(&mut first, &mut first_buffer).await;
    let second_url = next_data(&mut second, &mut second_buffer).await;
    assert_ne!(first_url, second_url);
    let (a, b) = tokio::join!(post(&first_url, "first"), post(&second_url, "second"));
    for reply in [a.unwrap(), b.unwrap()] {
        assert_eq!(reply.status(), StatusCode::ACCEPTED);
        assert_eq!(reply.text().await.unwrap(), "forwarded");
    }
    for (reply, buffer, message) in [
        (&mut first, &mut first_buffer, "first"),
        (&mut second, &mut second_buffer, "second"),
    ] {
        let body: Value = serde_json::from_str(&next_data(reply, buffer).await).unwrap();
        assert_eq!(
            body,
            json!({"jsonrpc":"2.0","id":"shared-id","result":{"message":message}})
        );
    }
    translator.kill().await.unwrap();
}

#[tokio::test]
async fn translator_isolates_dynamic_environment_across_sse_clients() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let child = r#"awk 'match($0, /"id":[0-9]+/) {
        id = substr($0, RSTART + 5, RLENGTH - 5);
        value = ("FIXTURE_HEADER" in ENVIRON) ? ENVIRON["FIXTURE_HEADER"] : "unset";
        printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"value\":\"%s\"}}\n", id, value);
        fflush();
    }'"#;
    let mut translator = Command::new(env!("CARGO_BIN_EXE_context-forge-translate"))
        .args([
            "--stdio",
            child,
            "--expose-sse",
            "--expose-streamable-http",
            "--keepAlive",
            "0",
            "--port",
            &address.port().to_string(),
            "--enable-dynamic-env",
            "--header-to-env",
            "X-Fixture=FIXTURE_HEADER",
        ])
        .env("FIXTURE_HEADER", "ambient")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let root = format!("http://{address}");
    wait_for_translator(&client, &root).await;
    let feed = format!("{root}/sse");
    let mut first = client
        .get(&feed)
        .header("x-fixture", "first")
        .send()
        .await
        .unwrap();
    let mut second = client
        .get(&feed)
        .header("x-fixture", "second")
        .send()
        .await
        .unwrap();
    let mut first_buffer = Vec::new();
    let mut second_buffer = Vec::new();
    let first_url = next_data(&mut first, &mut first_buffer).await;
    let second_url = next_data(&mut second, &mut second_buffer).await;

    let send = |url: &str| {
        client
            .post(url)
            .body(json!({"jsonrpc":"2.0","id":1,"method":"ping"}).to_string())
    };
    let (a, b) = tokio::join!(send(&first_url).send(), send(&second_url).send());
    for reply in [a.unwrap(), b.unwrap()] {
        assert_eq!(reply.status(), StatusCode::ACCEPTED);
    }
    let first_value: Value =
        serde_json::from_str(&next_data(&mut first, &mut first_buffer).await).unwrap();
    let second_value: Value =
        serde_json::from_str(&next_data(&mut second, &mut second_buffer).await).unwrap();
    assert_eq!(first_value["result"]["value"], "first");
    assert_eq!(second_value["result"]["value"], "second");

    let (a, b) = tokio::join!(
        send(&first_url).header("x-fixture", "changed").send(),
        send(&second_url).send(),
    );
    for reply in [a.unwrap(), b.unwrap()] {
        assert_eq!(reply.status(), StatusCode::ACCEPTED);
    }
    let first_value: Value =
        serde_json::from_str(&next_data(&mut first, &mut first_buffer).await).unwrap();
    let second_value: Value =
        serde_json::from_str(&next_data(&mut second, &mut second_buffer).await).unwrap();
    assert_eq!(first_value["result"]["value"], "changed");
    assert_eq!(second_value["result"]["value"], "second");

    let reply = send(&format!("{root}/mcp")).send().await.unwrap();
    let reply: Value = serde_json::from_slice(&reply.bytes().await.unwrap()).unwrap();
    assert_eq!(reply["result"]["value"], "unset");
    translator.kill().await.unwrap();
}

async fn wait_for_translator(client: &Client, root: &str) {
    timeout(Duration::from_secs(3), async {
        loop {
            if client
                .get(format!("{root}/healthz"))
                .send()
                .await
                .is_ok_and(|reply| reply.status().is_success())
            {
                break;
            }
            sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .expect("translator starts");
}

async fn next_data(reply: &mut Response, buffer: &mut Vec<u8>) -> String {
    loop {
        while let Some(end) = buffer.iter().position(|&byte| byte == b'\n') {
            let line: Vec<_> = buffer.drain(..=end).collect();
            if let Some(data) = line.strip_prefix(b"data: ") {
                return std::str::from_utf8(data.trim_ascii_end())
                    .unwrap()
                    .to_owned();
            }
        }
        buffer.extend_from_slice(&reply.chunk().await.unwrap().expect("SSE data frame"));
    }
}
