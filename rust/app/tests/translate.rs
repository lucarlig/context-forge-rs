// SPDX-License-Identifier: Apache-2.0

use std::{net::TcpListener, process::Stdio, time::Duration};

use reqwest::{Client, Response, StatusCode};
use serde_json::{Value, json};
use tokio::{
    process::Command,
    time::{sleep, timeout},
};

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
