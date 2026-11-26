# Stdio server translation

The `context-forge-translate` executable exposes an MCP subprocess over legacy SSE, Streamable HTTP, or both. With no exposure flags it uses SSE. The subprocess command is split into arguments and executed directly.

```sh
cargo run --locked --bin context-forge-translate -- \
  --stdio /path/to/mcp-server --expose-sse --expose-streamable-http --port 8000
```

The pinned and native translators matched all eight rust-anything cases with a deterministic child process. Live connections also verified that an SSE POST returns HTTP 202 and the child reply arrives on the open stream. The Rust integration test starts the actual binary and verifies that concurrent HTTP and SSE clients may reuse the same request ID independently.

For replay, use a child that identifies itself as `stdio-fixture` version `1`, exposes `echo`, and returns the supplied `message` as text content. The fixture should write newline-delimited JSON-RPC to stdout and send diagnostics to stderr. Configure the reference launcher to serve both transports at the supplied `PORT`.

```sh
rust-anything app replay rust/replay/translate-stdio \
  --build "$PWD/target/debug/context-forge-translate --stdio /path/to/stdio-fixture --expose-sse --expose-streamable-http --port {port}"
```

The pinned translator's exposed `POST /mcp` waits for a correlated JSON response under either `--stateless` or `--jsonResponse` setting. The Rust binary accepts both flags and implements that response behavior. Remote transport connections and dynamic environment mapping are still in progress.
