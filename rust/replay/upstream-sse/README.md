# Legacy SSE upstreams

The pinned v1.1.2 gateway registered an unauthenticated SSE upstream named `fixture` through `POST /gateways`. Its GET stream advertised a relative POST endpoint. The gateway discovered a tool, a resource, a URI template, and a prompt, then translated both legacy and modern Streamable HTTP requests onto that SSE connection.

The pinned gateway matched all 12 cases. Rust matched the six legacy cases. The six modern results differ only in server version. The native gateway also verified registration, invocation, resource reads, and prompt retrieval against PostgreSQL. A Rust integration test exercises the default SSE transport and rejects a different-origin message endpoint before sending a request to it.

Replay against an isolated database registered with a live SSE fixture. The fixture exposes `echo` with a required string `message`, `fixture://notes/welcome` with text `Fixture contents`, and `welcome` with a required `name` argument. The prompt response describes itself as `Fixture prompt result` and returns `Hello <name>`. Use the metadata in the recorded responses to match list results.

```sh
MCP_REQUIRE_AUTH=false USE_STATEFUL_SESSIONS=false SSRF_ALLOW_LOCALHOST=true \
  DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/upstream-sse --build "$PWD/target/debug/context-forge-rs"
```
