# Legacy SSE ingress

The pinned v1.1.2 gateway and the Rust binary expose a separate legacy SSE transport at `GET /sse` and `GET /servers/{id}/sse`. The first SSE event advertises the absolute message URL and a server-generated session ID. Authorized POST requests return HTTP 202 and deliver replies on the open stream.

The live fixture verified initialization, the initial keepalive and notification sequence, ping, resource and prompt listings, unknown methods, and disconnect cleanup on both routes. Initialization reports the Rust version in the native gateway. The Rust integration test also verifies that another account cannot post to the stream and that a virtual-server session stays bound to its route. Sessions are worker-local.

The static cases replay authentication failures with global auth enabled and Streamable HTTP auth disabled. Both binaries require a principal with permission to use the legacy SSE connection. With global auth disabled, the pinned gateway returns HTTP 403 for an anonymous connection.

```sh
AUTH_REQUIRED=true MCP_REQUIRE_AUTH=false USE_STATEFUL_SESSIONS=false \
  DATABASE_URL="sqlite:///$FIXTURE_DATABASE" \
  rust-anything app replay rust/replay/legacy-sse --build "$PWD/target/debug/context-forge-rs"
```
