# Legacy SSE ingress

The pinned v1.1.2 gateway and the Rust binary expose a separate legacy SSE transport at `GET /sse` and `GET /servers/{id}/sse`. The first SSE event advertises the absolute message URL and a server-generated session ID. Authorized POST requests return HTTP 202 and deliver replies on the open stream.

The live fixture verified initialization, the initial keepalive and notification sequence, ping, resource and prompt listings, unknown methods, and disconnect cleanup on both routes. Initialization reports the Rust version in the native gateway. The Rust integration tests also verify that another account cannot post to the stream and that a virtual-server session stays bound to its route.

With `CACHE_TYPE=redis` and `REDIS_URL` configured, the message POST may arrive at a different worker from the SSE connection. Two live workers delivered the same replies as two pinned workers on both root and virtual-server routes. Rust removes the shared queue and its ownership record when the stream closes. In the pinned capture, the other worker continued accepting POSTs during the two-second disconnect check.

With `CACHE_TYPE=database`, two workers delivered the same replies against SQLite and PostgreSQL in both gateways. The Rust shared queues enforce the connection owner's identity and virtual-server scope when they accept a message. `CACHE_TYPE=memory` keeps Rust sessions local to the worker. `CACHE_TYPE=none` returns HTTP 404 on POST in both gateways.

The static cases replay authentication failures with global auth enabled and Streamable HTTP auth disabled. Both binaries require a principal with permission to use the legacy SSE connection. With global auth disabled, the pinned gateway returns HTTP 403 for an anonymous connection.

```sh
AUTH_REQUIRED=true MCP_REQUIRE_AUTH=false USE_STATEFUL_SESSIONS=false \
  DATABASE_URL="sqlite:///$FIXTURE_DATABASE" \
  rust-anything app replay rust/replay/legacy-sse --build "$PWD/target/debug/context-forge-rs"
```
