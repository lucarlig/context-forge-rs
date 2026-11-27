# Handoff

Start with [the port map](MAP.md). The source classifier found 77 units, including 11 blocked units. The root Python application and API package are among the blocked units. Port those by behavior using the existing HTTP and protocol tests.

The Rust workspace lives in `rust/app`. The probe and authentication-required cases are in `rust/app-cases`. Replay the original with rust-anything v5.0.1 and a reference launcher named `context-forge-reference-server` on PATH. Bind the original to the supplied `PORT` and use an isolated SQLite database. Set `RATE_LIMITING_ENABLED=false`, `CORRELATION_ID_ENABLED=false`, and `SECURITY_HEADERS_ENABLED=false` for both profiles.

Legacy MCP fixtures live under `rust/replay/mcp-legacy`. Enable legacy inbound mode and stateless JSON responses in the original launcher. Disable MCP authentication for the fixture. Register a deterministic public MCP gateway named `fixture-echo` with an `echo` tool that returns `echo: <message>`. Replay against a Rust gateway with the same fixture database and live upstream.

```sh
MCP_INBOUND_PROTOCOL_MODE=legacy MCP_REQUIRE_AUTH=false SSRF_ALLOW_LOCALHOST=true \
  DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/mcp-legacy --build "$PWD/target/debug/context-forge-rs"
```

The Rust binary matched eight of ten legacy cases, including tool listing and invocation. Both initialization cases differ only in the server version. All three probe and authentication-required cases matched.

The pinned gateway matched all 37 [modern MCP recordings](replay/mcp-modern/README.md). The Rust binary matched 27. Ten cases differ in the reported server version, including two legacy initialization responses. Two of the modern cases also differ in `Vary` because compression remains pending. The live Rust test covers virtual-server discovery, catalog TTL, tool argument headers, and request authorization.

The stateful MCP milestone is verified. The Rust gateway handles legacy session lifecycle, cancellation, progress, POST stream resumption, passive delivery and replay from upstream POST and persistent GET streams, cross-worker session routing through Redis, and modern tool input round trips. It answers legacy upstream pings and returns the pinned gateway's default errors for roots, sampling, and elicitation requests. Two native gateway processes verified Redis passive replay after the owning worker was killed. Initialization still reports Rust release metadata and the capabilities the gateway implements. See the [stateful MCP reference findings](replay/mcp-stateful/README.md) for the replay comparison.

The MCP catalog milestone is verified. Registration discovers resources, URI templates, and prompts. Legacy and modern MCP can list them, read local and federated resources, render prompts with stored JSON Schema validation, and complete prompt arguments and resource URIs. Legacy MCP can change the running log level. Modern subscriptions stream catalog registration changes and relay updates from visible upstream resources. The [catalog recordings](replay/mcp-catalog/README.md) document the database fixtures and verification on SQLite and PostgreSQL.

The transport milestone is verified. The Rust gateway accepts authenticated legacy SSE connections at root and virtual-server endpoints. Redis, SQLite, and PostgreSQL route POST messages between workers to the owning stream. The optional WebSocket relay accepts JSON-RPC over `/ws` with bearer authentication and per-method permissions. Registration accepts legacy SSE upstreams and routes tool invocation, resource reads, and prompt retrieval to them. The `context-forge-translate` binary exposes stdio MCP subprocesses over SSE and Streamable HTTP and bridges remote endpoints to stdout or a stdio child. Its dynamic header mapping runs a separate subprocess for each SSE connection. The gRPC translator modes belong to the gRPC federation milestone. [SSE ingress](replay/legacy-sse/README.md) · [WebSocket](replay/websocket/README.md) · [SSE upstream](replay/upstream-sse/README.md) · [Stdio translation](replay/translate-stdio/README.md)

The upstream authentication milestone is verified. Registration and invocation support Basic, bearer, custom headers, opt-in query credentials, one-time credentials, private CAs, mutual TLS, AWS SigV4, and OAuth client credentials. The token fixture exercised all seven supported signed client assertion algorithms. Live checks covered SQLite and PostgreSQL, and Rust replayed calls using credentials written by the pinned gateway. Header forwarding, signed caller identity, standing resource watches with stored headers, direct tool calls and resource reads, and Redis catalog pagination across workers are verified. Per-user authorization code, token exchange, and dynamic OAuth registration are part of the OAuth and SSO milestone. [Authenticated upstreams](replay/upstream-auth/README.md)

Gateway management now supports listing and detail reads at `/gateways`, `/v1/gateways`, and `/v1/mcp-servers`. SQLite and PostgreSQL passed live pagination and access checks. The read responses mask stored credentials and include catalog counts. [Gateway management read recordings](replay/gateway-management/read/README.md)

Gateway impact previews identify visible virtual servers associated with a gateway. Synchronous deletion removes the gateway, its cached catalog, and their associations in one transaction. Rust verified deletion with both native tables and the pinned gateway's SQLite schema. [Impact and deletion recordings](replay/gateway-management/delete/README.md)

Manual gateway refresh updates the cached catalog while preserving IDs and associations for retained entries. The pinned comparison covered tools alone and a full refresh with resources and prompts. The Rust integration test verifies that a failed discovery preserves the cached tools. [Gateway refresh verification](replay/gateway-management/refresh/README.md)
