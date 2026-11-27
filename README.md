# ContextForge RS

ContextForge RS is a standalone Rust rewrite of the [ContextForge gateway](https://github.com/IBM/mcp-context-forge). The reference release is [v1.1.2](https://github.com/IBM/mcp-context-forge/releases/tag/v1.1.2). See the [port map](rust/MAP.md) for implementation status.

## Full-port progress

`█████████░░░░░░░░░░░░░░░░` **36%**

9 of 25 [port milestones](rust/MAP.md#milestones) are verified. Each milestone counts equally.

The Rust binary serves health and readiness probes, modern and legacy MCP, scoped tool invocation, resource reads, prompt retrieval, and completions. Modern clients can subscribe to catalog changes and visible upstream resource updates. Register a Streamable HTTP or legacy SSE upstream through `POST /gateways` or `POST /v1/mcp-servers`. The gateway uses [rmcp](https://github.com/modelcontextprotocol/rust-sdk) protocol models and the modern Streamable HTTP server.

```sh
cargo run --locked
```

The binary listens on `127.0.0.1:4444` and uses `sqlite:///./mcp.db` by default. Set `HOST`, `PORT`, and `DATABASE_URL` to configure it. SQLite paths follow the upstream SQLAlchemy URL format. PostgreSQL URLs accept the upstream `postgresql+psycopg://` scheme.

MCP requires a signed bearer token from an active account by default. Set `JWT_SECRET_KEY` for HMAC verification or set `JWT_ALGORITHM` and `JWT_PUBLIC_KEY_PATH` for asymmetric verification. Authenticated MCP currently reads accounts and roles from an existing v1.1.2 database or a test fixture. Configure `MCP_ALLOWED_ORIGINS` and `MCP_ALLOWED_HOSTS` to enforce ingress allowlists.

The registration path accepts `STREAMABLEHTTP` and `SSE` upstreams. Set `AUTH_ENCRYPTION_SECRET` to register Basic, bearer, custom-header, or query parameter credentials. For a local fixture, set `SSRF_ALLOW_LOCALHOST=true` to allow loopback connections. Readiness checks Redis when `CACHE_TYPE=redis` and `REDIS_URL` is set. [Upstream authentication](rust/replay/upstream-auth/README.md)

The gateway negotiates modern and legacy MCP by default. Set `MCP_INBOUND_PROTOCOL_MODE=legacy` to accept legacy versions only. Set `MCP_CLIENT_CONNECT_MODE=legacy` to use legacy initialization for all upstreams.

Set `USE_STATEFUL_SESSIONS=true` to enable legacy sessions and `JSON_RESPONSE_ENABLED=false` to stream legacy POST replies over SSE. With `CACHE_TYPE=redis` and `REDIS_URL` set, passive GET replays retained events through any worker, including after the session's original worker exits. Set `MCPGATEWAY_SESSION_AFFINITY_ENABLED=true` to also route POST and DELETE to the worker that owns the session. The [stateful MCP notes](rust/replay/mcp-stateful/README.md) cover routing leases, delivery, and resumption.

Legacy `/sse` connections accept messages from any worker when `CACHE_TYPE=database` uses a shared database or `CACHE_TYPE=redis` uses a shared Redis server. The optional `/ws` JSON-RPC relay is enabled by `MCPGATEWAY_WS_RELAY_ENABLED=true`. Run `context-forge-translate` to bridge MCP between stdio, SSE, and Streamable HTTP. [Legacy SSE](rust/replay/legacy-sse/README.md) · [WebSocket](rust/replay/websocket/README.md) · [Stdio translation](rust/replay/translate-stdio/README.md)

```sh
cargo test --locked --workspace
cargo build --locked --workspace
DATABASE_URL=sqlite:///:memory: rust-anything app replay . --build ./target/debug/context-forge-rs
```

See [the replay handoff](rust/HANDOFF.md) for MCP fixtures and replay results.

[Apache 2.0 license](LICENSE)
