# ContextForge RS

ContextForge RS is a standalone Rust rewrite of the [ContextForge gateway](https://github.com/IBM/mcp-context-forge). The reference release is [v1.1.2](https://github.com/IBM/mcp-context-forge/releases/tag/v1.1.2). See the [port map](rust/MAP.md) for implementation status.

## Full-port progress

`██████████████████░░░░░░░` **72%**

18 of 25 [port milestones](rust/MAP.md#milestones) are verified. Each milestone counts equally.

The Rust binary serves health and readiness probes, modern and legacy MCP, scoped tool invocation, resource reads, prompt retrieval, and completions. Modern clients can subscribe to catalog changes and visible upstream resource updates. Register a Streamable HTTP or legacy SSE upstream through `POST /gateways` or `POST /v1/mcp-servers`. The gateway uses [rmcp](https://github.com/modelcontextprotocol/rust-sdk) protocol models and the modern Streamable HTTP server.

```sh
cargo run --locked
```

The binary listens on `127.0.0.1:4444` and uses `sqlite:///./mcp.db` by default. Set `HOST`, `PORT`, and `DATABASE_URL` to configure it. SQLite paths follow the upstream SQLAlchemy URL format. PostgreSQL URLs accept the upstream `postgresql+psycopg://` scheme.

The gateway, migration, configuration export and import, and credential rotation commands read `.env` from the working directory. Process variables take precedence. The server's `--env-file PATH` overlays application settings from another file. Set the bind address and port through `.env`, process variables, or listener flags.

`--host` and `--port` override the listener environment variables. The gateway uses `MCG_HOST` and `MCG_PORT` when their canonical variables are unset. Use `--port 0` to select an available port. On Unix, `--uds /path/to/gateway.sock` binds a filesystem socket with permissions set by the process umask.

Use `--fd 3` when a supervisor passes a TCP or Unix stream socket as descriptor 3. The inherited socket takes precedence over the bind options. The supervisor retains ownership of any Unix socket path.

### Containers

The image contains the gateway and `context-forge-translate`. It runs as UID 10001 and checks `/ready` over TCP on `PORT`. For a fresh deployment, generate the gateway secrets in `.env`.

```sh
cargo run --locked -- init-secrets --patch-env .env
docker build -f Containerfile -t context-forge-rs:local .
docker run --rm --env-file .env -p 127.0.0.1:4444:4444 \
  -e DATABASE_URL=sqlite:////var/lib/context-forge/mcp.db \
  --mount source=context-forge-data,target=/var/lib/context-forge \
  context-forge-rs:local
```

The named volume stores the SQLite database. For PostgreSQL and Redis, add the following settings to `.env`. Use the same URL-safe password in both values.

```dotenv
POSTGRES_PASSWORD=replace-with-a-random-hex-password
DATABASE_URL=postgresql://contextforge:replace-with-a-random-hex-password@postgres:5432/contextforge
```

```sh
docker compose up --build -d --wait
```

Compose runs `context-forge-rs migrate` before starting the gateway. PostgreSQL and Redis use named volumes and private service addresses. Set `CONTEXT_FORGE_PORT` to change the host port.

### Database and configuration commands

Use `context-forge-rs --config-schema [OUTPUT]` to print or save the configuration JSON Schema for the pinned ContextForge release.

`context-forge-rs init-secrets` writes `.env.secrets` by default. Use `--output` to choose another file, `--force` to overwrite it, or `--stdout` to print the generated values. On Unix, files written by this command have mode `0600`.

Run `context-forge-rs migrate` to prepare the native database schema before starting the gateway. Set `MCPGATEWAY_SKIP_MIGRATIONS=true` on gateway workers to require a current native schema at startup.

Set `MCPGATEWAY_BEARER_TOKEN` to use the configuration CLI. Both commands connect to the gateway at `HOST` and `PORT`.

```sh
context-forge-rs export --types tools --out backup.json
context-forge-rs import backup.json --dry-run
```

MCP requires a signed bearer token from an active account by default. Set `JWT_SECRET_KEY` for HMAC verification or set `JWT_ALGORITHM` and `JWT_PUBLIC_KEY_PATH` for asymmetric verification. Authenticated MCP currently reads accounts and roles from an existing v1.1.2 database or a test fixture. Configure `MCP_ALLOWED_ORIGINS` and `MCP_ALLOWED_HOSTS` to enforce ingress allowlists.

The registration path accepts `STREAMABLEHTTP` and `SSE` upstreams. Set `AUTH_ENCRYPTION_SECRET` to register Basic, bearer, custom-header, or query parameter credentials. For a local fixture, set `SSRF_ALLOW_LOCALHOST=true` to allow loopback connections. Readiness checks Redis when `CACHE_TYPE=redis` and `REDIS_URL` is set. [Upstream authentication](rust/replay/upstream-auth/README.md)

Set `MCPGATEWAY_GRPC_ENABLED=true` and `MCPGATEWAY_ADMIN_API_ENABLED=true` to register gRPC services through `/admin/grpc`. The gateway discovers methods through server reflection and exposes unary calls through MCP. [gRPC verification](rust/HANDOFF.md#grpc-federation)

Run `context-forge-rs rotate-credentials --dry-run` to check an offline credential rotation before applying it. The command supports SQLite and PostgreSQL. [Rotation settings and verification](rust/HANDOFF.md#credential-storage-and-rotation)

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
