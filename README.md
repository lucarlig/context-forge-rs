# ContextForge RS

ContextForge RS is a standalone Rust rewrite of the [ContextForge gateway](https://github.com/IBM/mcp-context-forge). The reference release is [v1.1.2](https://github.com/IBM/mcp-context-forge/releases/tag/v1.1.2). See the [port map](rust/MAP.md) for implementation status.

The current binary serves `GET /health`, `GET /ready`, and the legacy stateless MCP handshake at `/mcp` and `/mcp/`. Readiness checks Redis when `CACHE_TYPE=redis` and `REDIS_URL` is set.

```sh
cargo run --locked
```

The binary listens on `127.0.0.1:4444` and uses `sqlite:///./mcp.db` by default. Set `HOST`, `PORT`, and `DATABASE_URL` to configure it. SQLite paths follow the upstream SQLAlchemy URL format. PostgreSQL URLs accept the upstream `postgresql+psycopg://` scheme.

MCP requires a signed bearer token from an active account by default. Set `JWT_SECRET_KEY` for HMAC verification or set `JWT_ALGORITHM` and `JWT_PUBLIC_KEY_PATH` for asymmetric verification. Authenticated MCP currently reads accounts and roles from an existing v1.1.2 database or a test fixture. Configure `MCP_ALLOWED_ORIGINS` and `MCP_ALLOWED_HOSTS` to enforce ingress allowlists.

```sh
cargo test --locked --workspace
cargo build --locked --workspace
DATABASE_URL=sqlite:///:memory: rust-anything app replay . --build ./target/debug/context-forge-rs
```

See [the replay handoff](rust/HANDOFF.md) for the legacy MCP fixture and known differences.

[Apache 2.0 license](LICENSE)
