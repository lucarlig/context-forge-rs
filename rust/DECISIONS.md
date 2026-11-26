# Port decisions

## Reference release and runtime

Use the public v1.1.2 source at the commit in [the map](MAP.md). Run it only as an external behavior reference. Use a separate public GitHub repository under `lucarlig` for the Rust code. Start the Rust server directly with Axum and Tokio. Use SQLx pools for SQLite and PostgreSQL.

## Equivalence

Compare HTTP status, relevant headers, bodies, and external effects on synthetic fixtures. Exercise MCP sessions and streaming with black-box protocol tests. The generated rust-anything HTTP proxy reads the entire response body, which delays SSE delivery until the stream ends.

Use the captured probe profile to verify the probe handlers. The reference profile disables rate limiting, correlation IDs, and security headers. Verify default middleware responses when the middleware moves to Rust.

The visibility policy rejects malformed claims that upstream can treat as broader scopes. It discards blank and numeric team IDs. Database identity and membership remain the authority for session tokens. JWT verification and RBAC must also pass before the gateway grants an action.
