# Port decisions

## Native database history

The native schema ledger records revisions in the same transaction as their
schema changes. Keep applied revision definitions stable and append subsequent
schema changes as new revisions. Databases from the pinned gateway retain
their existing Alembic history.

## CEL response filters

Use the MIT-licensed `cel` crate starting with v0.16.1. This release counts
operator chains toward the parser depth limit and fixes the associated
stack overflow. [CEL release](https://github.com/cel-rust/cel-rust/releases/tag/v0.16.1)

Start one Rust subprocess per filter check or evaluation. Process startup adds
latency. It gives each operation a killable deadline and an empty environment.
The gateway limits concurrent workers, input and output sizes, and comprehension
iterations. Linux also enforces a per-worker address-space limit.

## Reference release and runtime

Use the public v1.1.2 source at the commit in [the map](MAP.md). Run it only as an external behavior reference. Use a separate public GitHub repository under `lucarlig` for the Rust code. Start the Rust server directly with Axum and Tokio. Use SQLx pools for SQLite and PostgreSQL.

## Equivalence

Compare HTTP status, relevant headers, bodies, and external effects on synthetic fixtures. Exercise MCP sessions and streaming with black-box protocol tests. The generated rust-anything HTTP proxy reads the entire response body, which delays SSE delivery until the stream ends.

Use the captured probe profile to verify the probe handlers. The reference profile disables rate limiting, correlation IDs, and security headers. Verify default middleware responses when the middleware moves to Rust.

The visibility policy rejects malformed claims that upstream can treat as broader scopes. It discards blank and numeric team IDs. Database identity and membership remain the authority for session tokens. JWT verification and RBAC must also pass before the gateway grants an action.

Delegate JWT signature verification to jsonwebtoken with RustCrypto. Use Jiff's bundled IANA rules for token access windows. The bundle supplies consistent timezone rules across images and increases the binary size.

The server reports its Rust version and advertises implemented MCP capabilities. The replay normalizes the runtime header and JSON key order. Keep the original tool and initialization responses in the fixtures.

Use `rmcp` 3.12 protocol models and its stateless Streamable HTTP server. Authorize requests in Axum before dispatch. Resolve the schema for tool argument headers within the caller's visibility and permissions. Use pinned DNS resolution and bounded HTTP reads for upstream requests. Try modern discovery before legacy initialization in automatic mode. Send each tool call once. [rmcp release](https://github.com/modelcontextprotocol/rust-sdk/releases/tag/rmcp-v3.12.0)

Bind MCP list cursors to caller, team scope, method, and virtual server. Derive the signing key from the configured gateway secret or generate it at startup for an unconfigured process.

With Redis affinity enabled, route session DELETE to the owning worker until the session expires. Return success only after the worker invalidates the session. The pinned gateway sometimes acknowledges a peer DELETE while leaving the original session active. [Two-worker reference observations](replay/mcp-stateful/README.md#event-resumption)
