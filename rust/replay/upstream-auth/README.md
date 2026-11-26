# Authenticated upstream MCP

The pinned gateway was run with three fixtures that require Basic, bearer, or custom-header credentials on initialization and tool invocation. The Rust gateway returned the same masked registration fields and passed all three invocation replays using both a database initialized by Rust and a database populated by the pinned gateway. Live native registration and invocation also passed on PostgreSQL.

Set `AUTH_ENCRYPTION_SECRET` to the secret used to seal the database values. Rust writes the v1.1.2 AES-256-GCM format for new Basic, bearer, and custom-header credentials. The pinned gateway stores a custom-header map as an object. Rust reads that format for existing rows and encrypts newly registered custom-header credentials.

For replay, register three public Streamable HTTP servers named `basic`, `bearer`, and `headers` in the fixture database. Each exposes an `echo` tool and prefixes its result with the gateway name. Use synthetic credentials that the upstream fixture requires and that the gateway stores using the configured encryption secret.

```sh
MCP_REQUIRE_AUTH=false MCP_INBOUND_PROTOCOL_MODE=legacy MCP_CLIENT_CONNECT_MODE=legacy \
  USE_STATEFUL_SESSIONS=false SSRF_ALLOW_LOCALHOST=true DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/upstream-auth --build "$PWD/target/debug/context-forge-rs"
```
