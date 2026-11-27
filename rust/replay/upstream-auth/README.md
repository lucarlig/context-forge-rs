# Authenticated upstream MCP

The pinned gateway was run with four fixtures that require Basic, bearer, custom-header, or query parameter credentials on initialization and tool invocation. The Rust gateway returned the same masked registration fields and matched all four invocation recordings using both a database initialized by Rust and a database populated by the pinned gateway. Live native registration and invocation also passed on PostgreSQL.

Set `AUTH_ENCRYPTION_SECRET` to the secret used to seal the database values. Rust writes the v1.1.2 AES-256-GCM format for new Basic, bearer, and custom-header credentials. The pinned gateway stores a custom-header map as an object. Rust reads that format for existing rows and encrypts newly registered custom-header credentials.

Query parameter authentication additionally requires `INSECURE_ALLOW_QUERYPARAM_AUTH=true`. Set `INSECURE_QUERYPARAM_AUTH_ALLOWED_HOSTS` to limit the feature to specific hosts. The gateway validates the host during registration and invocation, and stores the configured parameter value encrypted in `auth_query_params`.

Configured header forwarding and explicit upstream authorization use the same destination checks as stored credentials. [Header forwarding recordings](headers/README.md)

Set `IDENTITY_PROPAGATION_ENABLED=true` to forward authenticated user identity. The `IDENTITY_PROPAGATION_MODE` setting selects `headers`, `meta`, or `both`. Gateways may override the setting with `identityPropagation`. Claim signing uses a dedicated `IDENTITY_CLAIMS_SECRET` and binds the HS256 token to the gateway ID for 60 seconds. [Identity forwarding observations](identity.md)

Direct-proxy mode supports live tool calls and resource reads on root and virtual-server MCP routes. [Direct-proxy recordings](direct-proxy/README.md)

For replay, register four public Streamable HTTP servers named `basic`, `bearer`, `headers`, and `query` in the fixture database. Each exposes an `echo` tool and prefixes its result with the gateway name. Use synthetic credentials that the upstream fixture requires and that the gateway stores using the configured encryption secret.

```sh
MCP_REQUIRE_AUTH=false MCP_INBOUND_PROTOCOL_MODE=legacy MCP_CLIENT_CONNECT_MODE=legacy \
  USE_STATEFUL_SESSIONS=false SSRF_ALLOW_LOCALHOST=true DATABASE_URL="$FIXTURE_DATABASE_URL" \
  INSECURE_ALLOW_QUERYPARAM_AUTH=true \
  rust-anything app replay rust/replay/upstream-auth --build "$PWD/target/debug/context-forge-rs"
```
