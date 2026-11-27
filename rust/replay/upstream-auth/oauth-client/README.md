# OAuth client credentials

The pinned and Rust gateways requested a token during discovery and again on tool invocation. The token fixture checked `grant_type`, `scope`, and `audience` and accepted three client authentication methods. They were `client_secret_post`, `client_secret_basic`, and `none`. The Basic fixture used spaces and punctuation in the client credentials to check their encoding.

A configured client secret is masked in the gateway response and encrypted in the pinned Argon2id and Fernet format in the database. All three invocation replays passed against databases populated by both gateways. Native live registration and invocation also passed on PostgreSQL.

The Rust gateway also obtains a client credentials token on direct-proxy tool calls for legacy and modern MCP. The pinned gateway obtained a token through the cached tool path and made its live direct-proxy request without one. The protected upstream rejected that direct request.

The `private_key_jwt` method signs a new assertion for every token request. [Signed client assertion recordings](assertion/README.md)

For replay, register public Streamable HTTP gateways named `oauthpost`, `oauthbasic`, and `oauthpublic` using a fixture token endpoint and an upstream that requires its bearer token. Each upstream exposes an `echo` tool that prefixes its result with the gateway name. Set `AUTH_ENCRYPTION_SECRET` to the key used when registering the gateways.

```sh
MCP_REQUIRE_AUTH=false MCP_INBOUND_PROTOCOL_MODE=legacy MCP_CLIENT_CONNECT_MODE=legacy \
  USE_STATEFUL_SESSIONS=false SSRF_ALLOW_LOCALHOST=true DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/upstream-auth/oauth-client --build "$PWD/target/debug/context-forge-rs"
```
