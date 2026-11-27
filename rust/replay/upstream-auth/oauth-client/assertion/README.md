# OAuth signed client assertions

The pinned and Rust gateways registered and invoked an upstream for each of seven signing algorithms. The token fixture verified the signature, client ID, token URL audience, optional key ID, five-minute expiration, and unique assertion ID. It accepted the retry after returning a temporary error for a valid assertion. Both gateways rejected a 1024-bit RSA key and an EC key submitted for RSA signing before contacting the token endpoint.

The registration response masks the private key and the database stores it in the Argon2id and Fernet envelope. All seven tool calls replayed with databases populated by either gateway.

For replay, register seven public Streamable HTTP gateways named `rs256`, `rs384`, `rs512`, `ps256`, `es256`, `es384`, and `es512`. Each requires an access token from a fixture OAuth provider that validates its client assertion. Each upstream exposes an `echo` tool that prefixes its result with the gateway name. Set `AUTH_ENCRYPTION_SECRET` to the key used to register the gateways.

```sh
MCP_REQUIRE_AUTH=false MCP_INBOUND_PROTOCOL_MODE=legacy MCP_CLIENT_CONNECT_MODE=legacy \
  USE_STATEFUL_SESSIONS=false SSRF_ALLOW_LOCALHOST=true DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/upstream-auth/oauth-client/assertion --build "$PWD/target/debug/context-forge-rs"
```
