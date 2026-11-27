# AWS SigV4 upstream authentication

The pinned gateway and the Rust gateway registered and called an upstream on Streamable HTTP and legacy SSE. The fixture verified the signature against the method, URL, payload, and temporary session token. Both gateways returned HTTP 422 when the fixture refused an invalid signing key or the registration supplied the REST-only `unsigned_payload` option.

Registration masks `secret_access_key` and `session_token` and encrypts them individually using the database credential cipher. Rust replays both calls with records written by Rust and by the pinned gateway. Native Streamable HTTP registration and invocation also passed on PostgreSQL.

For replay, register a public gateway named `sigv4` with a signature-validating fixture that exposes an `echo` tool and prefixes its result with `sigv4: `. Use the corresponding upstream transport for each fixture. The request includes a synthetic caller authorization header to check that the gateway sends its own signature.

```sh
MCP_REQUIRE_AUTH=false MCP_INBOUND_PROTOCOL_MODE=legacy MCP_CLIENT_CONNECT_MODE=legacy \
  USE_STATEFUL_SESSIONS=false SSRF_ALLOW_LOCALHOST=true ENABLE_HEADER_PASSTHROUGH=true \
  DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/upstream-auth/sigv4/streamable-http --build "$PWD/target/debug/context-forge-rs"
```
