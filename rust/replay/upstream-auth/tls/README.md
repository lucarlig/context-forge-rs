# TLS and mutual TLS

The pinned and Rust gateways registered an HTTPS Streamable HTTP upstream using a private CA in `ca_certificate`. A second upstream also required `client_cert` and `client_key` during the TLS handshake. Both gateways discovered the upstream tool and invoked it through `/mcp`. The Rust mutual TLS registration and invocation passed on SQLite and PostgreSQL.

The private key is masked with `*****` in the registration response and stored in the pinned gateway's Argon2id and Fernet envelope. Rust invoked the mutual TLS upstream using a database populated by the pinned gateway, and the pinned decoder opened a key written by Rust. The fixtures use a locally generated CA and client certificate. The certificate and private key are supplied through registration and are absent from the recordings.

For replay, register a public Streamable HTTP upstream named `tls` and a public mutual TLS upstream named `mtls`. Each exposes an `echo` tool that prefixes its result with the gateway name. Set `AUTH_ENCRYPTION_SECRET` to the key used when registering the gateways.

```sh
for fixture in tls mtls; do
  MCP_REQUIRE_AUTH=false MCP_INBOUND_PROTOCOL_MODE=legacy MCP_CLIENT_CONNECT_MODE=legacy \
    USE_STATEFUL_SESSIONS=false SSRF_ALLOW_LOCALHOST=true DATABASE_URL="$FIXTURE_DATABASE_URL" \
    rust-anything app replay "rust/replay/upstream-auth/tls/$fixture" --build "$PWD/target/debug/context-forge-rs"
done
```
