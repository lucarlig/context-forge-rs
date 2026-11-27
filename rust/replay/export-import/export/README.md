# Configuration export

The SQLite and PostgreSQL recordings each cover 14 requests against ContextForge v1.1.2. They cover full and selective export, both route prefixes, credentials, dependencies, filters, and denied requests. Rust matched all 14 recordings on each database backend. The SQLite replay also passed against a copy of the upstream database.

Both routes require `admin.export`. Roots also require unrestricted platform administrator authority. The exporter uses the caller's catalog visibility for entities and linked tools. Full export uses tool names for server links. Selective export uses tool IDs. Select tools, gateways, and servers by ID, prompts by ID or invocation name, and resources and roots by URI.

The export omits SigV4 gateways and tools, and excludes federated MCP tools from the tool list. Rust authenticates ciphertext before exporting it. Rust masks legacy plaintext header values and excludes unexpected fields from encrypted header envelopes. The pinned selective endpoint can return plaintext headers and out-of-scope linked tool IDs. Rust also orders selective records by ID. The pinned PostgreSQL query can return a different order when its query plan changes.

The comparison normalizes the runtime timestamp and listener port. It compares response status and JSON and omits CORS and deprecated-route headers. The replay script creates a temporary copy of the recordings and signs fresh bearer tokens for the synthetic accounts.

```sh
cargo build --locked --bin context-forge-rs
sh rust/replay/export-import/export/replay.sh "$PWD/target/debug/context-forge-rs"
```

For PostgreSQL, set `DATABASE_URL` to an empty test database and pass `postgres` after the binary path.
