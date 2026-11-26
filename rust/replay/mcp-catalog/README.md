# Resource and prompt catalogs

The pinned v1.1.2 gateway registered an unauthenticated Streamable HTTP fixture that exposed one resource, one URI template, and one prompt. The gateway prefixed the names with `fixture-` and preserved the resource URI and URI template. Modern list results also included a private cache scope, a 300-second TTL, and server metadata.

The pinned gateway matched all six recordings. The Rust binary matched all three legacy cases on SQLite and PostgreSQL. The three modern cases on both backends differ only in the server version. The live Rust gateway test covers pagination, virtual-server membership, team visibility, and cursor rejection across methods.

Start the Rust binary once against an isolated SQLite database to create the schema. Load [the fixture](fixture.sql) and point the replay at the same database. The list methods read stored metadata and need no running upstream.

```sh
sqlite3 "$FIXTURE_DATABASE" < rust/replay/mcp-catalog/fixture.sql
USE_STATEFUL_SESSIONS=false MCP_INBOUND_PROTOCOL_MODE=auto MCP_REQUIRE_AUTH=false \
  DATABASE_URL="sqlite:///$FIXTURE_DATABASE" \
  rust-anything app replay rust/replay/mcp-catalog --build "$PWD/target/debug/context-forge-rs"
```

Native registration discovers resources, URI templates, and prompts and stores them in the same transaction as the gateway and tools. Native registrations of the live fixture produced the recorded list results on SQLite and PostgreSQL. The registration response preserves the reference's zero component counts. A Rust integration test also covers discovery across resource pages and upstreams that omit the tools capability.

Both gateways route a resource URI matching a stored template when the exact URI is absent. Both resolve `fixture-welcome` to the upstream prompt `welcome` and reject an unprefixed downstream prompt lookup. The Rust test covers a modern resource input round trip and checks that callers must declare elicitation before receiving the request. Authenticated resource reads use a private cache scope.

The local content suite under `content/` uses [a separate SQLite fixture](content/fixture.sql) for plain text, binary content, and a rendered prompt. The pinned gateway matched all eight recordings. Rust matched five, including the four legacy requests and the modern missing-argument error. The three successful modern responses differ only in the server version. Load `content/fixture.sql` and change the replay path above to `rust/replay/mcp-catalog/content` to run this suite.

The logging suite under `logging/` exercises valid legacy log levels, invalid legacy parameters, and the modern method-not-found response. Both gateways matched all 12 recordings. The Rust integration test also verifies runtime filter changes and covers an authenticated token whose scopes exclude `admin.system_config`. In permissive MCP mode the reference accepts anonymous level changes. Replay this suite with an empty disposable SQLite database and the same environment as the list cases.

The completion suite under `completion/` covers local prompt enum matches, resource URI suggestions, and invalid requests on legacy and modern MCP. The pinned gateway matched all 16 cases. Rust matched 14, with only the server version differing in the two successful modern responses. Load [the completion fixture](completion/fixture.sql) into a migrated SQLite database to replay. Native HTTP runs on SQLite and PostgreSQL also forwarded completion requests for prefixed prompts and URI templates, preserved prior argument values, and returned the reference error when the upstream omitted completion support. Virtual-server routes apply the same catalog scope to completion targets and resource suggestions as they do to catalog reads.

The `prompt-validation/` suite covers stored JSON Schema validation, the distinction between malformed MCP parameters and schema failures, and HTML escaping and whitespace handling in rendered messages. The pinned gateway matched all 14 cases. Rust matched 12, with only the server version differing in the two successful modern responses. Load [the prompt validation fixture](prompt-validation/fixture.sql) into a migrated SQLite database to replay. The native validator resolves schema references offline. The renderer enforces execution and output limits and uses MiniJinja for templates.

The `subscriptions/` suite covers protocol and media negotiation for `subscriptions/listen` and the availability of `resources/subscribe` on Streamable HTTP. Both gateways matched all five cases. Replay with a disposable SQLite database and the same environment as the list cases. Live SSE runs verify the acknowledgment, three list changes after gateway registration, and cancellation followed by completion at token expiry. The Rust integration test covers the per-caller stream limit and graceful shutdown. Registration invalidations are scoped to callers who can see the new gateway on the root catalog. Relay of individual upstream resource updates remains open.
