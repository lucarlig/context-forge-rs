# Handoff

Start with [the port map](MAP.md). The source classifier found 77 units, including 11 blocked units. The root Python application and API package are among the blocked units. Port those by behavior using the existing HTTP and protocol tests.

API token issuance, updates, revocation, and usage reports are available on
SQLite and PostgreSQL. Public resource scope, stored quota limits, and changes to
credential state are enforced by the gateway.
[Token lifecycle verification](replay/token-management/README.md)

Local login, account lifecycle and recovery, RBAC, and team management are
verified through the versioned and legacy HTTP routes. The team checks covered
capacity enforcement and single-use invitations under concurrent requests.
[Identity management verification](replay/identity-management/README.md)

OAuth authorization and refresh, caller-bound token exchange, dynamic
client registration, and client ID metadata are verified through the
gateway and MCP endpoints. The post-authorization connection probe tests
live tools access with the caller's stored credential. Browser SSO and
external bearer authentication cover provider setup, verification,
account binding, approvals, and group-based access on SQLite and
PostgreSQL. Virtual-server OAuth checks the approved issuer and resource
audience. [Gateway OAuth](replay/gateway-oauth/README.md) ·
[SSO](replay/sso/README.md) ·
[Virtual-server OAuth](replay/server-management/write.md#virtual-server-oauth-access-tokens)

## Credential storage and rotation

The offline `context-forge-rs rotate-credentials` command supports both
database backends. Set `OLD_AUTH_ENCRYPTION_SECRET`,
`NEW_AUTH_ENCRYPTION_SECRET`, and `DATABASE_URL` in the command's
environment. Use `--dry-run` to inspect the rotation before applying it
with the gateway workers stopped.

The verification database exercised 22 encrypted values across direct
envelopes, nested OAuth configuration, AES-GCM scalars, credential
headers, query credentials, and SigV4 credentials. The pinned command
covered the same 20 values outside SigV4. The Rust command preserved
plaintext and already-rotated values, rolled back the entire transaction
on an unreadable ciphertext, and could be repeated without further
changes. The SQLite dry run preserved the database file byte for byte.
On both databases, a restarted Rust gateway retrieved the existing
grant under the new key and invoked its protected upstream tool.

The rust-anything comparison matched all five SQLite cases for exit status and
stored effects. The cases exercised dry runs, rotation, idempotence, rollback,
and rejection of a known weak replacement key. Both databases also passed
live checks for tool SigV4 credentials and OAuth secrets inside nested arrays.
The database values remained readable under the new key. Unwrapped legacy
Fernet tokens require the historical schema migration before rotation.

## Native schema upgrades

The `migrate` command and gateway startup share an atomic native revision history
for identity, catalog, and database-backed SSE. The pinned bootstrap and the
Rust command matched both SQLite replays for the supported tables, database
integrity, and preservation of existing account data. A live PostgreSQL check
adopted the v1.1.2 schema and preserved its Alembic revision and seeded account.
Concurrent migration commands recorded each native revision once on both
backends. SQLite also verified that skip mode rejects an uninitialized
database and starts when the native history is current.

The historical catalog revision adds missing identity, OAuth, and MCP catalog
columns. It namespaces legacy federated resources and records the original
names. It preserves published names already customized by an operator.
Existing OAuth configurations require approval when the revision adds the
approval fields.

Seeded fixtures start at the v1.0.11, v1.1.0, and v1.1.1 revisions in
the pinned Alembic history. All eight replay cases match the reference column
definitions and seeded rows for this revision on SQLite and PostgreSQL.
The cases exercise custom resource name separators and verify idempotence.
A live SQLite check exercises startup migration, resource lookup, and OAuth
approval enforcement. A separate revision translates supported jq paths to CEL.
Eight SQLite and PostgreSQL replays match the pinned Alembic upgrade, including
the treatment of expressions that require a manual rewrite. Additional upstream
tables remain open.

Configuration export supports full and selective requests at both API prefixes.
The pinned 14-case suite matched native SQLite, SQLite initialized by the pinned
gateway, and PostgreSQL. Live checks covered authorization, scoped server links,
and credential masking. [Export recordings](replay/export-import/export/README.md)

Configuration import handles all six entity families, dry runs, job status,
and cleanup at both API prefixes. Live checks cover scoped writes, conflict
strategies, virtual-server tool links, and credential rekeying. [Import recordings](replay/export-import/import/README.md)

The native configuration CLI matched the pinned command in the rust-anything
round-trip replay. It exported a filtered bundle, previewed an import,
applied only the selected tool, and returned exit code 1 for a failed item
or missing authentication. The Rust check also verified Unix output mode `0600`.

## Gateway and protocol verification

The Rust workspace lives in `rust/app`. The probe and authentication-required cases are in `rust/app-cases`. Replay the original with rust-anything v5.0.1 and a reference launcher named `context-forge-reference-server` on PATH. Bind the original to the supplied `PORT` and use an isolated SQLite database. Set `RATE_LIMITING_ENABLED=false`, `CORRELATION_ID_ENABLED=false`, and `SECURITY_HEADERS_ENABLED=false` for both profiles.

Legacy MCP fixtures live under `rust/replay/mcp-legacy`. Enable legacy inbound mode and stateless JSON responses in the original launcher. Disable MCP authentication for the fixture. Register a deterministic public MCP gateway named `fixture-echo` with an `echo` tool that returns `echo: <message>`. Replay against a Rust gateway with the same fixture database and live upstream.

```sh
MCP_INBOUND_PROTOCOL_MODE=legacy MCP_REQUIRE_AUTH=false SSRF_ALLOW_LOCALHOST=true \
  DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/mcp-legacy --build "$PWD/target/debug/context-forge-rs"
```

The Rust binary matched eight of ten legacy cases, including tool listing and invocation. Both initialization cases differ only in the server version. All three probe and authentication-required cases matched.

The pinned gateway matched all 37 [modern MCP recordings](replay/mcp-modern/README.md). The Rust binary matched 27. Ten cases differ in the reported server version, including two legacy initialization responses. Two of the modern cases also differ in `Vary` because compression remains pending. The live Rust test covers virtual-server discovery, catalog TTL, tool argument headers, and request authorization.

The stateful MCP milestone is verified. The Rust gateway handles legacy session lifecycle, cancellation, progress, POST stream resumption, passive delivery and replay from upstream POST and persistent GET streams, cross-worker session routing through Redis, and modern tool input round trips. It answers legacy upstream pings and returns the pinned gateway's default errors for roots, sampling, and elicitation requests. Two native gateway processes verified Redis passive replay after the owning worker was killed. Initialization still reports Rust release metadata and the capabilities the gateway implements. See the [stateful MCP reference findings](replay/mcp-stateful/README.md) for the replay comparison.

The MCP catalog milestone is verified. Registration discovers resources, URI templates, and prompts. Legacy and modern MCP can list them, read local and federated resources, render prompts with stored JSON Schema validation, and complete prompt arguments and resource URIs. Legacy MCP can change the running log level. Modern subscriptions stream catalog registration changes and relay updates from visible upstream resources. The [catalog recordings](replay/mcp-catalog/README.md) document the database fixtures and verification on SQLite and PostgreSQL.

The transport milestone is verified. The Rust gateway accepts authenticated legacy SSE connections at root and virtual-server endpoints. Redis, SQLite, and PostgreSQL route POST messages between workers to the owning stream. The optional WebSocket relay accepts JSON-RPC over `/ws` with bearer authentication and per-method permissions. Registration accepts legacy SSE upstreams and routes tool invocation, resource reads, and prompt retrieval to them. The `context-forge-translate` binary exposes stdio MCP subprocesses over SSE and Streamable HTTP and bridges remote endpoints to stdout or a stdio child. Its dynamic header mapping runs a separate subprocess for each SSE connection. The gRPC translator modes belong to the gRPC federation milestone. [SSE ingress](replay/legacy-sse/README.md) · [WebSocket](replay/websocket/README.md) · [SSE upstream](replay/upstream-sse/README.md) · [Stdio translation](replay/translate-stdio/README.md)

The upstream authentication milestone is verified. Registration and invocation support Basic, bearer, custom headers, opt-in query credentials, one-time credentials, private CAs, mutual TLS, AWS SigV4, and OAuth client credentials. The token fixture exercised all seven supported signed client assertion algorithms. Live checks covered SQLite and PostgreSQL, and Rust replayed calls using credentials written by the pinned gateway. Header forwarding, signed caller identity, standing resource watches with stored headers, direct tool calls and resource reads, and Redis catalog pagination across workers are verified. Per-user authorization code, token exchange, and dynamic OAuth registration are part of the OAuth and SSO milestone. [Authenticated upstreams](replay/upstream-auth/README.md)

Gateway management now supports listing and detail reads at `/gateways`, `/v1/gateways`, and `/v1/mcp-servers`. SQLite and PostgreSQL passed live pagination and access checks. The read responses mask stored credentials and include catalog counts. [Gateway management read recordings](replay/gateway-management/read/README.md)

Gateway impact previews identify visible virtual servers associated with a gateway. Synchronous deletion removes the gateway, its cached catalog, and their associations in one transaction. Rust verified deletion with both native tables and the pinned gateway's SQLite schema. [Impact and deletion recordings](replay/gateway-management/delete/README.md)

Manual gateway refresh updates the cached catalog while preserving IDs and associations for retained entries. The pinned comparison covered tools alone and a full refresh with resources and prompts. The Rust integration test verifies that a failed discovery preserves the cached tools. [Gateway refresh verification](replay/gateway-management/refresh/README.md)

Gateway state changes update the gateway and its catalog together. Reactivation uses the gateway's stored credentials to discover a fresh catalog, and a failed discovery preserves cached entries. [Gateway activation verification](replay/gateway-management/state.md)

Gateway metadata and endpoint updates preserve retained catalog IDs and roll back changes when the new destination fails discovery. SQLite and PostgreSQL passed the live checks. [Gateway update verification](replay/gateway-management/update.md)

Gateway health checks update reachability and refresh the catalog on recovery. The live pinned comparison covered offline invocation, error persistence, and recovery using stored upstream credentials. [Gateway health verification](replay/gateway-management/health.md)

The opt-in asynchronous lifecycle accepts create, update, and delete operations and completes them in a database-backed worker. The live checks verified status transitions and recovery after a worker exited while holding a claim. [Gateway lifecycle verification](replay/gateway-management/lifecycle.md)

The root management APIs support canonically identified network and file roots, configuration export, and an SSE changes stream. The HTTP recordings verify the URI policy and the unrestricted administrator requirement. [Root management verification](replay/root-management/README.md)

The tag APIs aggregate counts and list tagged entities within the caller's catalog scope. SQLite and PostgreSQL matched all ten pinned replays. [Tag management verification](replay/tag-management/README.md)

Resource REST reads cover metadata, templates, and content by ID and URI. The recordings verify filtering and scoped access, including against SQLite created by the pinned gateway. [Resource read verification](replay/resource-management/read/README.md)

Resource REST writes support creation, update, state changes, and deletion. The live checks covered ownership, content limits, and metric retention and purge behavior. [Resource write verification](replay/resource-management/write.md)

Prompt REST reads list the scoped catalog and retrieve or render a prompt by ID
or name. The pinned recordings cover both API prefixes, inactive entries, and
public token scope. [Prompt read verification](replay/prompt-management/read/README.md)

Prompt management supports transactional creation, partial updates, state changes,
and deletion on both databases. The live checks covered template byte limits,
argument order, revision metadata, and virtual-server scoping.
[Prompt write verification](replay/prompt-management/write.md)

Tool REST reads expose scoped metadata, mask headers for callers without edit
access, and support JSONPath projection. Dry-run preview validates arguments and
checks virtual-server membership. [Tool read verification](replay/tool-management/read/README.md)

Tool management supports transactional creation, edits, state changes,
deprecation, and deletion. The comparison verified credential masking and
encrypted persistence on both databases.
[Tool write verification](replay/tool-management/write.md)

The REST federation milestone is verified through the live gateway. MCP
clients can discover and invoke registered REST tools through the scoped
catalog. Requests support URL templates, query and header mappings, JSON,
form data, and multipart bodies. The Rust client pins the upstream destination.
Fourteen scenarios matched the pinned gateway's results and outbound requests
on SQLite and PostgreSQL. A Rust integration test verifies that wrong-team
tokens, read-only tokens, and invalid URL arguments stop before outbound dispatch.
The pinned release stores REST passthrough settings as tool configuration.
MCP REST calls use `TOOL_TIMEOUT` and `REST_RESPONSE_TEXT_MAX_LENGTH`.

REST tools that select SigV4 can use their linked gateway's signer. A 401 triggers
one re-sign or one OAuth token exchange, depending on the authentication flow.
Linked credentials apply only to the gateway's origin. REST calls also honor
stored gateway identity settings. Ten scenarios verify signatures, retry counts,
request bodies, and response limits on SQLite and PostgreSQL. A live check
verifies that only the token endpoint receives the caller's JWT during exchange,
even with authorization forwarding enabled.

REST calls validate arguments before dispatch and preserve the response data
when output validation fails. The replays cover 53 invocation scenarios on
SQLite and PostgreSQL, including nested error paths, local schema references,
older schema drafts, regex subject limits, and malformed HTTP responses. They
also compare catalog schemas and result shaping for 2025 and 2026 clients.
REST calls and dry-run previews validate schemas with `pattern` or
`patternProperties` in isolated Rust workers. `REGEX_WORKERS` limits
concurrency, `REGEX_MAX_SUBJECT_BYTES` limits the validation input, and
`REGEX_TIMEOUT_SECONDS` covers worker startup and execution. The replay
compared timeout and size-limit errors and verified that saturated requests
stop before dispatch on SQLite and PostgreSQL. The worker slot remains
available for the next request after validation finishes.

REST parses UTF-8, UTF-16, and UTF-32 JSON bodies. Text fallback uses the
declared HTTP charset through `encoding_rs`. Ten response cases matched on
SQLite and PostgreSQL, including multibyte JSON, legacy text charsets, and
malformed JSON escapes.

The REST client negotiates gzip, deflate, Brotli, and Zstandard. It honors an
explicit `Accept-Encoding` header, decodes stacked encodings in reverse
order, and applies the body size limit at every layer. Twenty-two compression
and malformed Unicode cases matched on SQLite and PostgreSQL. Two additional
fixtures containing isolated Unicode surrogates still differ. Rust returns
a decoding error. The pinned gateway returns a text representation of the
object.

Authenticated `POST /rpc` and `POST /rpc/` serve tool calls, legacy tool
names, catalog reads, resource reads, prompt retrieval, and initialization.
The gateway applies virtual-server token restrictions before catalog access
or outbound dispatch. Rust Anything compared 45 cases on SQLite and
PostgreSQL. The comparison checks each implementation's release version and
resource subscription advertisement separately. Rust reports its own
release version and leaves resource subscriptions disabled on this route.
The RPC subscription, sampling, and elicitation paths remain open.

`POST /v1/tools/generate-schemas-from-openapi` generates schemas for a selected
operation. It requires `tools.create` and accepts an explicit document URL or
discovers `/openapi.json` on the tool origin. The fetch pins the destination,
rejects redirects, and shares a bounded cache across requests. The replays
cover schema extraction, error paths, and tool registration and invocation
with the returned schemas. The admin route is part of the admin milestone.

REST and cached MCP tools evaluate CEL response filters over `response`.
Tool writes check syntax and free variables before saving. Seventeen scenarios
match the pinned gateway's evaluation and validation on SQLite and PostgreSQL.
A live test verifies that migrated filters run after startup and that the
configured deadline returns a tool error.

## gRPC federation

With `MCPGATEWAY_GRPC_ENABLED=true` and the admin API enabled, POST
`/admin/grpc` to register a service. The gateway saves reflected descriptors
and methods in the database. Authenticated MCP callers can find and invoke
unary methods within their catalog scope.

The pinned replay matched registration, method discovery, descriptor reuse,
protobuf JSON defaults, and invocation errors on SQLite and PostgreSQL.
The gateway keeps healthy methods when a single descriptor lookup fails.
Rust returns the scoped record for `GET /admin/grpc/{id}`. The pinned gateway
returned HTTP 500 in the same fixture.
Registration stores gRPC metadata. The unary caller follows v1.1.2's behavior
for that metadata, which stays in the registry.

The admin API lists, updates, enables, disables, deletes, and re-reflects
services. The lifecycle replay matched page links, stable slugs, duplicate-name
conflicts, stale-method removal, and retained tool IDs on SQLite and PostgreSQL.
A failed reflection keeps the last successful descriptors. Rust omits disabled
services' tools from MCP listings. The pinned gateway listed those tools.
Native tests cover team-scoped writes, concurrent reflection, and dependent
record cleanup.

The TLS fixture matched trusted-root connections and rejected a hostname
mismatch. Rust also passed mutual TLS with a certificate chain and private
key in the gateway's `certs` directory. The v1.1.2 gateway disconnected during
registration in that fixture. Rust rejects credential files outside approved
directories.

`context-forge-translate --grpc HOST:PORT` runs the pinned discovery probe.
Register the service through `/admin/grpc` to expose its methods in MCP. The
CLI replay checked reflection, shutdown on SIGINT, and the exit code and
diagnostic for `--connect-grpc`.

## A2A federation

The gateway registers, lists, reads, and invokes agents through `/a2a` and
`/v1/a2a`. It creates derived MCP tools in the agent registration
transaction. Invocation supports HTTP/JSON and the A2A v0.3 and v1 JSON-RPC
bindings. Outbound requests use the gateway's pinned URL policy and an
agent-specific header allowlist.

The replay matched the pinned gateway on SQLite and PostgreSQL. It checked
name and ID lookup, both request formats, version conversion, upstream bearer
credentials, and invocation through the generated MCP tool. Native tests check
team scope, masked credentials, the feature flag, and outbound header filtering.
Agents registered by the pinned release and their existing bearer credentials
also work through both routes after Rust adopts the SQLite database.
UAID routing and enforced plugin bindings reject invocation before dispatch.

The A2A invocation routes persist task state, history, and artifacts. Agent
owners, team owners, and scoped platform administrators can page through
task summaries, read details, send follow-up messages, and cancel tasks.
Follow-up events store message IDs, part kinds and lengths, and state changes.
The v0.3 and v1 replays matched on SQLite and PostgreSQL. A Rust regression
test verifies that a response arriving after cancellation preserves the
canceled state. The pinned gateway can overwrite that state.
Rust also reads task history and page tokens created by v1.1.2 on SQLite.

The task push notification API validates callback URLs and encrypts bearer
tokens. Identical retries preserve the record, timestamp, and ciphertext.
Rust Anything matched create, rotation, scoped reads, and deletion on SQLite.
The same scenarios matched on PostgreSQL. A Rust test verified concurrent
retries, ownership checks, and blocked callback destinations. A v1.1.2
SQLite database retained its settings and ciphertext across migration and
an identical retry.

Agent updates, deletion, cards, OAuth, streaming with webhook delivery, and
UAID routing remain open.

## Gateway management

The gateway management and catalog milestone is verified. Standing upstream
listeners reconcile the catalog after acknowledgment and apply subsequent
tool, resource, and prompt changes. A two-worker Redis test verified that only
one stream stays open and that the peer takes over during shutdown.
[Standing listener verification](replay/gateway-management/listeners.md)

Virtual-server reads list scoped servers, interfaces, and selected catalog
associations. Public OAuth resource metadata is available for enabled servers
with approved settings. [Virtual-server read verification](replay/server-management/read/README.md)

Virtual-server writes manage associations, interfaces, instructions, and
OAuth approval transactionally. The pinned comparison covered a failed
association, encrypted OAuth settings, and approval of a specific revision.
[Virtual-server write verification](replay/server-management/write.md)

The virtual-server management milestone is verified. The handshake route uses
the running MCP transport and the caller's credentials. OAuth-enabled servers
advertise the protected resource metadata URL in their authentication
challenge. [Handshake verification](replay/server-management/handshake.md)
