# Virtual-server writes

The 26-request comparison against ContextForge v1.1.2 passed on SQLite,
PostgreSQL, and SQLite initialized by the pinned release. The comparison
normalized timestamps, fixture IDs, and the loopback request authority.

The fixture creates a server with a UUID, a tool association, and a protocol
interface. An unknown association rejects the transaction, and the next
request can create the same server. Edits replace associations and preserve
unchanged interfaces. Setting instructions to an empty string and clearing
them produce distinct results. Activation changes preserve the current
revision. The metrics fixture reads both existing raw and hourly records.

OAuth configuration changes require an unrestricted administrator. The
fixture verified encrypted storage, masked reads, preservation of the
unchanged approval generation when a caller submits a masked value, rejection
of a stale review version, and discovery after approval.

## Virtual-server OAuth access tokens

The pinned gateway and Rust matched 11 checks on SQLite and PostgreSQL
through `/servers/{id}/mcp`. A virtual server accepts a signed access
token from its approved authorization server for the configured resource
and resolves the user's roles and teams from the gateway database. The
checks covered the RFC 9728 challenge, a different resource audience, an
ID token, an unregistered email, a valid first-party session, and the
absence of access to the global MCP endpoint through a server-specific
token.

A server configured with a legacy client ID and no explicit resource
learned the matching audience from a verified access token. The replay
read back the learned resource and showed that a token for the original
fallback URL was then rejected. Rust stores only an audience that
matched the approved configuration and rechecks the generation before
using it.
