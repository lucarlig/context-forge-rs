# Gateway OAuth

The pinned gateway registered an authorization-code gateway against a
local OAuth provider and stored one user's token. The fixture then started
Rust with the same database and bearer configuration.

All ten status requests matched on SQLite and PostgreSQL after normalizing
timestamps. The checks covered missing authentication, unknown gateways,
visibility, per-user token state, batch limits, and omission of inaccessible
gateways. Rust also reported a token expiring within one minute as
`near_expiry` and a past expiry as `expired`.

The authorization-code fixture matched all 19 normalized HTTP responses on
SQLite and PostgreSQL. The provider checked the S256 verifier, resource
parameter, and exact callback URI. The gateway rejected an unbound callback
and replay of a consumed state. Token retrieval remained scoped to the
authorizing user and refreshed the token near expiry. The database stored
encrypted access and refresh tokens. A native SQLite run also retrieved a
token written by the pinned gateway.

`POST /oauth/fetch-tools/{id}` discovered a protected tool with the caller's
access token. The MCP tool call and the authorization prompt for another
caller matched the pinned gateway on SQLite and PostgreSQL. The second
caller did not reach the upstream provider. Two workers sharing either
database performed one provider refresh for concurrent token requests.

Queued registration deferred discovery until a user authorized. A queued
description edit preserved the catalog and the existing grant. Changing
the upstream destination or OAuth configuration invalidates stored user
grants and pending authorization states.

Dynamic client registration matched 13 normalized HTTP responses on SQLite
and PostgreSQL. The provider received the same RFC 7591 payload as the
pinned gateway. The fixture covered issuer metadata discovery under a
tenant path, authorization-code exchange, reuse of the registered client,
and global admin list, detail, and local deletion. Two workers sharing
either database made one registration request for concurrent authorization
attempts.
