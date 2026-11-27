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

The Client ID Metadata Document flow matched nine normalized requests on
SQLite and PostgreSQL. The gateway selected its HTTPS metadata document
when the provider advertised support and rejected an explicit CIMD
request with a different callback URI. The signed fixture also checked
the current and previous public keys in the published JWKS. The provider
verified the dedicated RSA key's client assertions for authorization-code
exchange and refresh, and the private key stayed out of the database.

Three RFC 8693 fixtures matched 10 normalized checks each on SQLite and
PostgreSQL. They covered impersonation, delegation with an actor access
token, and delegation with a signed actor assertion. The provider verified
the exact authenticated subject and expected grant fields. Repeated calls
with the same valid credential reused the exchange. The discovery
credential handled catalog refresh when configured, and a deferred
gateway could refresh under the calling user's credentials.

A separate check matched the pinned tool error when the provider returned
a non-bearer token. That response did not reach the MCP upstream. Gateway
configuration and connection changes for token exchange require a
platform administrator.

Two workers sharing Valkey reused successful exchanges and recent
failures on SQLite and PostgreSQL. A fresh credential for the same
caller used a separate cache entry. The fixture inspected the stored
values to verify that they contain no plaintext access tokens. Shared
entries are encrypted and bound to the gateway revision and caller
credential, and each worker has a bounded fallback cache.

The post-authorization handshake matched 14 checks using MCP
`initialize` and 15 using `server/discover` on SQLite and PostgreSQL.
It used the caller's exact gateway credential without refreshing it,
listed one live page of tools, and redacted the access token from
upstream metadata. The checks covered access and target matching,
missing and expired tokens, missing tools capability, insufficient
scope, and invalid list responses. A separate check matched the
default rejection of a private destination.
