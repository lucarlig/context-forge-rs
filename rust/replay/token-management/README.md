# API token lifecycle

The live fixture signed in on the pinned gateway through
`POST /v1/auth/email/login`. The Rust run used a signed session for the same
synthetic administrator while local login was being ported. It exercised both
token API prefixes and used the issued credential against the normal tool
catalog endpoint. Timestamp precision, generated UUIDs, and one-time credentials
vary by run.

| Request | Pinned gateway | Rust SQLite and PostgreSQL |
| --- | --- | --- |
| Empty list, issue, duplicate, detail, paginated list, admin list | 200, 201, 400, 200, 200, 200 | Same statuses and normalized metadata |
| Restricted API credential reads token metadata | 403 | 403 |
| First two catalog requests with an hourly limit of two | 200 | 200 |
| Third catalog request | 200 | 429 with the hourly limit detail |
| Usage report | 200 with zero recorded requests | 200 with two successful requests and two blocked requests |
| Update, disable, and re-enable | 200 | 200 |
| Catalog request while disabled | 200 | 401 |
| Revoke and use the old credential | 204, then 401 | 204, then 401 |
| Revoked token detail | Inactive with revocation fields unset | Inactive with the persisted revocation actor, reason, and timestamp |
| Signed API credential without a catalog record lists tokens | 200 | 403 |

Rust enforces the limit stored in the token catalog. The pinned issuer omits
it from the signed scope and its request middleware reads only that scope.
Setting `TOKEN_USAGE_LOGGING_ENABLED=false` leaves the usage report empty and
keeps the quota active. The quota stores timestamps and token IDs without
request metadata.

The interoperability fixture used the pinned gateway to create each database
and issue a credential. After switching to Rust, the same credential worked
and reached its stored limit on SQLite and PostgreSQL. The runtime also
enforced team membership, permission delegation, client IP, stored expiry,
and virtual-server scope through the actual MCP endpoint. The hash stored in
the database matched the SHA-256 digest of the one-time credential.

Two Rust workers shared each database. Twelve simultaneous tool catalog
requests with one daily quota slot returned one success and eleven HTTP 429
responses. A WebSocket connection used its hourly slot on the first RPC.
The next RPC and an HTTP call on the peer worker both returned the quota
error. Revocation through one worker took effect on the other worker before
its next request.
