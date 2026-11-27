# Gateway OAuth

The pinned gateway registered an authorization-code gateway against a
local OAuth provider and stored one user's token. The fixture then started
Rust with the same database and bearer configuration.

All ten status requests matched on SQLite and PostgreSQL after normalizing
timestamps. The checks covered missing authentication, unknown gateways,
visibility, per-user token state, batch limits, and omission of inaccessible
gateways. Rust also reported a token expiring within one minute as
`near_expiry` and a past expiry as `expired`.
