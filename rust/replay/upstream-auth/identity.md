# Upstream identity forwarding

Live SQLite and PostgreSQL cases verified that the Rust gateway loads the authenticated account's email and full name, forwards its effective team and admin scope, and sets the authentication method to `jwt`. The upstream fixture verified signed payloads in HTTP headers and MCP `_meta.user` against the configured key, gateway audience, issuer, and 60-second validity period.

The pinned gateway forwarded the same identity fields with global forwarding enabled. Its registration route left the submitted per-gateway overrides unset. With those overrides seeded in its database, it observed the enabled flag, custom prefix, and signing setting, and emitted both representations for the two single-mode cases. The Rust gateway persists the registration settings and applies the selected mode. The Rust integration test also verifies that a caller-provided identity in tool metadata is replaced with the authenticated account's identity.
