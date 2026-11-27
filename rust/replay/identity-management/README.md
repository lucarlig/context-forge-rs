# Local identity management

The live bootstrap fixture exercised both local authentication API prefixes.
It covered administrator login, self-registration, duplicate user rejection,
administrator user reads, scoped authorization, authentication events, and
user pagination. It ran against the pinned release and three Rust setups:
a fresh SQLite database, a fresh PostgreSQL database, and a SQLite database
initialized by the pinned gateway.

Fifteen of the 18 pinned responses matched on every Rust setup after
normalizing generated timestamps and identifiers. The remaining cases were
the following.

- The native profile reads the persisted last-login timestamp immediately.
  The pinned profile returned null after reporting the new timestamp at login.
- Native pagination returns a cursor when a second page exists. The pinned
  response returned a null cursor for a one-user page with two users in the
  database.
- The pinned role-list endpoint returned the account's two grants. The native
  bootstrap stores the same global and personal-team grants. Its role-list
  endpoint belongs to the role-management slice.

The native runs authenticated a registered user's session against the token
management API, issued a scoped API token, and used it to read the tool
catalog. They also verified that administrator login survives switching from
the pinned gateway to Rust with the same database and JWT configuration.
Fresh native databases bootstrap a local administrator when
`PLATFORM_ADMIN_PASSWORD` is set. Subsequent boots preserve the stored hash.

The user lifecycle fixture exercised password changes and reuse checks,
account lockout and unlock, administrator resets, deactivation, and deletion.
Thirty-two of 36 normalized responses matched the pinned gateway on both
databases. The role-list route was pending, two profiles exposed fresher
last-login data, and the rejected session used a different error detail.

Native password changes revoke both active API tokens and locally issued
sessions in the transaction that changes the password. This also covers
sessions issued during the same second as the change. The fixture verified
both credential types through the normal HTTP endpoints.

The password recovery fixture ran the pinned and Rust servers through a local
SMTP relay. It verified generic forgot-password responses, per-address rate
limits for known and unknown accounts, replacement of outstanding links,
confirmation email, and login with the new password. The database stored the
SHA-256 digest of the link token. On SQLite and PostgreSQL, two simultaneous
submissions of the same Rust reset link produced one success and one rejection.
The password and session revocations committed together.

All 24 normalized role-management responses matched on SQLite and
PostgreSQL. The fixture covered the permissions catalog, built-in roles,
inherited role creation, assignment, permission checks, revocation, and
soft deletion. It also checked that a regular account cannot list roles for
administration and that built-in roles cannot be edited.
