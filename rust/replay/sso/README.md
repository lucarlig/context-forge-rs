# Single sign-on

The SSO provider fixture matched 17 normalized HTTP responses on SQLite
and PostgreSQL. It exercised both public provider routes, admin access
checks, provider creation and updates, disabled-provider filtering, and
deletion. Admin responses omitted the client secret. A trusted API
provider's configured audience could be updated but could not be cleared
while the provider remained trusted.

The browser OIDC flow matched 15 normalized checks on both databases. The
provider verified S256 PKCE. Rust verified the ID token signature, issuer,
audience, and nonce, and checked that the userinfo subject matched the ID
token. The flow issued a gateway session for the new user and refused an
unbound browser, a replay, the wrong nonce, an unverified email claim, and
an attempt to sign in as an existing local account.

External OIDC bearer authentication matched 16 HTTP responses after
normalizing timestamps and first-login metadata. Both databases supported
trusted human and service identities through MCP and REST. The checks
covered the provider's configured audience, expiry, ID-token rejection,
trusted domains, account binding, and disabling a provider. Rust reads the
persisted login timestamp when constructing an account response.

With admin approval required, 23 normalized checks matched on both
databases. An eligible caller entered the pending queue, a reviewer could
approve or reject the request, and a rejected request stayed closed.
Account creation consumed approval in the same transaction and required
the same provider that requested it.
