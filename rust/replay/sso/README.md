# Single sign-on

The SSO provider fixture matched 17 normalized HTTP responses on SQLite
and PostgreSQL. It exercised both public provider routes, admin access
checks, provider creation and updates, disabled-provider filtering, and
deletion. Admin responses omitted the client secret. A trusted API
provider's configured audience could be updated but could not be cleared
while the provider remained trusted.
