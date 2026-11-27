# Asynchronous gateway lifecycle

With `GATEWAY_ASYNC_LIFECYCLE_ENABLED=true`, gateway creation, updates, and deletion return HTTP 202 and `Retry-After`. Workers discover and write the catalog for pending gateways, or remove deleting gateways and their associations. Failed initialization stays pending with a sanitized error and an exponential retry delay capped at 300 seconds. The API returns the existing pending operation when its owner repeats creation or submits an update while initialization is pending.

The pinned and Rust gateways both registered an authenticated fixture while its upstream returned HTTP 503. They recorded a retry, activated the gateway when the upstream recovered, queued a rename, and removed the gateway and its catalog on deletion. Rust passed on SQLite, PostgreSQL, and a pinned SQLite database with a pending operation already in progress.

Two Rust processes shared a SQLite or PostgreSQL database. While one worker held the lease, only that process contacted the upstream. After it was killed, the other process resumed the job when the lease expired. Deletion during an in-flight initialization prevented that worker from committing its catalog.

`GATEWAY_ASYNC_LIFECYCLE_POLL_INTERVAL`, `GATEWAY_ASYNC_LIFECYCLE_ATTEMPT_TIMEOUT`, and `GATEWAY_ASYNC_LIFECYCLE_LEASE_SECONDS` configure worker timing. Requests with one-time credentials run synchronously so the credentials can be used for discovery without staging them in the database.
