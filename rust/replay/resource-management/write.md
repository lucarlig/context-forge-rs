# Resource management writes

The resource API creates and updates resources and URI templates, changes their enabled state, and deletes them. It enforces catalog scope, ownership, and URI uniqueness within the target scope. Updates preserve naming history and advance the version. Text resources keep their text representation when a database also stores a byte copy.

The Rust gateway matched 17 live pinned operations after normalizing generated IDs and timestamps. They included creation, duplicate rejection, filtering by a normalized tag, exact content reads, update and version checks, template listing, activation, and deletion. The live sequence passed on SQLite, PostgreSQL, and SQLite populated by the pinned gateway.

The older SQLite fixture also verified that a caller with write permissions cannot modify another user's public resource without ownership. Deletion removed the virtual-server association and detached the hourly rollup. Passing `purge_metrics=true` removed the rollup.

A separate comparison matched the pinned HTTP 413 response for content whose UTF-8 encoding exceeds `CONTENT_MAX_RESOURCE_SIZE` and HTTP 415 for a media type excluded by strict MIME validation.

`POST /resources/subscribe` and `POST /v1/resources/subscribe` stream resource lifecycle events. The pinned comparison and live SQLite and PostgreSQL checks matched add, update, deactivate, activate, and delete events. An owner received an event for a private resource while a public-only subscriber received only the public events. The Rust stream receives writes handled by its gateway process.

Resource content reads honor `X-Server-ID`. Both gateways returned the content for a linked virtual server and HTTP 404 for an unlinked or unknown server.
