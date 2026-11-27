# One-time upstream credentials

With `oneTimeAuth: true`, registration uses the supplied credentials during discovery and stores `one_time_auth` as the authentication type. The gateway returns the type in its response and leaves the stored header and query credentials empty. A later call can supply its own credential through `X-Upstream-Authorization`.

The pinned gateway and Rust matched both invocation recordings. A live SQLite fixture checked stored values after registration and verified that the discovery and invocation requests used the credentials supplied for each operation.

For replay, register public fixtures named `onetime` and `marker`, each exposing `echo`. Register `onetime` with a bearer credential and the one-time flag. Register `marker` with `authType: "one_time_auth"`. Each upstream expects the synthetic credential sent in the recorded invocation and prefixes its response with the fixture name.
