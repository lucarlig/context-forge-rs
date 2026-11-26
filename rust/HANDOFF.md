# Handoff

Start with [the port map](MAP.md). The source classifier found 77 units, including 11 blocked units. The root Python application and API package are among the blocked units. Port those by behavior using the existing HTTP and protocol tests.

The Rust workspace lives in `rust/app`. The probe cases are in `rust/app-cases`. Use rust-anything v5.0.1 and a reference launcher named `context-forge-reference-server` on PATH to replay the original. The launcher must bind to the supplied `PORT` and start with an isolated SQLite database. Set `RATE_LIMITING_ENABLED=false`, `CORRELATION_ID_ENABLED=false`, and `SECURITY_HEADERS_ENABLED=false` for these cases. The Rust replay command is in the README.

Next, port database-backed identity and role grants, then connect verified JWTs to the visibility policy. Capture a stateless MCP legacy session against upstream. Cover initialization, tool discovery, invocation, and cross-team denial against the same synthetic upstream.
