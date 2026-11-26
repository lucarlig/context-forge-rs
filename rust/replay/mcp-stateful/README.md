# Stateful MCP reference findings

These observations come from black-box runs against the [pinned v1.1.2 gateway](../../MAP.md). The Rust stateful transport is pending.

The reference runs used isolated SQLite databases and generated test credentials. Each run required authentication and enabled JSON responses. The strict ownership profile also set `CACHE_TYPE=redis` and `MCPGATEWAY_SESSION_AFFINITY_ENABLED=true` with a disposable Redis instance.

## Legacy session lifecycle

| Operation | Reference result |
| --- | --- |
| `initialize` with `USE_STATEFUL_SESSIONS=true` | `200` with `Mcp-Session-Id` |
| `initialize` with `USE_STATEFUL_SESSIONS=false` | `200` with no session ID |
| `notifications/initialized` in an active session | `202` |
| Owner `ping` with a renewed bearer token | `200` with an empty result |
| Another authenticated principal uses the session in the Redis affinity profile | `403` on POST, GET, and DELETE |
| Unauthenticated POST in the required-auth profile | `401` |
| POST or DELETE omits the required session ID | `400` |
| Passive GET omits the session ID | `405` |
| Passive GET with `MCP_GET_STREAM_ENABLED=false` | `405` |
| Passive GET omits an acceptable `text/event-stream` media type | `406` |
| First passive GET for an active session | `200` with `text/event-stream` |
| Second passive GET while the first stays open | `409` with `Retry-After: 1` |
| Owner DELETE | `200` with an empty result |
| Passive GET immediately after DELETE | `404` |

## Event resumption

The reference fixture published synthetic `notifications/message` events to the session event bus. The client read real HTTP streams.

| Passive GET | Captured events in order |
| --- | --- |
| Open the fixture session stream | `A`, `B` |
| Send `Last-Event-ID` for `A` | `B` |
| Send an unknown `Last-Event-ID` and publish a fresh event | `D` |

Bind session access to the authorized principal and virtual server on every request. Apply the ownership check regardless of the cache backend. DELETE must invalidate the session for both POST and GET and close active streams. Verify those rules, cross-session cursor isolation, and cancellation through a live Rust gateway before checking off the milestone. [Legacy MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#session-management)
