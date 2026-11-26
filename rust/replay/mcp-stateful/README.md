# Stateful MCP reference findings

These observations come from black-box runs against the [pinned v1.1.2 gateway](../../MAP.md).

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

A live upstream fixture also confirmed the production delivery path without injecting events into the reference event bus. A stateful tool call triggered log notifications on both the upstream POST response and its passive GET stream. The downstream GET received the POST notification `C` followed by the upstream GET notifications `A` and `B`. Reconnecting with the cursor for `C` replayed `A` and `B`.

In the Redis affinity profile, two pinned gateway processes shared an isolated SQLite database and a disposable Valkey instance. The second process accepted a `ping` POST with a session initialized on the first. The first process handled the tool call while the second hosted the passive GET and delivered `C`, `B`, and `A`. Reconnecting to the second process from the cursor for `C` replayed `B` and `A` in the observed delivery order.

With `MCPGATEWAY_SESSION_AFFINITY_TTL=4`, both gateways let the original worker keep the session when remote POST routing expired. A peer POST returned `404`, the peer could open a passive GET, and a POST to the original worker renewed routing. The pinned gateway's peer DELETE returned `404` when affinity was current and `200` after it expired. The session on the original worker survived both. Rust routes DELETE to the original worker while the session is active and invalidates it there. [Session deletion decision](../../DECISIONS.md#equivalence)

Bind session access to the authorized principal and virtual server on every request. Apply the ownership check regardless of the cache backend. DELETE must invalidate the session for both POST and GET and close active streams. Verify those rules, cross-session cursor isolation, and cancellation through a live Rust gateway before checking off the milestone. [Legacy MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#session-management)

Rust forwards typed logging and catalog notifications from upstream POST responses and persistent GET streams. It associates upstream sessions with the downstream session, gateway endpoint, and authorization scope. Its live test confirms upstream session reuse, notification delivery after a tool returns, upstream reconnection with `Last-Event-ID`, and upstream closure after downstream DELETE. It also verifies replay and rejection with a narrowed bearer token.

## Server-initiated legacy requests

An upstream fixture sent each request while the client held an active stateful GET. The pinned gateway answered the upstream directly and the downstream GET carried no request in the four-second observation window. The `roots/list` run advertised the `roots` capability in the downstream initialize request.

| Upstream request | Reference reply |
| --- | --- |
| `ping` | Empty result |
| `roots/list` | `-32600`, `List roots not supported` |
| `sampling/createMessage` | `-32600`, `Sampling not supported` |
| `elicitation/create` | `-32600`, `Elicitation not supported` |

The Rust gateway answers these requests on upstream POST SSE replies and persistent GET streams. The live test checks both channels, including the upstream session and protocol headers and preservation of string and numeric request IDs.

## Rust lifecycle replay

The native gateway creates legacy sessions when `USE_STATEFUL_SESSIONS=true`. The process-local registry uses a sliding `SESSION_TTL` of one hour by default and caps the active set at 4,096 sessions. Set `MCP_GET_STREAM_ENABLED=false` to disable passive GET. The live Rust gateway test covers token renewal, principal and virtual-server isolation, notification acknowledgement, passive stream negotiation, listener conflict, and closure and invalidation after deletion.

Set `CACHE_TYPE=redis` and `REDIS_URL` to store session ownership and expiry in Redis. Redis validates the principal and virtual-server binding before allowing a lookup, renewal, or deletion. Set `MCPGATEWAY_SESSION_AFFINITY_ENABLED=true` for cross-worker POST and DELETE. `MCPGATEWAY_SESSION_AFFINITY_TTL` sets how long a peer can forward POST requests and defaults to 300 seconds. A POST on the owning worker renews this lease. The gateway returns HTTP `503` when the directory is unavailable. A live run against Valkey verified registration, renewal, deletion, and recovery after a cache restart.

Redis makes passive GET available on any worker with or without POST affinity. The pinned gateway renewed the listener lease after its configured three-second lifetime and removed it when the connection ended. Rust uses `MCP_GET_STREAM_LISTENER_TTL_SECONDS`, which defaults to 30 seconds, and closes the stream after two missed renewals. A two-process Rust run verified that remote POST stayed disabled, a competing GET returned `409`, a lost lease ended SSE, and release preserved a replacement lease.

Requests can reach any worker with access to the same Redis cache. The owning worker authenticates the relayed request and serves POST, passive GET, or DELETE. Redis Pub/Sub carries response chunks. Credits bound the relay to one pending chunk per request. A live test used two native processes for POST and DELETE. The Rust integration test also covers forwarded POST SSE, concurrent passive GET, recovery after a client disconnect, authorization, and stream closure after deletion.

The pinned gateway dispatched two forwarded calls to the same upstream in order. Rust queues forwarded POSTs per session before applying `MCPGATEWAY_AFFINITY_FORWARD_CONCURRENCY`. `MCPGATEWAY_AFFINITY_SESSION_LOCK_TIMEOUT` bounds the ordering wait and defaults to 30 seconds. Passive GET and cancellation can proceed while a POST is in flight. Calls sharing an upstream association remain serialized after the forwarding lock times out. A live Rust test covers the timeout and forwarded cancellation.

```sh
REDIS_URL=redis://127.0.0.1:6379/0 \
  cargo test --locked --lib redis_sessions::tests -- --ignored
REDIS_URL=redis://127.0.0.1:6379/0 \
  cargo test --locked --test gateway redis_affinity -- --ignored
```

The public legacy JSON profile produced eight recordings with rust-anything v5.0.1. The original matched all eight and Rust matched seven. The remaining initialization difference includes the Rust version and the current capability set and instructions. Missing-session POST and DELETE errors and rejected POST Accept headers before initialization include a temporary session ID. The live test verifies that reusing the ID from either missing-session error yields `404`.

```sh
USE_STATEFUL_SESSIONS=true MCP_REQUIRE_AUTH=false MCP_INBOUND_PROTOCOL_MODE=legacy \
  DATABASE_URL=sqlite:///:memory: rust-anything app replay rust/replay/mcp-stateful \
  --build "$PWD/target/debug/context-forge-rs"
```

## In-flight tool cancellation

The pinned gateway acknowledged a stateful `notifications/cancelled` POST with `202` and returned JSON-RPC error `-32800` with `Request cancelled` to the outstanding tool request. The synthetic upstream observed the notification with its own request ID, even when the downstream request used a string ID. The live Rust test reproduced all three results and also verified that a different principal or a second session could not cancel the call.

## POST replies over SSE

With `JSON_RESPONSE_ENABLED=false`, both versions require clients to accept JSON and SSE. Legacy requests receive their terminal JSON-RPC message as an SSE event. Modern discovery returns JSON. The live Rust test opens the legacy POST stream before an upstream tool completes and reads the cancellation error from the stream.

The pinned gateway and Rust include a priming event and event IDs for stateful initialization with protocol version `2025-11-25`.

The pinned gateway and the Rust binary matched all five stateless POST replay cases.

```sh
JSON_RESPONSE_ENABLED=false USE_STATEFUL_SESSIONS=false MCP_REQUIRE_AUTH=false \
  MCP_INBOUND_PROTOCOL_MODE=auto DATABASE_URL=sqlite:///:memory: \
  rust-anything app replay rust/replay/mcp-stateful/sse-stateless \
  --build "$PWD/target/debug/context-forge-rs"
```

## Modern tool input round trips

A synthetic upstream returned `input_required` with a form elicitation request and an opaque `requestState`. The pinned gateway returned HTTP `400` and JSON-RPC error `-32021` when the caller had omitted form elicitation. It returned the question when the caller declared `elicitation: {}`. Retrying with `inputResponses` and the saved state returned the completed tool result. On the upstream leg, the gateway forwarded the caller's elicitation capability and removed unrelated extensions. A legacy call received a tool error result instead of the question.

Both gateways return a tool error result with `io.contextforge/errorCode` when the upstream rejects the request with `-32021`. The live Rust test covers both rejection paths, successful continuation, the capabilities forwarded on each request, and the legacy result. Prompts and resources have separate handlers and remain part of the next milestone.

## Progress during tool calls

A synthetic upstream posted one progress event with an unrelated token, then one with the numeric token it received in `tools/call`. Both gateways delivered the matching event before the terminal reply and replaced its token with the caller's string token. The reference sent SSE for legacy streaming mode and for modern clients that accepted both media types and supplied a progress token. Legacy JSON mode returned a single JSON result. Rust also keeps modern responses in JSON when the client accepts only JSON. The live Rust test holds the upstream result until the client reads its progress event.

## Resuming a POST stream

The Rust gateway retains event history per stateful POST stream. The client can reconnect with `Last-Event-ID` and receive frames after that cursor, including a pending terminal reply. Live tests disconnect after progress, resume the outstanding invocation, and verify session and authorization isolation, including a revoked tool permission. Unknown or expired cursors open the passive SSE connection.

`STREAMABLE_HTTP_MAX_EVENTS_PER_STREAM` defaults to 100. `STREAMABLE_HTTP_EVENT_TTL` defaults to one hour after the stream finishes. The process retains at most 128 POST streams per session and budgets 64 MiB for retained events.

The pinned gateway accepted the resume GET in the same progress fixture and delivered no events in the 1.5-second observation window. Rust implements POST resumption by stream ID as described by the transport specification. [MCP resumability specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#resumability-and-redelivery)
