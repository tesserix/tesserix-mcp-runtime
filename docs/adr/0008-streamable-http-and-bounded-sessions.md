# ADR-0008: Streamable HTTP and bounded sessions

- Status: Accepted
- Date: 2026-08-30
- Tracking: [tesserix-mcp-runtime#10](https://github.com/tesserix/tesserix-mcp-runtime/issues/10)

## Context

AgentGateway needs one stable upstream MCP endpoint per runtime instance. The
endpoint must serve MCP Python SDK v1 and v2 clients while keeping protocol
types out of the core application contract. It must also fail closed under
malformed framing, large schemas and bodies, forged sessions, disconnects, and
gateway path rewriting.

ADR-0001 sets the per-pod envelope at 50 sustained and 200 burst calls per
second, 64 KiB requests, 512 KiB responses, at most 15 ms p99 runtime-added
latency, readiness within 2 seconds, idle RSS within 128 MiB, and 99.9% monthly
invocation availability. The expected catalog is 12 tools and the reviewed
maximum is 128. The fleet planning case grows from about 100 servers at 12
months to 500 at 36 months, with an 80:20 read-to-write invocation mix. This
transport persists no request history or business data; production load and
p99 evidence remain owned by issue #29.

The server baseline is MCP Python SDK `>=2.1.1,<3`, locked at 2.1.1. The
verified clients are 1.28.1, 1.29.1, and 2.1.1. Package versions are distinct
from Python 3.14 and protocol revisions 2025-11-25 and 2026-07-28; MCP SDK 1.34
does not exist, as ADR-0002 records.

Authentication verification and per-tool authorization remain issues #12 and
#13. This transport accepts only a trusted `HTTPCallContextProvider`; it does
not infer identity from model arguments or make an HTTP header authoritative by
itself.

## Decision

### Keep the official SDK authoritative

`StreamableHTTPTransport` constructs the official SDK `Server` and delegates
initialize, discovery, ping, tool dispatch, JSON-RPC validation, protocol
negotiation, and wire serialization to it. MCP-specific request, response, and
middleware types stay in `tesserix_mcp_runtime.adapters.streamable_http`.
`Application`, tool definitions, handlers, and manifests remain SDK-neutral.

The adapter adds only hosting concerns the SDK does not own for this platform:
route normalization, finite envelopes, context injection, tenant-bound session
admission, cancellation-token propagation, atomic response commitment,
telemetry, and listener lifecycle. It examines a bounded cancellation
notification body only to signal the matching core cancellation token before
the SDK cancels the task; the SDK still parses and validates that message.

### Use a private, readiness-aware listener

The default listener binds `127.0.0.1:8000` and serves `/mcp`. It waits for ASGI
lifespan startup before reporting readiness. Uvicorn access logs, date and
server headers, proxy-header trust, and Uvicorn-owned signal handlers are
disabled. The application composition root owns SIGINT/SIGTERM, drain, and
stop ordering.

A non-loopback bind is rejected unless both host and origin allowlists are
explicit. The official SDK enforces DNS-rebinding protection against those
lists. Direct public ingress is not a supported topology; AgentGateway remains
the external policy boundary.

Configured paths collapse repeated and trailing slashes once. The adapter
accepts that normalized path and one trailing slash, returns a generic 404 for
other routes, and never derives a route from forwarded headers. A gateway may
expose `/gateway/runtime/mcp` if it rewrites the upstream path to `/mcp` and
sets the intended upstream `Host`.

### Enforce one quantitative envelope

| Resource | Default ceiling |
|---|---:|
| Request headers | 128 fields / 32 KiB |
| Request body | 64 KiB |
| Buffered response | 512 KiB |
| Aggregate input/output schema JSON | 256 KiB |
| Tools | 128 |
| Discovery page | 32 tools |
| Discovery pages | 4 |
| Stateful sessions | 128, including pending creation |
| Session absolute lifetime | 30 minutes |
| Listener startup | 2 seconds |

Header names must be lowercase HTTP tokens. Header values reject control
octets other than horizontal tab. Tool count and aggregate schema bytes fail
before binding. Cursors contain a catalog fingerprint and page number; forged
or out-of-range cursors fail with stable invalid-parameter errors.

SDK responses are buffered before ASGI response commitment. Overflow or
serialization failure discards the entire buffered result and emits a generic
bounded internal error, so a secret-bearing partial result is not exposed.
Unbounded server-initiated event streaming is not a promised runtime surface in
this slice; later notification support must introduce an event-aware limiter
rather than silently removing the atomic guarantee.

### Default to stateless and isolate legacy sessions

Stateless mode is the default. Any supplied session header is rejected. The
2026-07-28 stateless-era path remains sessionless even when legacy stateful mode
is enabled.

Optional stateful mode exists for handshake-era clients. A new session reserves
capacity before the SDK creates it. The resulting opaque 32-character ID is
bound to the resolved `(tenant, issuer, subject)` tuple and an absolute expiry.
Missing, malformed, unknown, expired, or differently owned IDs all receive the
same generic 404 response. Scope changes do not change session ownership;
current scopes are authorized again for every tool call.

Explicit DELETE releases capacity. Expired sessions are pruned and terminated
on the next admission attempt; there is no unbounded timer per session. Active
requests retain a reference until cleanup, while new work on an expired session
is rejected. Pending reservations are included in the cap, preventing parallel
initializations from exceeding it.

MCP SDK 2.1.1 does not expose a public session-removal operation and its DELETE
path leaves a terminated transport in its internal registry. The adapter
therefore isolates access to the SDK's session registries in one method so
close and expiry release memory. This is an explicit upgrade risk: every SDK
upgrade must pass stateful close, expiry, and compatibility tests before merge.

### Propagate trusted context and cancellation

The context provider receives bounded request metadata whose representation
always redacts header values. Its immutable `CallContext`—identity, request and
run IDs, trace context, deadline, idempotency key, and cancellation object—is
passed unchanged to the application and handler.

An HTTP disconnect signals the token before the SDK cancels handler work. A
legacy `notifications/cancelled` message is matched by session plus typed
request ID so the correct token is signalled before SDK cancellation. Request
ID reuse cancels the superseded token, and all mappings are removed in a
`finally` path.

Protocol telemetry records bounded method, negotiated revision, SDK version,
and outcome. Telemetry failures are counted and never replace protocol results.
Library versions are not returned in client errors.

## Failure behavior

| Failure | Behavior |
|---|---|
| Wrong path or invalid stateless session | Generic 404 |
| Missing, forged, expired, or cross-owner stateful session | Generic 404 |
| Session capacity exhausted | Bounded 429 internal error |
| Invalid or oversized headers | Bounded 431 error |
| Oversized request body | SDK-enforced 413 |
| Unsupported protocol revision | Standard unsupported-version error |
| Malformed JSON-RPC or unknown method | Bounded standard SDK error |
| Response overflow or serialization failure | Atomic generic 500 |
| Request after drain begins | Generic 503 |
| Listener readiness timeout or bind failure | Stable configuration failure; no readiness |
| Client disconnect or cancellation notification | Matching handler token is signalled and work releases |

## Alternatives considered

- Implement a custom JSON-RPC stack: rejected because it would duplicate the
  SDK's protocol negotiation, error mapping, and client compatibility work.
- Expose a public listener by default: rejected because Gateway policy must not
  be bypassed and rebinding protection alone is not an ingress boundary.
- Make stateful mode the default: rejected because stateless request isolation
  has a smaller memory, tenant, and cleanup surface.
- Trust the SDK's idle timeout as the platform lifetime: rejected because idle
  extension is not an absolute resource bound and does not enforce a global
  session cap.
- Bind sessions only to tenant: rejected because a second subject in the same
  tenant must not inherit an existing protocol channel.
- Stream SDK output immediately: rejected for tool responses because a late
  serialization or size failure could expose a partial secret-bearing body.
- Maintain a second vector or semantic tool index in the runtime: rejected;
  Registry discovery remains a later system boundary and does not belong in
  transport selection.

## Verification

The in-memory protocol suite covers official initialize/list/call, pagination,
malformed messages, response atomicity, sessions, cancellation, context,
allowlists, and Hypothesis framing/header cases. The network matrix starts the
actual runtime and exercises SDK 1.28.1, 1.29.1, and 2.1.1. A local proxy rewrites
the gateway prefix. Every lane traverses two cursor pages and proves disconnect
cancellation reaches an active handler. Official MCP Inspector CLI 2.4.0 performs
the same pagination, call, cancellation, and clean-close sequence.

    uv run --frozen pytest tests/protocol/test_streamable_http.py
    uv run --frozen python compatibility/run_matrix.py
    uv run --frozen python compatibility/run_inspector.py

## Consequences, rollout, and rollback

The runtime gains direct dependencies on `mcp-types` and Uvicorn, both already
in the MCP SDK closure. Normal calls add one bounded header parse, one trusted
context construction, an atomic response copy of at most 512 KiB per active
response, and constant-time session or cancellation bookkeeping. It adds no
datastore, queue, external service, or durable storage cost. Issue #14 owns the
process and per-tenant concurrency ceilings; issue #29 owns production load and
soak evidence. This ADR does not turn unit timings into an SLO claim.

Rollout keeps listeners loopback-only behind AgentGateway, begins stateless,
and enables legacy state only for a named compatibility need. Route health must
remain inactive until readiness and client conformance succeed. Rollback drains
the instance, restores the prior image, and reactivates the previous immutable
gateway target. No Registry record, database migration, or durable external
state is written by this transport slice.
