# ADR-0012: Finite execution and tenant bulkheads

- Status: Accepted
- Date: 2026-08-30
- Tracking: [tesserix-mcp-runtime#14](https://github.com/tesserix/tesserix-mcp-runtime/issues/14)

## Context

ADR-0001 sets a 64 KiB request, 512 KiB response, 128-tool server, at most
15 ms runtime-added p99, and 99.9% monthly invocation availability target for
one server per process. ADR-0008 bounds the MCP network and session surface.
ADR-0010 supplies an authenticated deadline and tenant identity. ADR-0011
authorizes the exact tool and requires idempotency for mutations. None alone
bounds application JSON structure, handler concurrency, retry amplification,
or a handler that ignores cancellation.

The expected pod envelope remains 50 sustained and 200 short-burst calls per
second, with an 80% read / 20% mutation mix, up to 128 tools, and one
`Application` per process. At 500 deployed servers in the 36-month assumption,
failure containment must be per process and per verified tenant; a shared
durable scheduler would add cost and a larger failure domain without being
required for synchronous MCP calls.

Protected assets are process memory, event-loop and downstream capacity,
tenant availability, mutation correctness, and private results. Threat actors
include unauthenticated callers, authenticated noisy tenants, a compromised
gateway, dependency failures, and buggy or adversarial handlers. Network
metadata becomes trusted only after gateway verification. Arguments and
results remain untrusted at their respective runtime boundaries.

## Decision

### One immutable policy with hard maxima

`ExecutionLimits` is the public application-level policy. It owns finite JSON
bytes, depth, properties, arrays and total nodes; tool count; process, server,
tool and tenant concurrency; call and tool deadlines; cancellation grace; and
retry attempts and delays. Every field has a safe default and a constructor-
enforced maximum that a deployment cannot raise.

The default request/result ceilings remain 65,536 / 524,288 bytes. JSON
defaults are depth 16, 128 properties, 1,024 array items, and 4,096 total
nodes. Concurrency defaults are 64 process, 64 server, 32 per tool, and 16 per
tenant. Calls and tools default to 30 seconds, cancellation grace to one
second, and attempts to three with 50 ms initial and 500 ms capped backoff.
The complete default/maximum table is maintained in the
[runtime safety guide](../runtime-safety.md).

Streamable HTTP independently caps request and response bytes, headers,
aggregate schemas, tools, pages, sessions, startup and stream duration. Its
300-second stream maximum bounds long-lived SDK behavior even when no tool is
active. Schema, discovery metadata, gateway identity windows, and application
drain also have non-overridable maxima. Boundary policies may be lowered but
never changed to unbounded values.

### Iterative validation before and after execution

The application walks JSON iteratively, counts mappings, lists and scalar
nodes, validates finite JSON values and text keys, then performs canonical
UTF-8 serialization for the byte boundary. It rejects input before parsing,
authorization, or handler work when possible. It performs the same bounded
validation on serialized tool output before returning success. Result
overflow becomes `result_too_large`; no prefix or dynamic exception text is
returned.

Registration checks the 128-tool ceiling before listener startup. The
transport checks catalog schema bytes before binding and body bytes before SDK
JSON parsing. Atomic response buffering prevents a serialization or response
overflow from committing partial content.

### Immediate admission and tenant bulkheads

There is no internal execution queue. One event-loop-local controller checks
process, server, tool and verified-tenant counters and either grants a lease or
returns `overloaded` immediately. One application per process makes the
process counter authoritative for the supported deployment shape. Separate
processes are required for separate server failure or scaling domains.

The lease covers every retry and is released in `finally` after success or
failure. If cancelled work ignores task cancellation and is detached, the
lease stays with that work until it exits. Detachment therefore does not
increase effective concurrency. The application reports live detached work
for readiness and observability consumers.

### Earliest deadline and one cancellation path

At admission the runtime chooses the earliest authenticated caller/gateway
deadline, runtime maximum, and tool maximum. `GatewayJWTContextProvider`
accepts one positive decimal `X-Tesserix-Timeout-Ms`, clamps it to the
configured timeout, and enforces a 30-second configuration maximum.

The runtime links caller and local cancellation. Caller cancellation, HTTP
disconnect, protocol cancellation, or deadline expiration sets the handler's
`Cancellation` before task cancellation. A cooperative handler exits and
releases its lease. A handler that suppresses cancellation receives exactly
one configured grace period, then is detached and counted. Its lease remains
active and its late result is discarded. Stream expiry aborts its session,
prevents late ASGI sends, and returns a fixed bounded 504 if no response was
committed.

### Retry only safe transient work

Reads are retry eligible. A mutation is eligible only when reviewed metadata
requires idempotency and the verified context contains a key. Eligibility does
not itself cause a retry: only connection failure, timeout, `overloaded`, or
`unavailable` does. Validation, authorization, approval, conflict,
cancellation, result overflow, and unknown failures are never retried.

Backoff is capped exponential with deterministic request-scoped jitter. The
attempt cap includes the first call. The runtime does not begin a delay that
would reach or cross the original effective deadline. Every mutation attempt
receives the same immutable context and key; the product backing service
remains the authoritative idempotency store. The runtime owns handler retries,
so gateway and mesh policies must not add another retry layer.

### Stable overload and overflow outcomes

`overloaded` and `result_too_large` join the public error vocabulary.
`overloaded`, `timeout`, and `unavailable` are retryable only for safe or
idempotent calls. `cancelled` and `result_too_large` are never retryable.
Messages are fixed, generic and payload-free.

## Failure behavior

| Condition | Result | Resource behavior |
|---|---|---|
| Input exceeds any JSON boundary | `invalid_input` | Parser and handler do not run |
| Result exceeds a JSON or byte boundary | `result_too_large` | Result is discarded atomically |
| Process, server, tool, or tenant saturated | `overloaded` | Immediate shedding; no queue |
| Caller cancels | `cancelled` | Handler cancellation signalled before task cancellation |
| Earliest deadline expires | `timeout` | One cleanup grace, then optional detachment |
| Handler ignores cancellation | Original `timeout` or `cancelled` | Work stays counted until exit |
| Safe transient read fails | Retry within attempts and deadline | Same lease and context retained |
| Idempotent mutation transiently fails | Retry only with verified key | Same key reaches every attempt |
| Unsafe mutation or non-transient call fails | Original stable error | No retry |
| SDK stream reaches 300-second cap | Bounded HTTP 504 timeout | Session aborted; late sends discarded |

When a dependency returns 429 or 503, an adapter maps only a genuinely
transient condition to `overloaded` or `unavailable`. If the runtime crashes
during a mutation, replay with the same key recovers through the authoritative
backing service as decided in ADR-0011. No cross-process transaction or queue
is introduced.

## Alternatives considered

- Add a bounded internal queue: rejected because it consumes caller deadlines,
  hides overload, and duplicates gateway admission. Immediate shedding gives a
  smaller and observable failure domain.
- Use one global semaphore: rejected because a noisy tenant or slow tool could
  consume every slot.
- Cancel and immediately release capacity: rejected because a handler may
  suppress cancellation and create uncounted oversubscription.
- Retry every timeout or 5xx: rejected because mutations without durable
  idempotency can repeat effects and retries can outlive the originating call.
- Make jitter nondeterministic: rejected because deterministic request-scoped
  jitter distributes calls while preserving reproducible tests and evidence.
- Recursively walk JSON: rejected because recursion itself becomes a failure
  mode near attacker-controlled depth.
- Add a durable execution service: rejected because synchronous MCP calls need
  bounded in-process admission, not a second scheduler or data owner.

## Consequences, rollout, and rollback

Every call pays one bounded iterative traversal and canonical serialization at
input and output. The checked-in Python 3.14 ceiling benchmark measured a
largest local p99 of 3.65 ms and largest temporary allocation of 1,181,398
bytes at the 512 KiB result boundary on the recorded arm64 macOS host. This is
inside the 15 ms runtime-added target for the isolated validator, but it is not
a production load claim; issue #29 owns pod-shape load and soak evidence.

No dependency, database, queue, sidecar, credential, route, or Kubernetes
resource is added. Memory cost is bounded by active handler state plus atomic
response and validation buffers. Deployment termination grace must exceed the
longest configured call plus cancellation grace. Readiness may incorporate
saturation and detached counts in issue #16; liveness remains independent of
downstream services.

The rebuilt wheel is 70,260 bytes. This exceeds ADR-0003's original 65,536-byte
review budget after the official transport, gateway identity, tool policy, ADK
adapter, and this execution controller were added across the preceding
milestone, while the core dependency count remains 34 and this change adds no
dependency. The reviewed architecture ceiling is therefore raised to 98,304
bytes (96 KiB). The measured wheel uses 71.5% of that ceiling and preserves
28,028 bytes of explicit headroom; future growth still fails the architecture
gate rather than silently expanding the package.

Rollout is additive through a normal runtime version update with defaults
retained first. Existing callers see two new stable error codes and may use
their retryability field. Rollback is one dependency-lock reversion to the
previous runtime. It requires no data migration, but removes these protections
and is not a safe response to active resource abuse; traffic should remain on
the last known-good bounded version.

## Verification

- exact-boundary, over-limit, property, and protocol framing tests;
- tenant, tool, server and process concurrency isolation;
- deadline, caller cancellation, stubborn-handler grace and live detachment;
- capacity retention during detachment and release after every failure;
- eligible read and idempotent mutation retries with deterministic jitter;
- unsafe mutation, non-transient, attempt-cap and original-deadline negatives;
- gateway timeout syntax, duplicate, clamp and configuration-boundary tests;
- Streamable HTTP duration, body, header, response and session limits;
- reviewed machine-readable threat-model evidence;
- reproducible latency and peak-allocation observations at every default JSON
  ceiling;
- formatting, lint, strict typing, architecture, security, compatibility,
  package build and installed-artifact smoke gates.
