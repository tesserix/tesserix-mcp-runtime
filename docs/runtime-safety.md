# Runtime resource safety

`ExecutionLimits` is the reusable application-level safety policy for every
tool call, independent of transport. `StreamableHTTPLimits` adds protocol and
listener bounds before a call reaches the application. Defaults are suitable
for one MCP server per process; every field also has a non-overridable hard
maximum.

## Threat boundary

The protected assets are process memory, handler and downstream capacity,
tenant isolation, private tool results, and availability. An unauthenticated
network caller, an authenticated noisy tenant, a compromised gateway, or a
buggy tool may supply large, deeply nested, slow, duplicated, or retry-inducing
work. HTTP headers and MCP bodies are untrusted until the transport validates
their finite envelope and `GatewayJWTContextProvider` constructs an immutable
`CallContext`. Tool arguments remain untrusted after authentication and are
validated again before parsing. Tool results are untrusted until bounded
serialization completes.

## Application limits

Pass the policy explicitly when composing the application:

```python
from tesserix_mcp_runtime import Application, ExecutionLimits

application = Application(
    catalog=catalog,
    authorizer=authorizer,
    transport=transport,
    telemetry=telemetry,
    limits=application_limits,
    execution_limits=ExecutionLimits(),
)
```

The runtime rejects an invalid policy at construction. Values may be reduced
for a server but cannot exceed these hard maxima:

| Field | Default | Hard maximum |
|---|---:|---:|
| Input JSON | 65,536 bytes | 65,536 bytes |
| Result JSON | 524,288 bytes | 524,288 bytes |
| JSON depth | 16 | 32 |
| Object properties | 128 | 256 |
| Array items | 1,024 | 4,096 |
| Total JSON nodes | 4,096 | 16,384 |
| Tools per server | 128 | 128 |
| Process concurrency | 64 | 256 |
| Server concurrency | 64 | 256 |
| Per-tool concurrency | 32 | 128 |
| Per-tenant concurrency | 16 | 64 |
| Runtime call duration | 30 seconds | 300 seconds |
| Tool duration | 30 seconds | 300 seconds |
| Cancellation grace | 1 second | 5 seconds |
| Attempts including the first | 3 | 5 |
| Initial retry delay | 0.05 seconds | 1 second |
| Retry delay cap | 0.5 seconds | 5 seconds |

JSON traversal is iterative and counts every mapping, list, and scalar node.
Input is rejected before tool parsing or authorization when possible. Result
validation happens before a success value leaves the application; an
over-limit result is replaced by `result_too_large` and no result prefix is
returned.

`SchemaPolicy`, `MetadataPolicy`, `ApplicationLimits`, gateway identity
windows, and Streamable HTTP limits also enforce hard maxima. A deployment
cannot turn a reviewed finite boundary into an unbounded parser, listener,
identity cache, or shutdown.

## Admission and tenant bulkheads

Admission checks process, server, tool, and verified tenant counters
atomically in the event-loop task before handler execution. There is no
internal wait queue. A saturated boundary returns `overloaded` immediately,
with `safe_or_idempotent` retryability, so caller and gateway queues cannot
silently multiply runtime work.

One tenant's counter is independent of another tenant's counter. Tool and
tenant capacity remain held across retries. Every normal success or failure
releases all counters in a `finally` block. If a handler ignores cancellation
and is detached, its capacity remains held until that handler actually exits;
detachment cannot create hidden oversubscription. `Application.detached_invocations`
reports the live count for readiness and later observability integration.

The process concurrency ceiling assumes the supported deployment shape of one
`Application` and one MCP server per process. Run another process when a
server needs a separate failure or scaling domain.

## Deadlines and cancellation

The handler receives the earliest of:

```text
authenticated caller/gateway deadline
runtime admission time + max_call_seconds
runtime admission time + max_tool_seconds
```

`GatewayJWTContextProvider` accepts one positive decimal
`X-Tesserix-Timeout-Ms` value, clamps it to its configured maximum, and has a
30-second non-overridable gateway ceiling. Missing, duplicated, zero,
non-decimal, non-ASCII, leading-zero, or overlong values fail authentication
without echoing the value.

Caller cancellation, HTTP disconnect, protocol cancellation, and effective
deadline expiration signal the linked `context.cancellation` before the
runtime cancels the handler task. Handlers and downstream clients must use the
same deadline and cancellation object and release connections in `finally`:

```python
async def handler(input_model: Input, *, context: CallContext) -> Output:
    async with downstream_client(deadline=context.deadline) as client:
        request = asyncio.create_task(client.fetch(input_model.identifier))
        cancelled = asyncio.create_task(context.cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {request, cancelled},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancelled in done:
                raise asyncio.CancelledError
            return await request
        finally:
            for task in (request, cancelled):
                task.cancel()
```

A cancelled handler gets the configured grace period to clean up. A handler
that suppresses task cancellation is detached after that one grace period and
the caller receives one stable `timeout` or `cancelled` result. Streamable HTTP
also caps an SDK request or response stream at 300 seconds by default and hard
maximum. An expired uncommitted stream returns a bounded 504 with stable
`timeout` data and cannot emit a late response.

## Retry contract

The runtime retries only these calls:

| Tool effect | Idempotency declaration | Verified key | Retry eligible |
|---|---|---|---|
| Read | not applicable | optional | yes |
| Write or external effect | required | present | yes |
| Write or external effect | required | absent | no |

Eligible calls retry only `ConnectionError`, `TimeoutError`, `overloaded`, or
`unavailable`. Validation, authentication, authorization, approval, conflict,
cancellation, result overflow, and unknown failures are never retried.
Backoff is capped exponential with deterministic request-scoped jitter. The
attempt count includes the first call. A retry whose next delay would reach or
cross the original effective deadline is not started; the result is `timeout`.
The same immutable context and idempotency key reach every eligible mutation
attempt. The backing service remains the authoritative idempotency store.

The gateway, service mesh, and runtime must not all retry the same call. The
runtime owns tool-handler retries; upstream layers should preserve the
deadline and use the returned retryability classification.

## Stable outcomes

| Code | Retryability | Meaning |
|---|---|---|
| `overloaded` | `safe_or_idempotent` | A concurrency boundary is saturated |
| `timeout` | `safe_or_idempotent` | The effective deadline expired |
| `cancelled` | `never` | The originating caller cancelled |
| `unavailable` | `safe_or_idempotent` | A transient required dependency failed |
| `result_too_large` | `never` | A tool result exceeded a finite boundary |

Messages are fixed and payload-free. Arguments, results, tenant values,
credentials, exception text, and partial serialized output do not enter these
responses.

## Measurement and operations

The ceiling benchmark validates and serializes a value at each default JSON
dimension, then records p50, p99, maximum latency, and peak temporary Python
allocation:

```bash
uv run --frozen python benchmarks/measure_execution_limits.py --samples 100
```

The checked-in Python 3.14 observation is
[`benchmarks/execution-limits-observations.json`](../benchmarks/execution-limits-observations.json).
Its largest measured p99 was 3.65 ms and its largest temporary allocation was
1,181,398 bytes at the 512 KiB result ceiling on the recorded arm64 macOS
host. These are local regression evidence, not production capacity claims.

Container termination grace must exceed the longest deployed call deadline
plus cancellation grace. Readiness may shed when capacity or detached-work
thresholds are reached; liveness must not depend on downstream services.
Issue #16 owns RED metrics and readiness wiring, and issue #29 owns sustained
load and soak evidence.

Rollout is a normal library version update with limits first kept at defaults.
Rollback is one dependency-lock reversion to the prior runtime. No database,
queue, credential, network route, or live infrastructure mutation is added by
this safety layer.
