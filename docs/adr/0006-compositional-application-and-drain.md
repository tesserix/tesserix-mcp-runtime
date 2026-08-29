# ADR-0006: Compositional application and bounded drain

- Status: Accepted
- Date: 2026-08-30
- Tracking: [tesserix-mcp-runtime#8](https://github.com/tesserix/tesserix-mcp-runtime/issues/8)

## Context

Every server needs the same composition, admission, lifecycle, signal, and
shutdown behavior without a global singleton or import-time side effect.
ADR-0001 sets the initial per-pod envelope at 50 sustained and 200 burst calls
per second, 64 KiB requests, 512 KiB responses, at most 15 ms p99 runtime-added
latency, startup within 2 seconds, idle RSS within 128 MiB, and 99.9% monthly
invocation availability. The expected catalog is 12 tools and the reviewed
maximum is 128. Deployment grows from approximately 100 servers at 12 months
to 500 at 36 months.

The composition slice adds no network hop, datastore, queue, transaction, or
shared process state. Catalog lookup and in-flight admission are O(1); listing
is O(number of tools); memory is O(number of tools plus in-flight calls).
Local installed-wheel evidence measures startup and idle RSS against the
committed envelope. Load and p99 evidence remains owned by issue #29.

## Decision

### One explicit application object

`Application` is the composition root. Each instance receives one validated
`ToolCatalog`, `Authorizer`, `ApplicationTransport`, payload-safe `Telemetry`
sink, immutable `ApplicationLimits`, `Clock`, and ordered tuple of lifecycle
components. There is no ambient registry, environment lookup, service locator,
or global application. Multiple instances therefore coexist without sharing
catalog, transport, tasks, counters, or state.

Configuration is validated before lifecycle start. Dependency shapes,
component-name grammar, and unique component identities fail with a stable
code and field path before the transport can bind. The catalog and limits
remain their own immutable validation boundaries.

### Dependency and lifecycle order

Author-supplied dependencies start in registration order. The in-flight call
tracker starts next and the transport binds last. Drain and stop reverse that
order: the transport stops admission first, tracked calls finish or are
cancelled at the global deadline, and dependent hooks then unwind in reverse.
Partial startup failure uses ADR-0005's rollback and never reaches readiness.

`Application` exposes startup, ready, draining, and stopped through the
existing `LifecycleState`. Calls and listings are available only while ready.
Once drain changes state, no new application call can register even if it races
the transport drain callback.

### Invocation boundary

The application performs catalog lookup, input conversion, authorization,
handler execution, output conversion, and stable error mapping once. Adapters
delegate to this path instead of copying semantics. Invalid or unknown input
returns `invalid_input`; non-ready admission returns `unavailable`; known and
unknown execution failures use ADR-0005 mapping. Only scrubbed error identities
reach telemetry. A telemetry sink failure does not replace the client result;
the application increments a per-instance failure counter for issue #16 to
export later.

### Monotonic deadlines and signals

`ApplicationLimits.drain_timeout` is a positive finite duration. `Clock` is
injected; `SystemClock` uses monotonic process time and cancellable asyncio
timers. One application-wide timer bounds drain or stop. Cancelling the
in-flight lifecycle component first cancels and joins every tracked invocation,
so deadline return cannot orphan handler tasks.

`ShutdownSignalSource` is injected into `Application.run()`. The Unix
`ProcessSignalSource` scopes SIGINT and SIGTERM handlers to one wait and
removes its handlers afterward. Tests use an in-memory source and clock without
sleeping. `ApplicationRunResult` returns exit code 0 on clean shutdown or 1
with one `ApplicationDiagnostic` containing only a closed reason code,
lifecycle phase, and bounded exception type. Exception messages, hook data,
tool payloads, identities, and credentials are excluded.

The core does not call `sys.exit`, print, or own logging. A process entrypoint
serializes the safe diagnostic and exits with the returned code.
Only one `ProcessSignalSource` owns process-global signals at a time; multiple
application instances use manual lifecycle control or a single process-level
orchestrator rather than competing signal sources.

### Adapter boundary

`ApplicationTransport` and `ApplicationEndpoint` point adapters toward core.
`InProcessTransport` is the deterministic reusable fake. It binds no socket and
is the proof surface for composition tests. Issue #10 owns the MCP SDK v2
Streamable HTTP adapter and listener limits; this decision does not choose a
web framework.

## Failure behavior

| Dependency or failure | Behavior |
|---|---|
| Invalid catalog, limits, dependency, or component identity | Fail before transport start; readiness remains false |
| Lifecycle hook fails during startup | Stop every reached hook in reverse; application becomes stopped |
| Transport start fails | Roll back transport, tracker, and started dependencies; never ready |
| Authorizer fails or denies | Return mapped stable error; handler does not run |
| Telemetry sink fails | Preserve invocation result and increment the per-instance failure counter |
| Drain begins during a call | Reject later calls; allow the accepted call until the monotonic deadline |
| Accepted call exceeds deadline | Cancel and join it before returning the deadline failure |
| Drain or stop hook hangs | Cancel the lifecycle operation; return exit 1 with a scrubbed diagnostic |
| Signal source fails after readiness | Record a scrubbed signal failure, then still drain and stop |

There is no distributed transaction or replay protocol in this slice. A tool
retry is safe only when its owner enforces the idempotency contract; issue #13
owns that enforcement. A process crash loses only ephemeral in-flight work and
the transport session; authoritative product state remains outside the runtime.

## Alternatives considered

- Let every transport own invocation and lifecycle: rejected because MCP,
  in-process, and ADK paths would drift on authorization, error, and drain
  semantics.
- Use a module-level singleton: rejected because tests and multi-server
  processes would share policy, tasks, and shutdown state.
- Put transport types in core: rejected because the dependency arrow would
  point from reusable policy to protocol churn.
- Give each hook its own independent timeout: rejected because serial timeout
  multiplication can exceed Kubernetes termination grace. One global deadline
  bounds the whole operation.
- Add a queue, worker pool, database, or durable orchestrator: rejected because
  this in-process lifecycle has no cross-system commit or wall-clock workflow.

## Consequences, rollout, and rollback

The application adds a set insertion/removal and readiness branch per call,
with no I/O or serialization beyond existing tool behavior. The only new
runtime dependency is the Python standard library. A fresh installed wheel is
tested as a subprocess with real SIGTERM delivery, and startup/RSS measurements
are checked against the committed M0 targets.

This is an additive pre-release API. Rollout is adoption by server entrypoints;
no route, schema, credential, or live service changes. Rollback is reverting
the package commit or returning an entrypoint to direct lifecycle composition.
No data migration or compensation is required.
