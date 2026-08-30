# ADR-0014: Observability, health, and graceful drain

## Status

Accepted.

## Context

Each server needs the same answer to five operator questions: is it receiving
work, is work succeeding, is it saturated, is it safe to receive traffic, and
did telemetry itself fail? Per-server implementations would drift in names,
cardinality, redaction, probe behavior, and shutdown ordering.

The M1 envelope is 50 sustained and 200 burst calls per second per pod, at
most 128 tools, 64 KiB inputs, 512 KiB results, less than 15 ms runtime-added
p99 latency, less than two seconds startup, and 99.9% monthly availability.
Typical servers expose 12 tools. Production load and soak proof remains with
issue #29; these are design targets, not a new production performance claim.

The process must remain useful when no collector exists. It must also avoid a
collector outage becoming a serving outage or a backing dependency outage
causing Kubernetes to restart every pod.

## Decision

### Core aggregation and adapter direction

Add a core `RuntimeObservability` contract and finite in-memory Prometheus
aggregation. Core imports no OpenTelemetry package. The adapter translates the
fixed runtime vocabulary into OpenTelemetry API spans and instruments. The
OpenTelemetry API is a small base dependency because the included adapter uses
it; the SDK remains in the optional `otel` extra.

One observation instance is composed into `Application`, its
`ExecutionController`, and owned `OutboundHTTPClient` instances. Export is
optional. Without it, local metrics and health continue to work.

### Traces

Every accepted call owns one `mcp.server.request` SERVER span. Authorization
and tool execution are INTERNAL children. Each owned outbound call is a CLIENT
child carrying only a SHA-256 destination fingerprint. Validated W3C gateway
context is the request parent. Malformed trace context is discarded, starts a
local trace, and records a stable reason without the supplied value.

Span attributes are limited to server, registered tool, operation, outcome,
and destination fingerprint. Trace identity stays in the OpenTelemetry span
context rather than a metric label. Cancellation is caught only long enough to
set span outcome and is then re-raised.

### Metrics and logs

Emit RED count and duration by server, operation, registered tool, and stable
outcome. Emit in-flight work, capacity, saturation, queue depth, retry, limit,
cancellation, and dropped-telemetry signals. Immediate overload shedding means
queue depth is normally zero. Tool registration grammar, the 128-tool ceiling,
and a 2,048-series local cap bound cardinality.

Metrics never label tenant, subject, request ID, URL, payload, exception
message, or arbitrary input. Structured logs contain a redacted request ID,
trace ID, registered tool, operation, outcome, duration, event, server, and
stable reason only. Opaque request bodies remain non-DLP payloads and are not
logged or scanned.

### Bounded OpenTelemetry SDK lifecycle

Provide an optional lifecycle adapter with a maximum 2,048-span queue,
512-span export batch, five-second export timeout, five-second batch schedule,
and 60-second periodic metric export. Operators may reduce but not exceed the
hard ceilings. Export exceptions and failure results become local dropped
events; tool work continues. Drain forces a bounded flush, and stop shuts down
providers off the event loop.

### Health and operations

The Streamable HTTP listener reserves distinct `/startupz`, `/livez`,
`/readyz`, and `/metrics` paths. Startup reports whether application start
completed. Liveness is dependency-free. Readiness requires lifecycle `ready`,
open transport admission, and all configured dependency checks succeeding
concurrently inside a one-second default and five-second hard maximum.

Lifecycle enters `draining` before the transport closes admission. Readiness
therefore turns false first. Admission then returns 503, existing work drains
under the application deadline, in-flight gauges reach zero, and liveness plus
metrics remain available until listener stop.

Operational routes bypass gateway identity because Kubernetes must probe them.
They expose no dependency details or caller data. Network policy must keep the
listener private because metrics include registered tool names.

### Dashboard and alerts

The documented contract derives rate, failure ratio, latency quantiles,
saturation, retry, limit, cancellation, and telemetry integrity exclusively
from emitted metrics. A 99.9% availability objective uses multi-window burn
alerts: 14.4 times budget over 5 minutes and 1 hour, and 6 times over 30 minutes
and 6 hours. Policy refusals and caller cancellations are displayed separately
from availability failures. Every alert requires an owner, runbook, and
actionable response.

## Dependency and failure analysis

- Collector unavailable or exporter raises: bounded batches are dropped,
  `mcp_telemetry_dropped_count_total` increases locally, and serving continues.
- Export queue fills: the SDK retains at most 2,048 spans; excess telemetry is
  discarded rather than consuming unbounded memory.
- Metric/log/span adapter raises synchronously: the safe core wrapper counts a
  drop and returns control to the tool path.
- Readiness dependency is false, slow, or raises: readiness returns 503 with no
  dependency name or error, while liveness stays 200.
- Malicious unknown tool input: it cannot create a metric tool label; only a
  registered normalized name or `none` is used.
- Malformed gateway trace headers: verified identity continues, trace context
  falls back locally, and only `malformed_trace_context` is logged.
- Process receives termination while work is active: readiness changes first,
  new admission closes, accepted work finishes or is cancelled at the bounded
  drain deadline, then exporters flush and the listener stops.

There is no datastore, queue service, transaction, cache, cross-process
coordination, or recovery workflow. Metrics and traces are diagnostic and
never a source of truth.

## Alternatives considered

### Require an OpenTelemetry collector and SDK in core

Rejected. It increases the minimum dependency and startup footprint and makes
local health depend on external telemetry infrastructure.

### Let every server define its own instruments and probes

Rejected. Names, outcomes, labels, redaction, and drain ordering would drift,
preventing one reusable dashboard and safe fleet-wide alerts.

### Put health and metrics on a second listener

Rejected as the default. A second socket adds configuration, policy, probes,
and shutdown behavior. Explicit distinct same-listener paths satisfy the
current private sidecar topology; a future adapter may bind them separately
without changing the core operations protocol.

### Check dependencies from liveness

Rejected. A Registry or backing API outage would restart healthy runtime pods,
amplify load, and reduce availability. Dependency checks belong only in
bounded readiness.

### Label metrics with tenant, request, URL, or error message

Rejected. Those values are high-cardinality, may be sensitive, and are not a
stable operator vocabulary. Traces and redacted structured logs provide
request correlation.

## Security and residual risk

The assets are verified identity, payload confidentiality, credentials, tool
results, and telemetry availability. Attackers include unauthenticated callers,
another tenant, a malicious dependency response, and a compromised exporter.
The gateway-to-runtime request and runtime-to-collector links are trust
boundaries; caller metadata is validated and payload data never becomes
telemetry by default.

A registered tool name and destination fingerprint still reveal bounded
service topology. Operational paths must remain private. A compromised process
or custom exporter can observe in-process data and is outside field-level
redaction guarantees. Sampling and collector retention are deployment policy;
this runtime only bounds local buffers and fields.

## Verification

In-memory OpenTelemetry exporters assert exact parentage, span kinds,
attributes, outcomes, and metric labels. Application tests cover exporter
failure, cancellation, retry, limit, and canary exclusion. Gateway tests prove
malformed trace fallback. Outbound tests prove client parentage and URL-free
fingerprints. Drain integration proves readiness changes before transport
admission closes and in-flight work returns to zero. Streamable HTTP tests
exercise all four same-listener operational paths without network sockets.

The checked-in successful no-op application benchmark exercises all seven
hot-path observation emissions over 5,000 samples. Python 3.14 arm64 macOS
observed a 0.313 ms p99 against the unchanged 15 ms runtime budget. This is a
local instrumentation regression result; issue #29 retains production load,
transport, pod-shape, and soak proof.

Full formatting, lint, strict mypy and Pyright, unit, compatibility, security,
dependency, build, artifact, and package-size gates remain required before
merge. Runtime p99 and startup observations are reported against ADR-0001's
unchanged envelope rather than weakening it.

## Rollout

1. Deploy local metrics and probe paths with exporters disabled.
2. Verify startup, readiness, liveness, and termination on one canary pod.
3. Enable bounded exporters and confirm dropped telemetry remains flat.
4. Build the documented dashboard and run synthetic call, refusal, timeout,
   overload, and collector-outage exercises.
5. Enable ticket alerts, then paging burn alerts after a reviewed baseline.

## Rollback

Deploy the previous wheel. There is no persisted state or migration. Revert
probe paths in the owning GitOps repository in the same rollout so Kubernetes
does not target removed routes. Existing telemetry dashboards will become
absent but serving behavior and backing data are unchanged.

## Consequences

Every server receives one trace and metric vocabulary, safe logs, consistent
probes, and deterministic drain behavior. Operators can build one dashboard
and SLO alert set without payload inspection. The costs are bounded local
metric state, OpenTelemetry API in the base dependency closure, optional SDK
worker resources, four reserved paths, and readiness probe traffic to explicitly
configured dependencies.
