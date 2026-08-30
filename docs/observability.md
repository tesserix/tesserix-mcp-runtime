# Observability, health, and drain

The runtime emits one bounded operator contract for traces, RED metrics,
structured logs, health probes, and graceful termination. Core aggregation is
local and dependency-free. OpenTelemetry export is optional and lives in the
adapter layer.

## Compose one shared observation pipeline

Use the same `RuntimeObservability` instance for `Application`, owned outbound
clients, and the OpenTelemetry lifecycle. That shared instance preserves the
active request context through authorization, execution, and downstream
client spans.

```python
from tesserix_mcp_runtime import Application, ApplicationLimits, SystemClock
from tesserix_mcp_runtime.adapters.opentelemetry_sdk import OpenTelemetrySDKRuntime

otel = OpenTelemetrySDKRuntime(
    server_name="orders-mcp",
    span_exporter=span_exporter,  # optional OpenTelemetry SDK exporter
    metric_exporter=metric_exporter,  # optional OpenTelemetry SDK exporter
    logger=structured_logger,  # optional JSON log destination
)

application = Application(
    catalog=catalog,
    authorizer=authorizer,
    transport=transport,
    telemetry=error_telemetry,
    limits=ApplicationLimits(drain_timeout=20.0, readiness_timeout=1.0),
    clock=SystemClock(),
    observability=otel.observability,
    lifecycle=(otel,),
    readiness_checks=(registry_check, backing_api_check),
)
```

Pass `otel.observability` to each `OutboundHTTPClient` owned by a tool. Do not
create a second exporter per tool. With no SDK runtime, `RuntimeObservability`
still provides the local Prometheus rendering used by `/metrics`.

The SDK adapter bounds its span queue at 2,048 entries, exports at most 512
spans per batch, uses a five-second export timeout, and reads metrics every 60
seconds by default. Limits can be reduced but not raised above the runtime hard
ceilings. Export exceptions and failure results increment the local dropped
counter and never escape into tool execution.

The SDK's upstream batch processor accepts a span export timeout but does not
enforce it around exporter calls. The runtime therefore allows one exporter
call on a daemon thread, waits at most the configured timeout, and drops later
batches while that call remains blocked. A collector stall cannot accumulate
export threads or hold graceful drain open.

## Trace contract

One accepted call creates the following parent-child sequence:

```text
validated gateway parent
└── mcp.server.request       SERVER
    ├── mcp.tool.authorization  INTERNAL
    ├── mcp.tool.execution      INTERNAL
    └── mcp.client.request      CLIENT, for each owned downstream call
```

Span attributes use only `mcp.server.name`, `mcp.tool.name`, `mcp.operation`,
`mcp.outcome`, and the SHA-256 `mcp.destination.fingerprint` on client spans.
URLs, request IDs, tenant IDs, subjects, headers, payloads, and exception text
are never span attributes. A malformed `traceparent` or `tracestate` is
discarded; the runtime starts a local trace and emits only the stable
`malformed_trace_context` reason.

The outcome vocabulary is `success`, `policy_refusal`, `tool_failure`,
`timeout`, `cancellation`, `overload`, `dependency_outage`, `invalid_input`, and
`limit_exceeded`. Operators and alerts must branch on these values, never on
log messages.

## Prometheus metric contract

The `/metrics` renderer is deterministic Prometheus text. OpenTelemetry uses
the corresponding dotted instrument names. All labels are fixed and bounded;
no metric contains a request, tenant, subject, URL, payload, or error-message
label.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `mcp_server_request_count_total` | counter | `server`, `operation`, `tool`, `outcome` | Completed logical operations |
| `mcp_server_request_duration_seconds_bucket` | histogram | `server`, `operation`, `tool`, `outcome`, `le` | Runtime operation duration |
| `mcp_server_request_duration_seconds_count` | histogram count | same except `le` | Duration sample count |
| `mcp_server_request_duration_seconds_sum` | histogram sum | same except `le` | Duration total |
| `mcp_server_in_flight` | gauge | `server` | Admitted calls not yet released |
| `mcp_server_concurrency_limit` | gauge | `server` | Server admission ceiling |
| `mcp_server_saturation_ratio` | gauge | `server` | In-flight divided by server ceiling |
| `mcp_server_queue_depth` | gauge | `server` | Internal queue depth; zero because overload is shed immediately |
| `mcp_tool_in_flight` | gauge | `server`, `tool` | Active calls for one registered tool |
| `mcp_tool_concurrency_limit` | gauge | `server`, `tool` | Per-tool admission ceiling |
| `mcp_tool_retry_count_total` | counter | `server`, `tool` | Retry delays actually entered |
| `mcp_server_limit_count_total` | counter | `server`, `tool`, `limit` | Global, server, tool, tenant, input, result, or drain limit events |
| `mcp_server_cancellation_count_total` | counter | `server`, `tool` | Calls ending in cancellation |
| `mcp_telemetry_dropped_count_total` | counter | `server` | Local or external telemetry drops |

Registered tool names already obey the runtime grammar and the catalog is
limited to 128 tools. Unknown input never creates a new tool label. The local
RED aggregator additionally caps request series at 2,048.

## Structured log contract

Logs are single JSON objects. `request_completed` contains only `event`,
`server`, redacted `request_id`, `trace_id`, `operation`, registered `tool`,
stable `outcome`, and `duration_seconds`. Lifecycle, readiness, and rejected
trace-context events use stable reason codes. Inputs, outputs, identities,
tokens, URLs, exception strings, and stack traces are not fields.

## Operational HTTP paths

`StreamableHTTPConfig` exposes four explicit same-listener paths. They accept
`GET` and `HEAD`, bypass request authentication, return `Cache-Control:
no-store`, and reveal no identity or dependency detail. Protect the listener
with workload network policy because metrics include registered tool names.

| Path | Success | Unavailable | Dependency behavior |
|---|---|---|---|
| `/startupz` | 200 `started` | 503 `starting` | Never checks dependencies |
| `/livez` | 200 `live` | Listener unreachable | Never checks dependencies |
| `/readyz` | 200 `ready` | 503 `not_ready` | Runs bounded configured readiness checks only while accepting |
| `/metrics` | 200 Prometheus text | Listener unreachable | Reads local memory only |

The MCP and operational paths must all be distinct. Readiness checks run
concurrently inside the configured one-second default and five-second hard
maximum. A false result, exception, or timeout makes readiness false without
exposing the dependency name or failure text. Liveness never calls Registry,
identity, a collector, or a backing API.

`Application.drain()` changes lifecycle state to `draining` before the
transport closes admission. Therefore `/readyz` becomes false first. New work
then receives 503, while accepted work retains its bounded drain window and
`mcp_server_in_flight` reaches zero before stop. `/livez` and `/metrics` remain
available until the listener stops.

## Dashboard contract

A server dashboard can be built only from the metrics above:

1. Call rate by `server`, `tool`, and `outcome` from a five-minute `rate()` of
   `mcp_server_request_count_total`.
2. Error ratio by stable outcome. Treat `tool_failure`, `timeout`, `overload`,
   and `dependency_outage` as availability failures. Show `policy_refusal` and
   `cancellation` separately because they do not necessarily consume the
   platform availability budget.
3. p50, p95, and p99 duration with `histogram_quantile()` over summed
   `mcp_server_request_duration_seconds_bucket` rates.
4. In-flight work, concurrency ceiling, and saturation from
   `mcp_server_in_flight`, `mcp_server_concurrency_limit`, and
   `mcp_server_saturation_ratio`.
5. Top retry and limit reasons from `mcp_tool_retry_count_total` and
   `mcp_server_limit_count_total`.
6. Cancellation and telemetry integrity from
   `mcp_server_cancellation_count_total` and
   `mcp_telemetry_dropped_count_total`.

Do not join logs to produce a metric or extract labels from error text.

## Alert contract

The availability objective is 99.9% per month. Evaluate the failure ratio
described above against the 0.1% error budget. Both windows in a row must fire
before paging.

| Alert | Condition | Severity | Owner | Runbook action |
|---|---|---|---|---|
| Fast SLO burn | 14.4× budget burn over both 5 minutes and 1 hour | page | MCP runtime on-call | Compare outcomes, rollback the current release if correlated, then isolate the failing tool or dependency |
| Slow SLO burn | 6× budget burn over both 30 minutes and 6 hours | page | MCP runtime on-call | Inspect outcome and tool panels, capacity, and dependency health before the budget is exhausted |
| Sustained saturation | `mcp_server_saturation_ratio > 0.9` for 15 minutes with rising overload | ticket | Service owner | Raise replicas or reduce tool concurrency only after checking downstream capacity |
| Telemetry dropped | Any increase in `mcp_telemetry_dropped_count_total` for 15 minutes | ticket | Observability owner | Restore the collector/exporter and verify the counter stops increasing; serving does not require rollback |
| Retry or limit anomaly | Five-minute rate exceeds the service's reviewed baseline | ticket | Service owner | Break down by stable `tool` and `limit`; never page only on CPU or raw retry count |

Every deployed alert must supply the named Owner, a linked Runbook, the
server selector, and a tested notification route. Dashboards may add
deployment metadata outside this runtime contract, but alert correctness must
not depend on payload logs.

## Rollout and rollback

Start with local metrics and probes, then add optional exporters, then enable
alerts in ticket-only mode before paging. Canary a single pod and compare call
outcomes, p99 duration, dropped telemetry, and readiness during termination.
Rollback is one wheel deployment. There is no stored state or migration; the
previous wheel simply removes these spans, metrics, and operational routes.

For local instrumentation regression evidence, run:

```shell
uv run --frozen python benchmarks/measure_observability.py \
  --samples 5000 --warmup 500
```

The checked-in Python 3.14 arm64 macOS observation is 0.313 ms p99 for a
successful no-op application call with all seven observation emissions. It is
not production load or network evidence; issue #29 owns those measurements.

See [ADR-0014](adr/0014-observability-health-and-graceful-drain.md) for the
quantitative decision, failure analysis, alternatives, and residual risk.
