# MCP operations and recovery

This is the operator contract for a stateless MCP deployment. Runtime pods own
no authoritative data: PostgreSQL owns Registry/domain and idempotency records;
Temporal owns durable workflows; Qdrant is a rebuildable tenant-filtered search
projection; Valkey is non-authoritative cache/coordination. Never put payloads,
subjects, tenant IDs, tokens, or URLs in dashboards or alerts.

## Objectives and dashboards

Invocation availability is 99.9% per month. Count `tool_failure`, `timeout`,
`overload`, and `dependency_outage` as availability failures; show policy
refusals and cancellations separately. Invocation p99 is product-owned and
must be set from the 250 ms handler baseline plus measured Gateway/runtime
overhead. Activation freshness is p99 <=120 seconds; semantic search is
best-effort and never authorizes invocation; readiness is 99.9% and liveness
has no external dependency.

Dashboard RED and saturation panels use only the bounded runtime metrics in
[observability](observability.md): call rate/error ratio/p99, in-flight,
`mcp_server_saturation_ratio`, retries, limits, cancellations, and
`mcp_telemetry_dropped_count_total`. Add Gateway/Registry aggregates using
immutable version, route generation, condition reason, and safe request ID;
never tenant or tool arguments.

## Paging and action

| Symptom | Threshold | Owner | Action |
| --- | --- | --- | --- |
| Fast burn | 14.4× error-budget burn in both 5m and 1h | MCP runtime on-call | Correlate deployment/version and revert the route/image if correlated. |
| Slow burn | 6x burn in both 30m and 6h | MCP runtime on-call | Isolate outcome/tool/dependency; protect remaining budget. |
| Route stale | desired active version lacks matching Gateway generation for 10m | Gateway/Registry on-call | Read exact activation conditions; keep last-known-good route and repair reconciler. |
| Probe/reconcile backlog | readiness/probe failure or backlog exceeds its reviewed interval for 15m | Gateway on-call | Stop promotion; inspect safe condition/request ID and reconcile only complete snapshots. |
| Auth-denial anomaly | 5m denial rate exceeds reviewed baseline without policy rollout | Security on-call | Compare issuer/audience/key freshness; fail closed, do not relax scopes. |
| Telemetry loss | drops increase for 15m | Observability on-call | Restore collector/exporter; serving remains live. |

Every page has this table's owner, a notification route, and the linked action.
Do not page on CPU or one tool error alone.

## Trace one failed call

Start with the safe request ID and trace ID from Gateway/runtime logs. Join, in
order: immutable Registry ref/digests -> activation generation/condition ->
Gateway route generation -> Kubernetes Deployment/Pod readiness condition ->
Gateway trace -> runtime outcome -> backing API safe correlation ID. A resource
or workflow reference is reauthorized fresh at each step; it is not a session.

## Incident runbooks

- Registry outage: existing exact routes use last-known-good metadata; halt
  publication/activation, page only route-staleness, then restore/read the
  Registry before resuming reconcile.
- Gateway outage: runtime is not bypassed publicly. Restore Gateway capacity
  or revert its GitOps revision; inspect data-plane versus control-plane scope.
- Identity outage: known keys may use the bounded stale window; unknown/new
  identities fail closed. Restore issuer/JWKS connectivity—never disable JWT
  validation.
- Backing API outage: isolate its destination breaker and affected tools;
  preserve unrelated tools, use existing external idempotency on retry, and
  start/inspect Temporal workflows for durable work.
- A bad deployment: keep `maxUnavailable: 0`, restore the prior immutable
  route/image with `git revert --no-edit <failed-tesserix-k8s-commit>`, merge,
  and let Argo CD reconcile. Never use imperative rollout undo.

## Recovery, backup, and cost

Data-plane RPO is zero because pods have no durable state; route recovery RTO
is five minutes from approved revert to ready. Registry metadata RPO/RTO and
backup retention are owned by its PostgreSQL operator: a backup is not valid
until an isolated restore verifies signatures, immutable versions, routes, and
tenant boundaries. Run this game day before GA and record detection/recovery
times without production data.

Revisit capacity and cost after the first load test and production window:
two core replicas request 256 MiB total (512 MiB limit); at the current 210
burst RPS/250 ms p99 plan this is 52.5 concurrent calls. Record per-server
idle/active compute, image retention, trace/log/metric volume, Gateway
cross-zone traffic, and backing-API egress. Scale on saturation, not CPU.
