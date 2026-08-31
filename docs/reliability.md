# Reliability qualification

This runbook produces bounded, sanitized reliability evidence for a Tesserix
MCP server. It does not publish an image, mutate Registry state, or change a
cluster.

## Stateless contract

Every MCP call is independently routable. The request carries verified
workload identity, tenant authority, tool and arguments, authorization,
request and trace identifiers, an external idempotency key for mutations, and
an optional opaque conversation reference. The runtime retains no user,
tenant, conversation, previous-call, or workflow state.

PostgreSQL or the backing application owns domain state; Valkey may coordinate
bounded caches, limits, or idempotency; object storage owns artifacts; Temporal
owns durable waits and workflows; the Registry owns tool metadata; and the
Gateway owns authentication and policy. The MCP pod owns none of those records.
In-memory cancellation, concurrency, metrics, breaker, and verified-key caches
are disposable and reconstructible.

The production transport is `stateless_http=True`. Requests carrying
`Mcp-Session-Id` fail, and the Service uses no session affinity. The stateless
test alternates two replicas, requires every delivery to succeed, and requires
one external effect for a shared idempotency key. It leaves request-owned memory
and request-owned filesystem entries at zero after the calls.

## Offline deterministic evidence

From the repository root:

```bash
uv run --frozen python benchmarks/measure_reliability.py
```

The command exercises in-process sustained, burst, boundary, soak,
cross-replica statelessness, duplicate delivery, dependency failure, and
rollout scenarios. It prints JSON. The checked-in
`benchmarks/reliability-observations.json` is the reviewed result for the
default bounded plan.

No raw payload, authorization token, tenant identifier, conversation
reference, exception traceback, or dependency URL belongs in evidence. A
report may retain bounded counts, safe outcome names, timings, platform
version, and SHA-256 digests only.

The deterministic dependency matrix is:

| Injection | Required result |
| --- | --- |
| Registry outage | Cached serving path succeeds; unaffected calls succeed |
| AgentGateway outage | Affected calls are unavailable; runtime queue remains bounded |
| Identity refresh outage | Bounded stale verified keys succeed, then new identity fails closed |
| Blocked telemetry export | Calls succeed, bounded records drop, drop counter increases |
| DNS latency or outage | Affected calls time out, destination circuit opens, other destinations succeed |
| Backing API outage | Affected calls fail safely, runtime retry cap holds, destination circuit opens |
| Duplicate mutation delivery | All deliveries return the recorded result and create one external effect |
| SIGTERM or eviction | New work is rejected and accepted work drains within 45 seconds |
| Rolling update | Previous capacity remains and user-visible interruption stays within five seconds |
| Canary abort or rollback | Previous route remains/restores without losing accepted work |

## Real transport evidence

Build and start the immutable runtime image using the compatibility stack, then
measure the direct lane:

```bash
uv run --frozen python compatibility/measure_reliability.py \
  --endpoint http://127.0.0.1:38080/mcp \
  --lane direct_http \
  --report /tmp/direct-reliability.json
```

Start the digest-pinned AgentGateway compatibility container and measure the
Gateway route:

```bash
uv run --frozen python compatibility/measure_reliability.py \
  --endpoint http://127.0.0.1:33000/gateway/runtime/mcp \
  --lane agentgateway \
  --report /tmp/agentgateway-reliability.json
```

Each lane must complete 100 sustained calls, 200 burst calls, and four boundary
calls at 60,000 request bytes and 500,000 response bytes without an error or an
unbounded queue. The lane is encoded in the target and report, so a direct run
cannot be submitted as AgentGateway evidence.

The default command is a qualification run and enforces both 50 sustained and
200 burst calls/second. GitHub-hosted PR runners are not controlled performance
hosts, so the compatibility workflow passes `--compatibility-smoke`: that mode
still requires every call, boundary, and queue check to pass but does not claim
rate qualification. It marks the report targets with `compatibility_smoke`, and
the correlator rejects such a report. Never retain or promote smoke output as
qualification evidence.

Correlated Gateway evidence uses one fresh isolated container pair per load
kind. Verify the chosen loopback ports are unused; never run this load against a
cluster or production endpoint. Enable `--reliability-spans` on the
compatibility server. Its bounded exporter writes only
`TESSERIX_RELIABILITY_SPAN` records for `mcp.tool.execution`; it retains no
trace, request, tenant, argument, result, or tool identifier and does not add
the OpenTelemetry SDK to the runtime core.

For each of `sustained`, `burst`, and `boundary`, capture the Gateway and
runtime Prometheus endpoints before the client starts. Sample the runtime
container into temporary JSON Lines with repeated non-streaming reads so
terminal control bytes cannot enter evidence:

```bash
mkdir -p /tmp/reliability/sustained
curl --fail --silent --show-error \
  --output /tmp/reliability/sustained/gateway-before.prom \
  http://127.0.0.1:31520/metrics
curl --fail --silent --show-error \
  --output /tmp/reliability/sustained/runtime-before.prom \
  http://127.0.0.1:38080/metrics
while docker stats --no-stream --format '{{json .}}' compatibility-runtime
do
  :
done > /tmp/reliability/sustained/pod-resources.jsonl &
resource_sampler=$!
```

Run exactly one client window, then stop the sampler and capture the two final
counter snapshots plus the safe span records:

```bash
uv run --frozen python compatibility/measure_reliability.py \
  --endpoint http://127.0.0.1:33000/gateway/runtime/mcp \
  --lane agentgateway \
  --kind sustained \
  --report /tmp/reliability/sustained/client.json
kill "$resource_sampler"
wait "$resource_sampler" || true
curl --fail --silent --show-error \
  --output /tmp/reliability/sustained/gateway-after.prom \
  http://127.0.0.1:31520/metrics
curl --fail --silent --show-error \
  --output /tmp/reliability/sustained/runtime-after.prom \
  http://127.0.0.1:38080/metrics
docker logs compatibility-runtime 2>&1 \
  | rg '^TESSERIX_RELIABILITY_SPAN ' \
  > /tmp/reliability/sustained/runtime-spans.log
```

The reusable correlator parses the bounded raw sources, rejects decreasing or
incomplete counters, derives histogram and span p99 values, checks that client,
Gateway tool-call, runtime metric, and runtime span counts join exactly, and
emits only aggregates plus a digest of the source window:

```bash
uv run --frozen python compatibility/correlate_reliability.py \
  --kind sustained \
  --client-report /tmp/reliability/sustained/client.json \
  --gateway-before /tmp/reliability/sustained/gateway-before.prom \
  --gateway-after /tmp/reliability/sustained/gateway-after.prom \
  --runtime-before /tmp/reliability/sustained/runtime-before.prom \
  --runtime-after /tmp/reliability/sustained/runtime-after.prom \
  --runtime-spans /tmp/reliability/sustained/runtime-spans.log \
  --pod-resources /tmp/reliability/sustained/pod-resources.jsonl \
  --output /tmp/reliability/sustained/correlation.json
```

Repeat with fresh containers and `--kind burst` and `--kind boundary`.
AgentGateway performs bounded discovery/list traffic around tool calls, so its
duration sample count may exceed its exact `tools/call` count; the correlator
requires the latter, runtime metrics, runtime spans, and client samples to equal
the requested window. Commit only the merged sanitized summary. The reviewed
result is `benchmarks/agentgateway-reliability-correlation.json`; raw
Prometheus, span, resource, and client files remain temporary and must not be
committed.

## Capacity and scaling

`deploy/kubernetes/reference/capacity-plan.json` is the machine-readable
arithmetic. At 210 burst calls/second and 250 ms p99, concurrent demand is
52.5. A 64-call pod at 50% normal occupancy supplies 32 normal slots, so two
pods cover the burst and the availability floor. Observed 112 MiB peak RSS is
covered by a 128 MiB request and 256 MiB limit. There is no CPU limit for the
I/O-bound reference.

`deploy/kubernetes/reference/horizontal-pod-autoscaler.json` scales from two to
ten replicas on `mcp_server_saturation_ratio` at 0.5, with a 300-second
scale-down stabilization window. Adoption must confirm the custom metric is
available and recompute all inputs for the product handler. The reference
placeholders remain deliberately non-deployable.

## Promotion and failure handling

A result passes only when all loads meet their envelope, all six bounded
resources remain within budget, every concurrency dimension is evidenced,
cross-replica calls retain no request state, retry ownership is singular,
every dependency has contained blast radius, every rollout drains, and the
capacity plan covers observations. Artifact and profile digests must match the
candidate under review.

Adopt the reference through `tesserix-k8s`; do not apply it imperatively.
Argo CD must own rollout and rollback. Keep the prior image and Registry route
through the observation window. Rollback is one reviewed Git revert. A failed
canary is aborted before traffic changes; a post-cutover regression restores
the previous route within the five-minute RTO.
