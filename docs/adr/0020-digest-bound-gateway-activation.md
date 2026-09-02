# ADR-0020: Digest-bound Gateway activation and observable status

## Status

Accepted. The runtime-side contract and observer are implemented. Registry and
Gateway writers remain rollout-blocked on the linked owning-repository issues.

## Context and quantitative envelope

Publication does not prove that a server is safely routable. A Registry write
can succeed while its delivery artifact is unavailable, AgentGateway resources
are rejected, an authenticated MCP handshake fails, a tag moves, or a stale
controller reports success for an older deployment. Treating any one of those
events as “active” exposes unready or unauthorized tools.

The existing source at Agentic Registry commit
`6921474591b6c59e89025370c310c7f85859246f` already provides a signed immutable
artifact read, capability probing, `Ready`/`Unreachable`/`Drifted` observations,
an HA Lease-elected Registry-to-AgentGateway controller, strong snapshot ETags,
condition-aware apply, and last-known-good retention. The GitOps source at
`tesserix-k8s` commit `1805e20336a52c4995e9373ab6f291e45733b6e7`
wires two controller replicas in shadow mode, a 30-second poll, a five-minute
safety reconcile, a 20-second resource-acceptance deadline, a 15-minute probe
CronJob, and a retained five-minute route-sync rollback CronJob. It currently
sources only `devai` and does not enforce per-server scopes. Neither repository
has a complete per-version activation generation or publisher-facing status.

Current production desired state is 52 Registry-owned resources and less than
1 MiB. The 36-month design envelope is fewer than 1,000 resources and a 5 MiB
snapshot. Registry mutations stay below one request/second at peak with more
than 20 reads per write. One CLI waiter polling every two seconds adds 0.5 read
requests/second; five concurrent release waiters add 2.5 requests/second.

For a healthy server, the control-plane objective is 99.9% monthly availability
and publish-commit-to-active p99 no greater than 120 seconds:

| Stage | Budget |
| --- | ---: |
| Registry poll and verified snapshot pickup | 30 seconds |
| Backend, policy, and probe-route acceptance | 20 seconds |
| Authenticated modern discovery and bounded operation probe | 30 seconds |
| Public-route acceptance and status feedback | 20 seconds |
| Status propagation and scheduling margin | 20 seconds |

Already accepted data-plane routing has RTO 0 during Registry, reconciler, or
status-store outage. Its RPO is the last accepted, authenticated-probe-proven
immutable digest. Probe evidence becomes stale after 20 minutes; the existing
15-minute probe remains the safety path after immediate activation probing is
added.

Assets worth protecting are Registry publication authority, immutable artifact
identity, tenant route and policy state, OAuth credentials, tool inventory, and
last-known-good routing. Attackers include an unauthenticated caller, another
authenticated tenant, a compromised publisher/controller/prober, and a
compromised dependency. Trust is crossed at Agentic Registry auth, Registry
status observation writes, Kubernetes API apply, AgentGateway authorization,
and the MCP protocol probe. Every boundary validates identity, object scope,
generation, and both digests.

## Decision

### One versioned contract, not one shared mutable flag

Registry exposes `status.activation` using the closed
[`v1alpha1` JSON Schema](../../contracts/activation-status-v1alpha1.schema.json).
The contract binds all observations to:

- the exact `mcpservers/<namespace>/<slash/name>@<version>` reference;
- Registry canonical SHA-256 digest;
- delivery artifact SHA-256 digest;
- a positive monotonic desired-state generation; and
- canonical UTC observation and transition timestamps.

The contract is closed (`additionalProperties: false`). A field, condition,
actor, or semantic change requires another schema version rather than silently
changing `v1alpha1`. Conditions contain bounded reason codes and request IDs,
never arbitrary messages, protocol payloads, claims, tokens, or tool schemas.

Registry alone derives `phase` and persists `activeAt`. Every consumer,
including the Python observer, independently re-derives the phase and rejects a
mismatch. No component may overwrite a single generic status string.

| Condition | Exclusive writer | Meaning when `True` |
| --- | --- | --- |
| `Published` | Registry | Signed immutable version and both digests are committed |
| `DeploymentReady` | Gateway reconciler | Backend, required policy, and mesh-only probe route are accepted for this generation |
| `ProbeReady` | Protocol prober | Authenticated `server/discover` and a bounded self-contained operation succeeded for this generation |
| `Healthy` | Protocol prober | Current probe evidence is successful and within its freshness window |
| `RouteReady` | Gateway reconciler | Public route and references are accepted for this generation |
| `Failed` | Registry | Activation ended terminally before first public activation |

Actor endpoints compare-and-set on generation plus both digests. Duplicate
reports are idempotent. Lower, mixed, or moved observations are rejected and
cannot resurrect an old route. The CLI pins the first observed generation when
the caller does not supply one, rejects a later generation change, and rejects
regressing `observedAt` timestamps.

### Deterministic phase state machine

Runtime process `LifecycleState` (`startup`, `ready`, `draining`, `stopped`) is
unrelated and remains unchanged. Gateway activation has these states:

| Phase | Derivation and routing consequence |
| --- | --- |
| `draft` | Desired state is draft; no committed Registry version or route |
| `published` | `Published=True`; immutable version exists but no accepted stage deployment |
| `deployed` | `DeploymentReady=True`; only the mesh-only probe path may reach it |
| `probed` | `ProbeReady=True` and `Healthy=True`; public promotion is pending |
| `active` | All readiness conditions are true and `activeAt` is set; public route may serve |
| `degraded` | A previously active generation is no longer fully ready; retain or restore the most recent healthy last-known-good digest |
| `deprecated` | Lifecycle intent is deprecated; existing route remains observable during the retirement window, but new activation waits do not treat it as active |
| `retired` | Lifecycle intent is retired; remove discovery and route state, returning non-disclosing 404 |
| `failed` | `Failed=True` before first activation; never create a public route |

Lifecycle intent (`draft`, `published`, `deprecated`, `retired`) takes precedence
over readiness. A terminal failure after a version was active is represented as
`degraded`, not `failed`, so last-known-good recovery remains explicit.

The linear progress states may be skipped by observation. For example, a waiter
for `deployed` succeeds if its first exact observation is already `active`.
Deprecated, retired, failed, and degraded are not treated as historical success
for an `active` wait.

### Staged activation and last known good

1. Publisher commits and verifies one immutable Registry version.
2. Registry export renders the backend, required per-server authorization
   policy, and mesh-only probe route with generation and digest annotations.
3. The reconciler applies idempotently, waits for backend/policy acceptance and
   probe-route `Accepted=True` plus `ResolvedRefs=True`, then reports
   `DeploymentReady`.
4. The immediate prober authenticates like an ordinary machine client through
   the mesh-only listener, performs modern `server/discover` and a bounded
   self-contained operation (or the legacy handshake only for an explicitly
   declared compatibility revision), and
   reports `ProbeReady` and `Healthy`.
5. Registry export adds the public route. The reconciler reports `RouteReady`
   only after public acceptance, resolved references, and policy acceptance.
6. Registry derives `active` and advances the last-known-good pointer only now.

Public desired state never points at a merely published, deployed, probed,
failed, stale, or digest-mismatched candidate. A crash at any step leaves extra
staged resources at worst; replay is idempotent and pruning is forbidden until
all replacement acceptance gates pass. If no prior healthy version exists, the
system reports degraded/failed honestly rather than inventing availability.

Deprecation is a reversible observation window in this pre-GA contract;
retirement is the route-removal transition. Retirement and rollback operate on
immutable refs and digests, never mutable `latest` state.

### Bounded publisher observation

The opt-in publisher package owns a reusable typed status model, exact Agentic
CLI adapter, and monotonic waiter. It does not write Registry status, mutate
Kubernetes, run a probe, or activate a route. `agentic` continues to own
credentials, tenant selection, and Registry transport.

One-shot observation succeeds even when the observed phase is failed: the read
itself succeeded. A wait returns nonzero for incompatible terminal state or
deadline. Registry read failures are retried only when the delegated adapter
marks them retryable. The default wait is 120 seconds with a two-second poll;
the hard bounds are 0.1–900 seconds and 0.1–30 seconds respectively. Sleeps
never cross the monotonic deadline and cancellation propagates without being
converted to a status.

### Ownership and linked delivery

The runtime repository owns the schema, typed consumer, safe explanation, CLI,
and architecture decision. Missing producer and rollout work is tracked in:

- `tesserix/agentic-registry#105`: persist and derive per-version activation;
- `tesserix/agentic-registry#103`: gate AgentGateway export by phase;
- `tesserix/agentic-registry#104`: immediate authenticated protocol probing;
- `tesserix/tesserix-k8s#754`: staged reconciliation and status feedback;
- `tesserix/tesserix-k8s#753`: last-known-good, failure injection, and SLO proof;
- `tesserix/tesserix-k8s#752`: per-server policy acceptance and negative auth.

Automatic production activation remains unavailable until those dependencies
are implemented, the controller is promoted from shadow through GitOps, and
the existing CronJob is suspended so exactly one writer remains.

## Failure and consistency analysis

- Registry unavailable before status read: retry only its safe retryable error
  until the caller deadline; already accepted routes continue.
- Controller or Kubernetes API unavailable: candidate remains published or
  deployed; no public promotion; replay the same generation.
- Crash between apply and report: object annotations retain identity; duplicate
  apply/report is idempotent.
- Probe auth, negotiation, size, drift, or timeout failure: do not promote;
  retry while allowed, then derive failed. Raw error and protocol payload are
  discarded.
- Public route or policy rejection: keep prior public route and report the
  bounded condition reason/request ID.
- Tag moves or generation changes during wait: return non-retryable superseded
  status. The caller starts a new wait only after reviewing the new identity.
- Stale observation arrives after promotion/retirement: Registry CAS rejects it;
  clients also reject mixed identities and decreasing observation time.
- Registry status write fails after Kubernetes acceptance: do not infer success
  from Kubernetes alone; retry the idempotent report.
- Scheduled probe becomes stale: mark health unknown/false and derive degraded;
  do not let an old successful probe authorize a new generation.
- Duplicate polls or reports: strong snapshot digest and exact generation make
  them idempotent.

The system is eventually consistent for new activation, bounded by the 120
second objective. Existing data-plane requests remain independent of Registry,
reconciler, status store, and probe availability.

## Security and authorization

Registry derives publisher identity and tenant from authenticated context, not
request bodies. Observation endpoints authorize the actor and exact object;
another tenant receives non-disclosing not-found behavior. The reconciler and
prober can mutate only their named conditions. Registry alone mutates phase,
failure, and lifecycle intent.

All delegated commands use argv without a shell. Refs reject URLs, queries,
credentials, traversal segments, whitespace, and control characters while
retaining slash-containing artifact names. Digests are lowercase SHA-256.
Status and errors expose only identity, phase, safe reason, request ID, bounded
timestamps, and retryability. They never echo Registry documents, MCP payloads,
JWTs, headers, tool inputs/results, or secret-bearing environment values.

Public `RouteReady` requires the exact per-server policy to be accepted and its
identity roles provisioned first. The current `requireServerScope=false` state
cannot satisfy production activation.

## Alternatives considered

- Treat publication as active: rejected because it bypasses deployment,
  protocol, health, and authorization evidence.
- Let every component write one phase string: rejected because concurrent stale
  writers can regress or forge state.
- Use only Kubernetes object conditions: rejected because publisher/UI clients
  lack namespace access and object conditions do not bind the runtime artifact.
- Keep only the 15-minute probe CronJob: rejected because it cannot meet a
  bounded release activation objective.
- Introduce an event bus now: rejected for the polling baseline; fewer than one
  change/second and a 120-second SLO do not justify another durable system.
  Event-driven reconciliation remains a later measured decision.
- Put Kubernetes credentials or Registry write authority in the runtime:
  rejected by least privilege and failure-domain separation.

## Rollout, rollback, observability, and cost

Rollout is additive: ship the Registry schema/endpoints, gated export, immediate
probe, and status feedback while the controller remains shadow. Verify exact
snapshot/resource identities, condition ownership, one leader, two ready
replicas, auth negatives, MCP invocation, SLO metrics, and alerts. A separate
GitOps change promotes the controller to active and suspends the CronJob.

Rollback is one reviewed Git revert to shadow/disabled plus replay of the
selected last-known-good immutable ref before unsuspending the CronJob. Rollback
must never fetch mutable latest or prune from an unverified export. Retirement
is not deletion of immutable Registry history.

Metrics cover activation duration and stage lag, stuck phase, stale probe,
generation/digest mismatch, status-write error, reconcile error, drift, and
leader cardinality. Refs, request IDs, tenants, and subjects stay out of metric
labels. Alerts use SLO burn or actionable stuck thresholds with a runbook.

The runtime observer adds no always-on service or storage. Polling costs one
short `agentic pull` process and Registry read per interval. Control-plane cost
remains two 64 MiB-request/128 MiB-limit sync pods plus scheduled probe Jobs;
immediate probes add one bounded call per activation. The six linked issues must
measure and revise these pre-GA assumptions before production promotion.

## Verification

- typed fixtures derive and safely explain all nine phases;
- JSON Schema and checked-in active example remain compatible with public enums;
- invalid actors, duplicate/mixed conditions, payload fields, unsafe refs,
  regressing observations, generation moves, and digest moves fail closed;
- fake-clock tests prove progression, safe retries, terminal behavior, and exact
  timeout without wall-clock sleep;
- Agentic adapter tests prove exact slash-name argv, metadata/spec/status digest
  agreement, bounded output, and secret-safe failure;
- CLI tests prove one-shot observation, wait-to-active, timeout exit/details,
  and no manifest/tool payload output;
- full package tests, Ruff, strict mypy, strict Pyright, public API snapshots,
  builds, and security checks remain required before merge.
