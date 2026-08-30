# ADR-0021: Identity-scoped tenant Gateway reconciliation

## Status

Accepted. The reusable contract, reference eligibility evaluator, route identity
derivation, complete-snapshot validator, and cursor-page assembler are
implemented in this repository. Registry, identity-control-plane, controller,
and GitOps rollout remain blocked on linked owning-repository issues.

## Context and quantitative envelope

Adding a tenant to Gateway reconciliation currently requires a Git change. At
Agentic Registry commit `6921474591b6c59e89025370c310c7f85859246f`,
`GET /v0/export/agentgateway` accepts a caller-supplied comma-separated
`namespace` query. It calls `Store.List` once for every supplied namespace but
does not follow `NextCursor`; the shared store default is 50 results. The route
adapter drops non-DNS characters and truncates names to 63 characters, so two
distinct Registry identities can collapse to one Kubernetes name or route
path. Legacy flat paths default on and per-server scope policy defaults off.

At `tesserix-k8s` commit
`1805e20336a52c4995e9373ab6f291e45733b6e7`, the route-sync chart hard-codes
`registry.sourceNamespaces: [devai]`, `legacyFlatPath: true`, and
`requireServerScope: false`. Its controller consumes one YAML body capped at 5
MiB, validates a whole-body digest and minimum resource count, applies a
snapshot, waits for Backend and HTTPRoute acceptance, and optionally prunes.
It does not page, isolate prune authority by tenant, or wait for
AgentgatewayPolicy acceptance.

The design target is 100 active routes at 12 months and 500 at 36 months. Each
route renders exactly three resources (Backend, HTTPRoute, authorization
Policy) or four when a credential Policy is required: 300–400 resources at 12
months and 1,500–2,000 at 36 months. The hard contract ceiling is 1,000 routes,
4,000 resources, 1,000 tenant projections, 100 routes and 100 tenants per page,
and ten pages. Five pages every 30 seconds are 0.17 Registry requests/second at
the target; ten pages are 0.33 requests/second at the hard ceiling. Reads
outnumber writes by at least 20:1 and desired-state writes remain below one per
second.

Control-plane availability is 99.9% monthly. An eligible newly onboarded
tenant must reach the `active` phase from ADR-0020 within p99 120 seconds.
Existing accepted routes retain last-known-good state with data-plane RTO 0
during Registry, identity, controller, or Kubernetes API outage. Committed
eligibility and snapshot state have RPO 0. An explicit tenant deactivation must
install deny state within p99 60 seconds and complete safe pruning within ten
minutes.

Assets worth protecting are tenant route isolation, Registry publication and
activation authority, identity-provider roles, upstream credential references,
last-known-good routes, and audit history. Threat actors include an
unauthenticated caller, an authenticated publisher from another tenant, a
compromised tenant, controller, Registry or dependency, and an insider. Trust
is crossed at onboarding state ingestion, identity-role projection, Registry
artifact and activation reads, export authorization, cursor consumption,
rendered-resource validation, and Kubernetes apply/prune. Every crossing binds
tenant, environment, generation, and digests and fails closed.

## Decision

### Registry owns one authoritative eligibility join

The reconciler no longer sends namespace allowlists. It authenticates with one
deployment identity bound server-side to exactly one target environment. The
Registry derives the environment from that identity; a query parameter, route
manifest, or publisher cannot select another environment.

For each logical MCP server, Registry selects at most one exact immutable
version and evaluates these authoritative facts in order:

1. tenant onboarding projection is `ready` and fresh;
2. exact activation phase and both digests satisfy ADR-0020 `active`;
3. authoring lifecycle is `active`;
4. visibility is `internal` or `public`, never `private`;
5. environment-scoped Gateway policy is enabled;
6. server approval is `approved`;
7. artifact target environment equals the reconciler environment;
8. the exact collision-safe per-server identity role exists and its evidence is
   fresh;
9. new admission fits tenant and global quotas.

The onboarding service remains authoritative for tenant existence, membership,
suspension, and deactivation. The identity provider remains authoritative for
roles. Registry stores versioned, auditable projections with source generation
and freshness; a missing, stale, regressing, or ambiguous projection is not
eligible. Publishers may request Gateway policy but cannot assert onboarding,
approval, environment binding, activation, or role readiness.

The closed reason vocabulary is `eligible`, `tenant_not_ready`,
`activation_not_ready`, `lifecycle_ineligible`, `visibility_ineligible`,
`gateway_disabled`, `approval_required`, `wrong_environment`,
`scope_not_ready`, `tenant_quota_exceeded`, and `global_quota_exceeded`.
Reasons are safe codes, not upstream messages or payloads.

### Admission quotas never evict existing eligible routes

Defaults are 50 active routes per tenant and 500 globally. The hard ceiling is
1,000 globally. Lowering a limit retains all existing routes that still pass
the non-quota checks; it rejects only new admissions. New candidates are
ordered by canonical `publishedAt`, then exact ref. Tenant quota is evaluated
before global quota. There is no priority preemption or automatic deletion.
Operators raise a reviewed quota or explicitly retire a route.

### Route identity is exact and collision resistant

Registry and every consumer implement the checked-in reference algorithm; no
consumer accepts publisher-provided Kubernetes names, path segments, or scope
keys. Tenant IDs are canonical DNS labels. Server namespaces are dot-separated
DNS labels and server leaves begin and end with an alphanumeric character, so
path-like identities such as `../orders` and `io.example/..` are rejected
before hashing.

For a value, `digest(domain, value)` is lowercase hex SHA-256 over UTF-8
`domain + NUL + value`. A slug lowercases the value, replaces each run outside
`[a-z0-9]` with one hyphen, trims hyphens, and uses `mcp` if empty. A DNS
identity is the first 46 slug characters, trimmed, plus `-` and the first 16
hex digest characters. The full route identity digest uses domain
`gateway-route-v1` and value `tenantId + NUL + serverName`. Separate path
segments use domains `gateway-tenant-v1` and `gateway-server-v1`.

This yields:

- Kubernetes name: DNS identity of `mcp-<tenant>-<server>` using the full route
  identity digest;
- route path: `/mcp/<tenant DNS identity>/<server DNS identity>`;
- scope: `mcp:<tenant DNS identity>:<server DNS identity>`;
- annotation: the full `sha256:<64 hex>` identity digest.

The full identity digest, resource name, path, and scope must all be unique in
one snapshot. A cryptographic suffix collision or different record using any
same derived value invalidates the entire export. Exact vectors are in the
checked-in example and tests.

Existing human-readable tenant paths remain temporary aliases only for routes
already present at migration start and only where the old identity is
unambiguous. New tenants receive only canonical hashed paths. Registry
discovery returns the canonical path. Legacy flat `/mcp/<server>` paths are
disabled for new snapshots and removed after a dated client migration.

### Desired resources are digest bound

Every eligible route record contains the exact Registry digest, delivery
artifact digest, activation generation, full identity digest, and a
`renderedDigest` over its three or four desired Kubernetes resources. The
renderer removes status and server-managed metadata, orders resources by
`apiVersion`, `kind`, `namespace`, and `name`, canonicalizes their JSON, and
hashes the resulting byte sequence. `resourceCount` is three or four. The
snapshot also carries the sum, capped at 4,000.

The controller validates the record identity, exact number of resources,
ownership labels, tenant and generation annotations, target namespace,
allowed GVKs, and rendered digest before apply. A valid identity record with
different Backend, route, policy, credential reference, target namespace, or
parent Gateway is rejected.

### Pages are unusable until one complete snapshot exists

The v1 export returns at most 100 routes and 100 tenant projections per page,
using the same zero-based slice for both collections. A page contains snapshot
digest, environment, generation, observed timestamp, total route/resource/
tenant counts, page index and size, current cursor, next cursor, completion
flag, and bounded request ID.

The first cursor is null. Every subsequent cursor must equal the previous
`nextCursor`; cursors are unique, opaque, expire within five minutes, and are
bound by authenticated identity, environment, snapshot digest, and offset.
Registry either serves every page from the same bounded snapshot or recomputes
the complete ordered set and returns `snapshot_changed` when its digest differs.
It never silently advances a cursor onto new state.

The consumer requires contiguous indices, exact expected page count, identical
metadata, exact slice lengths, canonical ordering, final `complete=true`, final
`nextCursor=null`, unique identities, tenant counts, and recomputed digest.
Stopped pagination, 50-row store truncation, retry against a new generation,
cursor loop, duplicate item, changed count, or digest disagreement discards all
pages. No resource is applied, activated, or pruned from a page or partial
collection.

The assembled `v1alpha1` document is closed and requires `complete=true`. Its
snapshot digest is SHA-256 over canonical ASCII JSON containing schema version,
environment, generation, completeness, route/resource/tenant counts, ordered
route records, and ordered tenant projections. Observation and top-level
request IDs do not alter desired state. Per-tenant request IDs remain bound to
their eligibility generation.

### Tenant projections authorize pruning explicitly

Every previously managed tenant must have an explicit projection. It binds
tenant state, monotonic generation, desired route count, completeness, request
ID, and `pruneAuthorized`. Missing tenant projection, missing page, pending
onboarding, stale generation, or invalid digest never authorizes deletion.

For a ready tenant, a complete generation can remove a retired server only
after all retained/new Backend, authorization Policy, probe route, and public
route resources are accepted. Suspension and deactivation first install or
confirm deny state. Registry emits `pruneAuthorized=false` for the first
complete changed generation; after a fresh identity check and one full poll it
advances audited prune authority. The controller then deletes only resources
with its managed-by label, exact tenant identity digest, environment, and an
older or equal tenant generation. It never performs a global absence-based
prune.

Apply and prune are idempotent. A crash before apply leaves last-known-good. A
crash after apply but before acceptance leaves staged resources; replay is
safe. A crash after acceptance but before prune replays the same explicit
tenant prune. There is no cross-system transaction and no attempt at rollback;
the state machine only advances using immutable desired identities.

### Status, audit, and observability

Registry exposes identity-scoped per-tenant reconcile status: source
generations and freshness, desired/admitted/rejected counts, safe reason codes,
snapshot and rendered digests, last attempt/success, applied/accepted/pruned
counts, drift, and request IDs. Another tenant receives non-disclosing
not-found behavior. Activation, suspension, deactivation, quota change, route
admission, and prune authority are append-only audited events with actor,
tenant, environment, generation, decision, and before/after identifiers—never
tokens or artifact/tool payloads.

Metrics remain aggregate or use a bounded environment/stage label set. Tenant,
server, ref, subject, request ID, digest, route, and scope are not metric labels.
Metrics cover export/page duration, page restarts, snapshot size/count,
eligibility reasons, quota rejections, identity collisions, role freshness,
apply/accept/prune duration and errors, per-stage lag, and last-known-good age.
Alerts use SLO burn, stuck generation, repeated snapshot change, stale role
projection, identity collision, or actionable prune failure. Logs use safe
identifiers and request IDs without credentials or documents.

### Failure behavior

- Registry or identity projection unavailable: no new snapshot; retain
  last-known-good and retry with bounded jitter.
- Page request times out: discard collected pages; retry from the first cursor.
- State changes between pages: Registry returns `snapshot_changed`; discard and
  restart, never combine.
- Duplicate delivery: digest and generation make evaluation, apply, status
  report, and prune idempotent.
- Role provisioning lags: `scope_not_ready`; no route or public policy is
  created.
- Tenant exceeds quota: existing eligible routes remain; deterministic new
  candidates are rejected and visible in status.
- Two tenants publish the same short server name: independently derived tenant
  segments, scopes, full identity digests, and resources remain distinct.
- Lossy-name or digest collision: complete snapshot invalid; alert and make no
  mutations.
- Controller or Kubernetes API fails after apply: staged resources remain;
  last-known-good public route does not move; replay exact snapshot.
- Explicit deactivation: deny first, then prune only with fresh explicit tenant
  authority; missing tenant data never means delete.
- Registry compromise: blast radius is bounded by the deployment identity's
  environment, closed GVK/namespace allowlist, page/resource ceilings,
  rendered digest validation, per-tenant labels, and policy acceptance.

## Compatibility, rollout, and rollback

The runtime contract is additive and pre-release. Core server installs and
process lifecycle are unchanged. The current v0 export and static chart remain
available only during migration.

Rollout order is:

1. add Registry onboarding/role projections, policy and quota state, v1
   eligibility status, route vectors, and paginated export behind a feature
   gate;
2. add complete-page assembly, rendered-resource validation, per-tenant status,
   and tenant-scoped prune to the controller while it remains shadow;
3. run old and new exports against the current allowlisted tenant, require
   equal exact intended backends/policies and explain every deliberate path or
   name change;
4. provision and verify per-server roles, set scope policy required, disable
   legacy flat paths for new routes, and migrate discovery/client endpoints;
5. scale and failure-test 500 routes/2,000 resources and the 1,000-route hard
   ceiling;
6. promote one controller through GitOps and suspend the legacy CronJob so
   exactly one writer remains;
7. remove `sourceNamespaces` and the v0/static fallback after the dated
   rollback window.

Rollback is one reviewed Git revert to shadow/disabled v1 reconciliation and
the prior immutable controller/image/chart version. The last accepted snapshot
and routes remain; rollback never interprets an empty v1 export as deletion.
During the compatibility window the old allowlist export can be re-enabled
without changing tenant data. Destructive legacy-path removal occurs only
after migration evidence and has its own approval. No live cloud or Kubernetes
mutation is part of this repository change.

At the 36-month target, five small control-plane reads per 30 seconds and at
most 2,000 desired resources fit the existing two-controller deployment, but
the owning issues must measure CPU, memory, API-server apply duration, and body
size before changing the current 64 MiB request/128 MiB limit. A hard 10-page,
1,000-route, 4,000-resource ceiling bounds memory and API pressure. No new
datastore or event bus is justified; existing Postgres state and polling are
enough. Event-driven reconciliation remains deferred to issue #34.

## Alternatives considered

- Keep a Git namespace allowlist: rejected because onboarding remains manual
  and omission silently blocks tenants.
- Export every readable/public Registry server: rejected because visibility is
  not approval, environment, activation, role readiness, or quota authority.
- Let publishers set `gatewayEnabled` and names directly: rejected because it
  crosses tenant, identity, and Kubernetes trust boundaries.
- Keep lossy names and reject only observed collisions: rejected because route
  identity changes with catalog contents and truncation remains ambiguous.
- Apply each page as it arrives: rejected because timeout or generation change
  becomes broad accidental prune or mixed desired state.
- Treat missing tenant as deactivated: rejected because dependency outage
  becomes destructive.
- Add an event bus now: rejected at fewer than one desired-state write/second;
  bounded cursor polling is simpler and measurable.

## Verification and external ownership

This repository verifies deterministic same-name/collision cases,
default-deny eligibility, quota retention and ordering, exact artifact and
rendered digests, canonical snapshot hashing, explicit tenant completeness,
schema/example agreement, successful multi-page assembly, and rejection of
stopped, mixed-generation, cursor-broken, duplicate, tampered, and missing-
tenant snapshots.

Producer and GitOps delivery is tracked by
[`agentic-registry#106`](https://github.com/tesserix/agentic-registry/issues/106),
[`agentic-registry#107`](https://github.com/tesserix/agentic-registry/issues/107),
and
[`tesserix-k8s#755`](https://github.com/tesserix/tesserix-k8s/issues/755),
also linked from
[the tenant reconciliation guide](../tenant-gateway-reconciliation.md). Until
those land, `sourceNamespaces`, legacy aliases, and current scope defaults
remain unchanged; this runtime package does not mutate Registry, identity,
Gateway, Kubernetes, or cloud state.
