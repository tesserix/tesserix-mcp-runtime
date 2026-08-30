# Tenant Gateway reconciliation

This repository provides the reusable, read-only contract for removing static
tenant allowlists from MCP Gateway reconciliation. It does not discover
tenants, provision identity roles, export Registry state, render Kubernetes
resources, or apply/prune a live Gateway. Those mutations remain with the
Agentic Registry, identity control plane, route-sync controller, and GitOps
repositories.

The current deployed chart still has `sourceNamespaces: [devai]`, legacy flat
paths enabled, and per-server scope enforcement disabled. The current Registry
v0 export also stops at its first store page. Do not infer that publishing a
server makes a newly onboarded tenant routable yet.

## Authoritative eligibility

Registry—not the publisher or controller—must join these facts for one exact
version and target environment:

| Fact | Authoritative owner | Eligible value |
| --- | --- | --- |
| Tenant onboarding | Identity/onboarding control plane projection | `ready` and fresh |
| Activation | ADR-0020 Registry activation status | exact generation/digests are `active` |
| Lifecycle | Immutable Registry artifact | `active` |
| Visibility | Registry authorization metadata | `internal` or `public`; never `private` |
| Gateway policy | Environment-scoped Registry policy | enabled |
| Approval | Registry control-plane decision | `approved` |
| Environment | Reconciler identity plus artifact policy | exact match |
| Per-server role | Identity-provider readiness projection | present and fresh |
| Admission | Registry quota state | existing route or available tenant/global slot |

Any missing, stale, mixed, unapproved, disabled, private, wrong-environment, or
scope-not-ready fact rejects the candidate. Publishers cannot supply trusted
onboarding, role, approval, activation, or environment state in a manifest.

Defaults admit at most 50 new routes per tenant and 500 globally, with a hard
1,000-route ceiling. Lowering a quota keeps existing otherwise-eligible routes
and rejects only new candidates. New admission is deterministic by publish
timestamp and exact ref; it never evicts another route.

## Reusable Python reference

The optional manifest package contains the reference decision and naming
algorithm. Inputs must already be trusted Registry/control-plane facts:

```python
from tesserix_mcp_manifest import (
    GatewayApprovalState,
    GatewayEligibilityCandidate,
    GatewayEligibilityPolicy,
    GatewayRouteRecord,
    GatewayTenantState,
    ManifestLifecycle,
    ManifestVisibility,
    evaluate_gateway_eligibility,
)

candidate = GatewayEligibilityCandidate(
    ref="mcpservers/tenant-blue/io.example/orders@1.2.3",
    tenant_id="tenant-blue",
    server_name="io.example/orders",
    registry_digest="sha256:" + "a" * 64,
    artifact_digest="sha256:" + "b" * 64,
    activation_generation=7,
    published_at="2026-08-30T12:00:00Z",
    lifecycle=ManifestLifecycle.ACTIVE,
    visibility=ManifestVisibility.INTERNAL,
    tenant_state=GatewayTenantState.READY,
    gateway_enabled=True,
    approval_state=GatewayApprovalState.APPROVED,
    environment="production",
    activation_ready=True,
    scope_ready=True,
    currently_routed=False,
)

decision = evaluate_gateway_eligibility(
    (candidate,),
    policy=GatewayEligibilityPolicy(target_environment="production"),
)[0]
assert decision.eligible

# The owning renderer supplies a digest over its exact three or four resources.
record = GatewayRouteRecord.from_decision(
    decision,
    rendered_digest="sha256:" + "c" * 64,
    resource_count=3,
)
print(record.resource_name, record.route_path, record.scope)
```

Names, paths, and scopes include collision-resistant hashes of the exact
tenant/server identity. Distinct tenants with the same server name and names
that collapse under legacy DNS sanitization remain distinct. Every snapshot
also carries the full identity digest; any duplicate derived name, path, scope,
ref, or digest rejects the whole snapshot. Tenant IDs and reverse-domain server
names must be canonical; traversal-shaped names are rejected before identity
derivation.

`GatewayRouteRecord` contains only identities and digests. It never includes
backend URLs, Kubernetes YAML, tool schemas, credentials, claims, token
contents, MCP inputs/results, or upstream error messages.

## Complete paginated snapshots

The wire schema is
[`gateway-reconciliation-v1alpha1.schema.json`](../contracts/gateway-reconciliation-v1alpha1.schema.json).
Its `#/$defs/page` definition describes one page, with a checked-in
[`page example`](../contracts/gateway-reconciliation-page-v1alpha1.example.json).
The final assembled contract has a checked-in
[`snapshot example`](../contracts/gateway-reconciliation-v1alpha1.example.json).

Consumers validate each external page and assemble all pages before use:

```python
from tesserix_mcp_manifest import (
    GatewayReconciliationContractError,
    GatewayReconciliationPage,
    assemble_gateway_reconciliation_pages,
)

try:
    pages = tuple(
        GatewayReconciliationPage.from_document(document) for document in registry_page_documents
    )
    snapshot = assemble_gateway_reconciliation_pages(pages)
except GatewayReconciliationContractError:
    # Keep last-known-good. Never apply or prune a partial/mixed export.
    raise
```

A valid chain has at most ten pages and exactly the expected number from the
declared counts/page size. It begins at page zero with a null cursor; every next
cursor matches; all pages share environment, generation, timestamp, request
ID, counts and digest; slices have exact lengths; routes and tenants use
canonical order; the final page alone is complete and has no next cursor. The
assembler revalidates tenant route counts, exact identities, rendered resource
counts, and the canonical whole-snapshot digest.

Timeout, stopped pagination, cursor loop, changed generation, repeated page,
changed count, missing tenant, duplicate route, unsafe derived identity,
invalid resource digest, or any malformed external value raises one fixed
payload-free contract error. No collected page is usable by itself.

## Apply, activation, and pruning rules

For every eligible record the owning implementation must:

1. fetch or render the exact Registry-digest-bound server;
2. produce exactly one Backend, HTTPRoute, and per-server authorization Policy,
   plus an optional credential Policy;
3. validate the closed GVK/namespace/ownership allowlist and the record's
   rendered digest/resource count;
4. apply staged resources idempotently and wait for Backend, policy, parent,
   `Accepted`, and `ResolvedRefs` evidence;
5. run ADR-0020's authenticated MCP protocol probe before public activation;
6. report safe per-tenant and activation status with generation/digests;
7. prune only with an explicit complete tenant projection and fresh
   `pruneAuthorized=true` generation.

Missing tenant state never means deletion. Pending onboarding cannot authorize
pruning. Suspension/deactivation installs deny state first. Registry advances
prune authority only after a fresh identity check and a complete subsequent
poll. The controller deletes only its own resources for that exact tenant,
environment, identity, and non-newer generation. Existing last-known-good
routes remain on Registry, identity, page, controller, or Kubernetes API
failure.

## Scale and operating limits

- 12-month target: 100 routes, 300–400 resources, one page.
- 36-month target: 500 routes, 1,500–2,000 resources, five pages.
- Hard bound: 1,000 routes, 4,000 resources, 1,000 tenants, ten pages.
- Poll interval: 30 seconds, or 0.17 Registry RPS at target and 0.33 RPS at the
  hard bound.
- New-tenant eligible publish to active: p99 at most 120 seconds.
- Existing data-plane RTO during control-plane outage: zero.
- Explicit deactivation deny: p99 at most 60 seconds; safe prune: ten minutes.

Owning implementations must measure the 500-route and hard-ceiling body size,
memory, CPU, API-server apply/acceptance duration, and failure recovery before
raising current controller resources. Tenant/server identifiers must not be
Prometheus labels. Per-tenant status is an authenticated bounded API; aggregate
metrics and safe audit events carry decision codes and request IDs.

## Rollout and rollback

Rollout starts with Registry and controller feature gates, then shadow
comparison against the existing allowlisted `devai` export. Every intended
backend and policy must match or have a reviewed path/name migration. Provision
per-server roles and prove negative cross-tenant access before requiring scope
policy. Promote exactly one writer through GitOps, suspend the legacy CronJob,
then remove `sourceNamespaces` and v0 only after a dated rollback window.

Existing unambiguous tenant paths may remain temporary aliases. New tenants use
only the canonical collision-safe path. Legacy flat paths are never created for
new tenants.

Rollback is a Git revert to shadow/disabled v1 reconciliation and the prior
immutable image/chart. The controller retains the last accepted snapshot and
does not treat an empty or failed v1 read as deletion. During the migration
window, the prior allowlisted export can be restored without changing tenant or
artifact data.

The normative ownership, failure analysis, security model, hash algorithm,
pagination rules, SLOs, costs, migration, and rollback are in
[ADR-0021](adr/0021-identity-scoped-tenant-gateway-reconciliation.md).

## External delivery

Concrete ownership is split into:

- [`tesserix/agentic-registry#106`](https://github.com/tesserix/agentic-registry/issues/106):
  authoritative identity-scoped eligibility, quotas, tenant projections, and
  snapshot-bound pagination;
- [`tesserix/agentic-registry#107`](https://github.com/tesserix/agentic-registry/issues/107):
  cross-language route identity, rendered-resource binding, complete page
  assembly, tenant-scoped reconcile/status/prune;
- [`tesserix/tesserix-k8s#755`](https://github.com/tesserix/tesserix-k8s/issues/755):
  immutable image/chart, environment-bound identity, shadow comparison, scale
  and failure proof, one-writer promotion, and removal of `sourceNamespaces`.

They depend on activation status, authenticated probing, per-server
authorization-policy acceptance, staged reconciliation, and last-known-good
proof already tracked from ADR-0020.
