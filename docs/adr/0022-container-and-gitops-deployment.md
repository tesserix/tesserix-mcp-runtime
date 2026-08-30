# ADR-0022: Digest-pinned containers and GitOps deployment

## Status

Accepted. The core and ADK reference images, container verifier, Kubernetes
contract, and read-only CI evidence lane are implemented in this repository.
Product adoption and image publication remain owned by `tesserix-k8s` and its
release pipeline; the checked-in reference manifests intentionally cannot be
deployed without that adoption work.

## Context and quantitative envelope

The runtime must give every MCP server the same reproducible process boundary
without making the larger Google ADK dependency closure the default. Production
images target Python 3.14. The repository envelope requires at least
50 calls/second sustained and 200 calls/second burst, no more than 15 ms runtime
added p99 latency, startup within two seconds, idle RSS at or below 128 MiB,
and 99.9% monthly invocation availability. These remain GA targets rather than
claims about an unmeasured product handler.

The reference Deployment starts with two replicas. Runtime safety admits at
most 64 process calls per pod. For an illustrative 250 ms p99 product call, a
200 calls/second burst creates `200 * 0.250 = 50` concurrent calls. Keeping
normal occupancy at or below 50% of the 64-call ceiling gives 32 calls per pod,
so `ceil(50 / 32) = 2` replicas meets that example and the multi-zone
availability floor. A one-second p99 handler would instead require
`ceil(200 * 1 / 32) = 7` replicas. Every adopter must repeat this arithmetic
with measured peak rate and handler latency; two replicas are not a universal
capacity claim.

Each pod requests 128 MiB and is limited to 256 MiB, giving a two-replica
scheduled floor of 256 MiB and a 512 MiB failure ceiling. No CPU request or
limit is encoded because the authoritative Tesserix workload policy currently
requires memory-only resources. Product adoption must follow that policy and
must not silently add a throttling CPU limit.

## Threat model and trust boundaries

Assets worth protecting are the base-image and application provenance, runtime
and tenant isolation, workload identity, backing credentials, MCP payloads,
the last-known-good image, and the previous Registry route. Threat actors
include an unauthenticated Gateway caller, an authenticated tenant attempting
cross-tenant access, a compromised build dependency or base-image publisher, a
malicious contributor, and an operator applying incomplete placeholders.

Trust is crossed from source to CI, CI to a container registry, registry digest
to `tesserix-k8s`, Git desired state to the cluster, AgentGateway to the pod,
and the pod to identity, telemetry, and backing APIs. CI consumes immutable
digests with least-privilege read permission and no publishing credential.
Kubernetes admits only the intended Gateway peer and declared egress. The
runtime validates exact Host and Origin allowlists and verified identity again;
network reachability alone never authorizes a tool call. No secret, service
account key, kubeconfig, tenant payload, or production data belongs in an
image, manifest, SBOM, scan report, or CI log.

## Decision

### Core is the default immutable image

The core Dockerfile uses the dated Tesserix Python 3.14 runtime base by digest.
The ADK Dockerfile uses the dated Python 3.14 ADK base by digest only for a
server that actually selects the ADK bridge. Both use a digest-pinned `uv`
builder, build the repository wheel in an isolated stage, and copy only the
wheel and its resolved runtime environment into the final base. A missing or
republished base digest makes the build fail; there is no tag-only or floating
fallback.

The final process runs as `10001:10001`, enters through `tini`, writes only to a
bounded `/tmp`, and contains no runtime shell. Kubernetes additionally applies
a read-only root filesystem, `RuntimeDefault` seccomp, dropped capabilities,
and `allowPrivilegeEscalation: false`. The image listens on a non-loopback
address only because its command supplies explicit Host and Origin allowlists;
the library default remains loopback-only.

Google ADK 2.8.0 constrains the OpenTelemetry API and SDK to 1.42.1. The
runtime therefore supports `>=1.42.1,<2`: the immutable ADK base retains 1.42.1
while the current core lock resolves 1.44.0. Increasing the shared minimum to
1.44 would make the supported ADK image unsatisfiable and is not evidence of a
newer or safer runtime.

### CI produces evidence but does not publish

The container workflow builds both variants with a synthetic package version,
runs the same verifier used locally, records image configuration and compressed
archive size, creates SPDX and CycloneDX SBOMs, scans OS packages and a freshly
generated language SBOM separately, validates Kubernetes 1.31 schemas, and
uploads seven-day evidence artifacts. Actions and tool images are immutable.
Workflow permissions are `contents: read`; it has neither package-write nor
OIDC permission and cannot publish an image or mutate a cluster.

Some base layers carry an inherited layer SBOM that mentions packages no
longer present in the merged filesystem. Direct Trivy library discovery can
therefore report `msgpack 1.1.2` and `setuptools 70.3.0` even though neither is
installed in either final image. CI does not suppress those names or CVEs. It
scans actual image OS packages and runs the language gate against a fresh Syft
SPDX inventory of the merged image, which is the installed application
closure. Both gates must pass.

### Product desired state stays in the owning GitOps repository

This repository publishes a reusable Kubernetes contract containing a
Deployment, ClusterIP Service, ServiceAccount, PodDisruptionBudget, and
NetworkPolicy. It specifies two replicas, memory resources, all three probes,
45-second termination grace, a five-second pre-stop propagation window,
zero-unavailable rolling update, topology spread, bounded temporary storage,
workload identity, AgentGateway-only ingress, and bounded DNS, telemetry,
identity, backing-API, and metadata egress.

The reference uses `registry.invalid`, a placeholder namespace and identity,
and invalid Host and Origin values. It is not product desired state and is
deliberately unusable as checked in. Adoption copies or renders the contract
through the owning `tesserix-k8s` chart, replaces every placeholder, pins the
published application digest, and goes through that repository's review and
Argo CD reconciliation. This repository never applies production manifests.

## Dependency failure classification

Readiness is an admission decision; liveness answers only whether the process
loop can continue. An adopter records every dependency in exactly one tier:

| Dependency | Tier | Readiness behavior | Invocation behavior |
| --- | --- | --- | --- |
| Verified Gateway identity and usable JWKS within its bounded stale window | Critical | 503 when new callers cannot be authenticated | Fail closed without calling a tool |
| Policy or audit authority required by every exported tool | Critical | 503 when the server cannot safely authorize work | Return a stable safe dependency error |
| Backing API required by every useful tool | Critical | 503 after its bounded readiness check fails | Return a stable safe dependency error; never retry unsafe writes |
| Backing API used by only some tools | Degradable | Remain ready so independent tools continue | Only affected calls fail with a stable safe dependency error |
| OTLP collector | Optional | Never changes readiness or liveness | Drop bounded telemetry and count the drop |
| Registry and GitOps control plane after a route is installed | Degradable control plane | Serving pods remain ready | Last-known-good route and image continue serving |

Checks have finite timeouts and run concurrently. A backing outage never makes
liveness fail, because restarting a healthy process amplifies the dependency
incident. Readiness must not probe an optional dependency. A product that
cannot state whether its backing API is critical or degradable is not ready for
adoption.

## Canary, promotion, and rollback

An immutable candidate digest first enters non-production with zero active
Registry/AgentGateway traffic or a separate smoke-only route. Its startup,
readiness, liveness, MCP initialization, discovery, representative read, safe
error, and SIGTERM drain must pass. Promotion changes the Gateway target only
after the candidate is ready and the health policy permits cutover. The
previous Registry route and previous image digest remain valid through at least
one complete observation window; cleanup is a later change.

If the new pod never becomes ready, the zero-unavailable rollout leaves the old
ReplicaSet and previous Registry route serving. The failed candidate is not
promoted. Rollback is one Git revert in `tesserix-k8s`; Argo CD reconciles that
single prior desired-state revision. An imperative `kubectl rollout undo` is
not a rollback because Git would immediately reapply the failed state.

For a pre-cutover canary failure, data-plane RTO is zero because traffic never
moves from the previous route. After a cutover regression, the operational RTO
target is five minutes from approved revert to previous-route readiness. The
runtime is stateless, so its configuration RPO is zero: Git and immutable
digests retain the exact desired state. Product data RPO remains owned by each
backing service.

Configuration follows expand-contract. First deploy code that accepts both old
and new optional fields, flags, identity references, or allowlist entries. Then
change desired state and promote the route. Remove old configuration only in a
later release after every previous pod and rollback window has expired. A
rename, removal, and code cutover never share one revision.

## Cost and capacity

The fixed reference reserves 256 MiB across two pods and permits at most
512 MiB before OOM isolation. The measured merged image sizes are about 64 MiB
for core and 139 MiB for ADK; selecting ADK more than doubles registry storage,
node-pull bytes, cold-pull time, SBOM size, and vulnerability surface. Core is
therefore the cost default.

At 30 retained single-architecture revisions, the observed compressed archives
consume roughly 2.0 GB for core or 4.4 GB for ADK before registry
deduplication. Multi-architecture publication multiplies the application
variant cost. Cross-zone Gateway traffic, backing-API egress, and telemetry
retention are product-specific and must be estimated during adoption. The
reference has no autoscaler because an unmeasured generic scaling signal is
worse than an explicit replica decision; adopters add a bounded concurrency or
in-flight signal only after load evidence.

## Alternatives considered

- A floating weekly or `latest` base was rejected because a rebuild would no
  longer reproduce or roll back the reviewed bytes.
- Using the ADK all-extras base for every server was rejected because most
  servers do not need its dependency, size, and CVE surface.
- A shellful slim runtime was rejected because operational convenience expands
  the post-compromise toolset; ephemeral debug containers provide controlled
  diagnostics instead.
- Publishing or applying product manifests from this repository was rejected
  because it creates a second desired-state owner and bypasses Argo CD review.
- Imperative production canaries and `kubectl rollout undo` were rejected
  because the reconciler would overwrite them and the audit trail would be
  incomplete.
- Building a generic Helm chart here was deferred. The five-resource contract
  is enough for the current single owning GitOps repository and avoids a second
  templating API before another adopter exists.

## Consequences

Builds are deterministic and fail honestly when an immutable dependency
disappears. Core servers avoid ADK by default, final images have a small attack
surface, and the reference enforces safe scheduling, ingress, egress, probes,
and drain behavior. Previous traffic capacity survives a failed rollout and
rollback is an auditable desired-state revision.

Operators must publish application images elsewhere, replace every fail-closed
placeholder, classify dependencies, measure product latency, choose capacity,
and implement the adoption change in `tesserix-k8s`. Distroless operation means
debugging uses logs, metrics, traces, the verifier, or a separately authorized
ephemeral debug container rather than executing a shell in the workload. The
reference NetworkPolicy may need product-specific peers, but broad internet
egress and secret-bearing manifests remain prohibited.
