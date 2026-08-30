# ADR-0023: Release integration journey and sanitized evidence

## Status

Accepted for implementation. The hermetic contract lane and the digest-pinned
container lane described here are the release gate for the publication,
discovery, activation, invocation, and rollback lifecycle.

## Context and quantitative envelope

The separate publication, Registry discovery, Gateway activation, runtime
policy, redaction, and fault contracts do not prove that their wire formats
compose. A release needs one automated journey that carries the same immutable
identity from publication to an authorized tool result and observes recovery
without production credentials or a production cluster.

The disposable catalog contains fewer than 100 artifacts. One MCP declaration
is bounded to 1 MiB by publication and its exact Registry document is expected
to remain below 256 KiB. The integration runner uses one caller at a time and
at most two concurrent calls for the drain assertion. The happy path must
finish within 120 seconds, broken down as 30 seconds for Registry readiness and
publication, 10 seconds for semantic search and exact fetch, 60 seconds for
route acceptance and the authenticated probe, and 20 seconds for invocation.
The complete outage and rollback matrix must finish within 10 minutes.

The existing production envelope remains 50 calls/second sustained, 200
calls/second burst, no more than 15 ms runtime-added p99 latency, and 99.9%
monthly invocation availability. This low-volume journey proves contract
compatibility and bounded recovery; it is not a load or availability claim.
Evidence is a canonical JSON document below 1 MiB, retained for seven days.

## Threat model and trust boundaries

Assets worth protecting are private semantic metadata, tenant and subject
identity, Registry signing results, Gateway route authority, backing write
effects, idempotency results, audit and trace correlation, and secret canaries.
Threat actors include an unauthenticated caller, an authenticated caller from
another tenant, a malicious artifact publisher, a compromised dependency, and
a failed or stale deployment.

Trust is crossed from publisher to Registry, Registry search stub to exact
fetch, Registry export to Gateway desired state, Gateway to runtime, runtime to
identity and backing APIs, and every component to the evidence sink. Each
crossing validates a bounded typed document and independently authorizes the
verified subject and tenant. Identity is derived only from a signed disposable
JWT. A caller from another tenant receives the same non-disclosing absence or
authentication failure whether the artifact or route exists. Raw tokens,
authorization headers, request bodies, secret-shaped fields, and tool payloads
never enter evidence.

## Decision

### Two lanes share one evidence contract

Every relevant pull request runs a networkless hermetic lane. It exercises the
public lifecycle state machine with deterministic boundary implementations and
proves canonical-reference continuity, tenant isolation, idempotent replay,
timeout projections, fail-closed activation, rollback selection, and evidence
redaction. This lane is fast enough to remain a normal package test and cannot
use Docker or the internet.

Nightly, release-candidate, and manually dispatched CI runs the real container
lane. It uses:

- Agentic Registry source commit
  `6921474591b6c59e89025370c310c7f85859246f` with its in-memory store;
- AgentGateway 1.4.1 image
  `sha256:efd79355b89094a8225a9db465d9a01dc656b377f0bab458761b935a13231d29`;
- the repository's Python 3.14 core image and a deterministic reference MCP
  server;
- separate disposable identity/JWKS and backing-API processes; and
- a dedicated Docker bridge with no production credential or kubeconfig.

All source commits, images, actions, and tool versions are immutable. The lane
records their digests and local image IDs. It publishes nothing and receives
only `contents: read` permission.

### Verified runtime compatibility

The pinned core image currently proves Python 3.14.7 with MCP SDK 2.1.1. The
frozen root dependency and the container verifier both require 2.1.1; the
separate compatibility lane continues to exercise an MCP SDK 1.28.1 client at
the protocol boundary. Those are different claims: 1.28.1 is a legacy client
compatibility case, not the runtime dependency. MCP SDK 1.34 is not a version
present in the checked lock, supported matrix, built image, or authoritative
package evidence, so the journey must never synthesize that version. Where a
request says “1.34”, this repository treats it as Python 3.14 only when the
runtime and image checks independently prove that interpretation.

### The journey is progressive and digest-bound

The runner performs these phases in order:

1. validate and publish one immutable private MCP version with one stable
   idempotency key;
2. repeat the publication and require the original result without a second
   Registry revision;
3. search by intent as the owner, inspect a bounded safe stub, follow its exact
   fetch path, and recompute the canonical Registry digest;
4. search and fetch as another tenant and require non-disclosure;
5. fetch the Registry AgentGateway export, verify its digest and allowlisted
   resource kinds, and translate its selected remote endpoint to the isolated
   Docker service address;
6. start the digest-pinned Gateway with an equivalent standalone route, wait
   for an authenticated MCP initialize/list probe, and only then mark the
   exact Registry digest active;
7. invoke read, write, approval-required, deterministic failure, slow, and
   secret-canary tools through Gateway while asserting tenant, subject, scopes,
   request/trace correlation, deadlines, telemetry, audit, redaction, and
   backing effects;
8. publish a bad version, record the failed probe, keep the last-known-good
   route active, and select that exact version for rollback; and
9. inject Registry, Gateway, and backing-API outages and record their bounded
   visible states before restoring the disposable stack.

AgentGateway 1.4.1 standalone mode cannot import Registry-exported Kubernetes
resources. The journey therefore validates the exported
`AgentgatewayBackend`, `HTTPRoute`, and optional `AgentgatewayPolicy` documents
as the control-plane contract, then exercises an equivalent standalone MCP
target as the data path. Equivalence requires the same tenant, sanitized server
identity, MCP target path, and upstream path. Only the environment-specific
DNS name and local HTTP scheme may differ, and that translation is recorded as
a non-secret assertion. Actual Kubernetes controller reconciliation remains a
separate GitOps adoption test; this journey does not invent Kubernetes
conditions it did not observe.
Standalone mode does not prove Kubernetes controller adoption. That final gap
is owned by `tesserix/tesserix-k8s#758`, which depends on the staged reconcile
work in `tesserix/tesserix-k8s#754` and must observe real CRD conditions in a
disposable cluster.

### Disposable network shape

The Compose bridge deliberately uses `internal: false`. With the pinned Compose
5.5.0 implementation used by this lane, an internal bridge suppresses the
published host-port path that the black-box runner must use. Every published
port is nevertheless loopback-only and dynamically allocated; no service binds
to a non-loopback host address. Services use fixed bridge addresses solely for
the runtime gateway-CIDR allowlist, carry no production credentials, mount no
kubeconfig, and cannot address a production endpoint through configuration.
This is process and authority isolation, not a claim that Docker supplies an
egress firewall.

Compose may assign a different ephemeral host port after `stop` then `start`.
The lifecycle controller therefore starts the service and re-resolves the
published port before every restoration probe. Holding the original origin is
an invalid assumption and is covered by a networkless regression test.

### Writes and rollback are replay-safe

The reference write tool requires a caller-provided idempotency key. The
backing API stores the key and original result atomically with the effect. A
duplicate request returns that result and does not increment the effect count.
There is no distributed transaction across Registry, Gateway, runtime, and the
backing API: immutable publication is the pivot, route activation is a
separate observed decision, and the previous active digest remains the
compensation target.

Candidate publication never changes the active route. A failed probe leaves
the previous digest serving, so its data-plane rollback RTO is zero. A failure
after route replacement is repaired by one restart with the previous checked
configuration; the integration RTO budget is 60 seconds. The runtime is
stateless and Registry versions are immutable, so configuration RPO is zero.
In-flight work uses the old process until its bounded drain completes; new
sessions select exactly one healthy configured target.

### Evidence fails closed

Every phase appends a typed assertion containing only a stable code, boolean
outcome, elapsed milliseconds, request/trace identifiers, immutable digests,
and bounded condition projections. The serializer rejects unknown fields,
non-finite numbers, oversized values, secret-shaped keys, bearer-token forms,
and any configured canary. Before upload, the runner scans its JSON, component
logs, Registry stubs, fetched manifests, Gateway export, traces, metrics, and
audit projections. A match fails CI and prevents evidence publication.

The final evidence explicitly distinguishes `healthy`, `control_plane_degraded`,
`activation_timed_out`, `probe_failed`, `gateway_unavailable`,
`backing_unavailable`, and `rolled_back`. Registry failure after activation is
degradable: last-known-good invocation continues. Gateway failure is critical
to invocation. A backing outage affects only dependent tools and never causes
a duplicate write. Optional telemetry failure drops bounded observations and
does not change authorization or invocation.

The real lane verifies those classifications directly. During Registry outage
the already configured Gateway continues to serve the known-good digest;
Registry restoration is probed at its newly resolved origin. Gateway outage is
visible to the caller and restoration requires a fresh authenticated MCP probe.
Backing outage returns the stable unavailable failure, restoration succeeds,
and the recorded write effect count remains unchanged.

## CI, rollout, and rollback

The hermetic lane enters the ordinary quality workflow for changes to journey
contracts or integration code. The real lane runs nightly, on a release
candidate dispatch, and when manually requested. Pull requests never receive a
secret and do not run untrusted code with elevated Docker credentials. Both
lanes upload evidence with `if: always()` so a failed phase remains diagnosable,
but the sanitizer must succeed before the artifact is eligible for upload.

Rollout is additive: land the hermetic contract, then enable the real scheduled
lane, then make its green result a release-candidate requirement. Rollback is
one revert of the workflow and journey files. No production route, Registry,
or cluster state changes as part of either rollout or rollback.

## Cost

The hermetic lane adds seconds to affected quality jobs. The real lane has a
10-minute hard timeout and runs once nightly, for an upper bound near 300
Linux-runner minutes per 30-day month plus release-candidate runs. Images are
local to the ephemeral runner and are not published. Seven-day JSON evidence
below 1 MiB makes artifact storage negligible. Registry and Gateway build/pull
network bytes dominate cost; the core image is reused instead of the ADK image
because the journey does not need ADK.

## Alternatives considered

- One mocked end-to-end unit test was rejected because it cannot detect wire,
  image, routing, or protocol drift.
- Running only the container journey on every pull request was rejected because
  it is slow, network-dependent, and unsafe for untrusted fork code.
- A second vector database or runtime reranker was rejected because Agentic
  Registry already owns authorized semantic ranking.
- A production-cluster smoke test was rejected because it requires production
  authority and makes failures non-hermetic.
- A disposable Kubernetes controller test is deferred until the owning GitOps
  repository provides a pinned, reusable AgentGateway adoption fixture. The
  Registry export remains validated here rather than being represented as
  reconciled status.
- Temporal was rejected for this bounded CI journey. It has no durable
  production work or wall-clock wait; an explicit finite runner and immutable
  evidence are smaller and sufficient.

## Consequences

Release candidates gain reproducible proof that the supported components
compose, tenant boundaries stay closed, write replays have one effect, outage
states are explicit, and a bad candidate cannot displace the last known good.
The evidence artifact is useful without containing tenant payloads or secrets.

The real lane costs more than unit tests and depends on the pinned Registry
commit and Gateway image remaining fetchable. Standalone routing does not prove
Kubernetes controller acceptance; that limitation remains explicit until the
owning GitOps fixture exists and is tested rather than inferred.
