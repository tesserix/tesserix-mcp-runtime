# ADR-0025: Adversarial security verification and digest-bound evidence

- Status: Accepted
- Date: 2026-08-31
- Tracking: [tesserix-mcp-runtime#30](https://github.com/tesserix/tesserix-mcp-runtime/issues/30)
- Supersedes: none

## Context and quantitative envelope

Unit checks for JWT parsing, tenant policy, egress, and redaction do not prove
that the built package, image, Agentic Registry, AgentGateway, and runtime keep
the same authority at their real boundaries. A release could pass scanners and
still disclose a private Registry projection, accept a forged claim, connect to
metadata, or retain a secret in a newly added sink.

Security contract 1.0 therefore has 51 required cases: 9 tenancy, 9 identity,
6 authority, 8 egress, 12 redaction, 3 control-plane, and 4 CI/dependency cases.
It scans 12 named sinks: manifests, semantic annotations, schemas, errors,
results, logs, traces, metrics, audit, crash dumps, SBOMs, and release assets.
One observation and one sink are each bounded to 1 MiB; the canonical report is
also bounded to 1 MiB. The real lane retains sanitized evidence for seven days
and remains inside ADR-0023's ten-minute timeout. It is a low-volume release
gate, not a throughput or availability benchmark.

Assets worth stealing or corrupting are tenant-private metadata, verified
identity and authority, approval and idempotency decisions, backing effects,
egress destinations, package/image/manifest/SBOM identity, CI authority, and
secrets reaching observable sinks. Threat actors include an unauthenticated
caller, an authenticated caller from another tenant, a malicious publisher, a
compromised action or dependency, and an insider presenting forged review
evidence. Trust is crossed at every caller, Gateway, runtime, backing, Registry,
artifact, workflow, and evidence boundary; each crossing validates bounded
input and independently authorizes the exact tenant, subject, scope, route, and
digest.

## Decision

`tesserix-mcp-testkit` publishes the typed security contract beside its
conformance and journey contracts. Each `SecurityCase` fixes an area, severity,
expectation, blocking policy, and required evidence mode. Tenant, identity,
authority, and control-plane cases require black-box observations; egress cases
require an isolated-network harness; artifact-facing redaction cases require
artifact evidence; CI and dependency cases require static evidence. A producer
cannot relabel weaker evidence as the required mode.

The real journey runs the built runtime behind pinned AgentGateway 1.4.1 and the
pinned Agentic Registry commit from ADR-0023. Its fake identity provider issues
only named synthetic adversarial variants. During verifier dependency outage,
its JWKS and token boundaries return 503 without rotating signing keys: an
already-valid cached key follows the runtime's bounded local-verification
policy, while an unknown key fails closed. The fixture remains live only for
health and test control, so the case isolates verifier behavior from container
port changes or accidental key rotation.

The journey also exercises cross-tenant discovery, exact fetch, route access,
session reuse, tool calls, backing observations, metrics, and audit; scope and
claim disagreement; trusted-header spoofing; approval, idempotency, and confirm
replay; forged/unsigned control-plane metadata; and a route missing its required
scope. That route case consumes the Registry's `requireServerScope` export,
rejects a Backend and HTTPRoute whose expected `AgentgatewayPolicy` is absent,
and proves the scoped live route refuses a signed token missing only its
`mcp:<tenant>:<server>` claim. The isolated SSRF harness covers redirect,
encoded IP, IPv6, DNS rebinding, metadata, loopback, private ranges, and
alternate ports. The CI gate rejects mutable actions, over-broad permissions,
untrusted privileged pull requests, and release dependency-policy drift.

Every report binds the source revision and exact package, image, manifest, and
SBOM SHA-256 identities. It also binds the tested runtime, Registry, and Gateway
component revisions. A result retains only its case ID, evidence mode, request
ID where applicable, pass state, and SHA-256 evidence digest. Raw observations
are bounded, scanned for configured canaries and secret shapes, hashed, and
discarded. Named sink evidence retains only the sink, digest, and byte count.

All 51 results and all 12 sink identities must be present exactly once.
Redaction results must reuse the exact digest of their named sink. The runtime
component revision must equal the report's image digest. Unknown, missing,
duplicated, mismatched, non-finite, oversized, or secret-bearing values fail
closed before canonical JSON is emitted.

A failed case first requires a unique finding with the contract severity, a
bounded owner, remediation, and disposition. Open findings cannot carry retest
evidence. Remediated findings must carry the exact retest digest. A required
case still cannot become release evidence while its result is failed; the
successful retest changes the result to passed and binds the same digest to the
finding.

GA evidence additionally requires an approved review by someone other than the
preparer. The review time cannot predate the evidence, and its scope digest is
computed over every subject, component, result, surface, and finding while
excluding the review itself. Serialization with
`require_independent_review=True` enforces those conditions. Release-candidate
and nightly evidence may retain `review: null`; it is not GA approval.

MCP SDK 1.34 does not exist in the authoritative or checked dependency state.
The real image continues to prove Python 3.14 and MCP SDK 2.1.1, while the
separate compatibility lane exercises the supported 1.28.1 client boundary.
This contract does not manufacture another SDK version.

## Options considered

### Scanner reports only

Rejected. Static and dependency scanners cannot observe cross-tenant wire
behavior, Gateway authority, backing effects, cached verification, or every
runtime sink.

### Copy private tests into every MCP repository

Rejected. Copies drift in case identity, severity, evidence requirements, and
release policy. One versioned testkit contract makes additions and breaking
changes explicit.

### Store raw requests, tokens, and payloads as evidence

Rejected. Raw evidence expands the breach surface and conflicts with the data
it is meant to protect. Digests and bounded non-secret observations are enough
to bind a reviewed run.

### Exercise production identity, Registry, or tenants

Rejected. A release gate needs reproducible adversarial behavior without
production authority, customer data, or a production blast radius.

## Failure behavior, rollout, and rollback

Missing or failed required evidence prevents report serialization and therefore
blocks the release journey. A verifier outage admits no unknown key. A new sink
without a named redaction case makes the required surface set drift visibly and
must extend the versioned contract. A route without its exact scope never
activates. CI policy ambiguity is denial, not a warning.

Rollout is additive: publish the testkit API, enable networkless contract tests,
run the isolated CI/SSRF gates, then require the pinned real journey before
publication. Downstream projects pin a compatible testkit version and adopt new
contract majors deliberately. Rollback is one revert of the contract, fixture,
and workflow integration; no production route, credential, database, or
Registry version is mutated by this suite. Previously emitted evidence remains
bound to its original contract version and digests.

## Cost and consequences

The default suite remains offline and adds sub-second package tests plus static
security checks. The real lane adds one disposable Registry, Gateway, identity,
backing service, and two runtime containers within the existing ten-minute
budget. Evidence storage remains below 1 MiB plus already retained sanitized
journey artifacts for seven days. Image build and pull time dominate cost.

Release reviewers gain one exact, reusable security vocabulary and can prove
that a finding was retested against the same evidence scope. The contract is
deliberately strict: adding a required case or changing an existing meaning is
a reviewed contract-version decision, and every new observable sink must be
named rather than silently accepted.
