# ADR-0026: Digest-bound evaluation bundles and promotion gates

- Status: Accepted
- Date: 2026-08-31
- Tracking: [tesserix-mcp-runtime#28](https://github.com/tesserix/tesserix-mcp-runtime/issues/28)
- Supersedes: none

## Context and quantitative envelope

An MCP server can conform to the protocol and still return the wrong result,
cross a tenant boundary, weaken an authorization denial, repeat a side effect,
leak a credential, or become too slow or unavailable. Registry lifecycle labels
must therefore be derived from repeatable evidence for the exact code, runtime,
manifest, image, and dataset rather than from a publisher assertion.

Evaluation is a low-volume PR and release gate, not a serving workload. One
runner executes cases sequentially, so its peak concurrency is one target call.
A v1 bundle is bounded to 1 MiB, 1,000 cases, 10 attempts per case, 64 scopes,
64 assertions, 64 JSON levels, 100,000 JSON nodes, and a 60-second per-attempt
timeout. The reference workload is
8 cases and 9 calls. Twenty conforming runs plus 160 single-metric mutation
runs complete inside a five-second CI budget; the checked-in observation takes
about 0.12 seconds on the development host with zero false passes and zero
false failures. This leaves more than 10x growth to 80 reference cases before
the current budget needs review. Each case sets its own latency budget from 1
to 60,000 ms; the default experimental policy requires at least 95% latency and
99% availability scores, while internal and GA require 100% for every metric.

The runner persists no raw request, result, telemetry, token, or tenant value.
One sanitized JSON or Markdown report contains bounded identifiers, counts,
timings, failure codes, and SHA-256 digests. CI evidence should use the existing
seven-day artifact retention; longer retention stores only signed sanitized
reports. The cost is sub-second CPU for the reference gate plus the target time
of a deployed canary. No database, queue, or cache is introduced.

Assets worth stealing or corrupting are tenant data, credentials, approval and
idempotency authority, tool effects, artifact identity, evaluation outcomes,
signing keys, and Registry lifecycle state. Attackers include a malicious MCP
publisher, an authenticated caller from another tenant, a compromised target
or dependency, and an author attempting to approve their own evidence. Trust
is crossed when JSON enters the runner, when authority becomes an invocation,
when target output returns, when a report is signed, and when reviewers map the
report to a lifecycle. Every crossing validates a bounded schema, fails closed,
and retains no secret-bearing payload.

## Decision

`tesserix-mcp-testkit` owns evaluation contract v1 beside its conformance,
journey, fault, and security contracts. The checked-in JSON schema and Pydantic
model are generated from one source. A bundle fixes each tool input, structured
result or JSON-pointer assertion, tags, tenant, scopes, approval state,
idempotency key, telemetry expectations, attempts, timeout, latency budget,
metrics, blocking metrics, and optional quarantine. Its canonical SHA-256
digest changes when any of those values or its promotion policy changes.

Every run binds five exact `sha256:` identities:

- source revision;
- runtime package or executable;
- Registry manifest;
- container image; and
- canonical evaluation dataset.

The runner supports the same `EvaluationTarget` protocol in two modes.
`InProcessEvaluationTarget` adapts a local async callable.
`StreamableHttpEvaluationTarget` uses MCP 2.x `streamable_http_client` and
`ClientSession`; a per-case client factory receives the validated authority
context so it can obtain short-lived credentials without placing them in the
bundle. A target that owns its own network client requires an exact hostname
allowlist and HTTPS. Injected clients own their routing policy explicitly.

The eight metrics are correctness, schema conformance, secret leakage, tenant
isolation, authorization denial, idempotency, latency, and availability.
Synthetic secret and tenant placeholders are replaced only at invocation time.
Canaries are scanned across structured results and telemetry and never enter a
report. Idempotency requires at least two explicit attempts under one key, an
identical observable outcome, and one stable side-effect digest. The runner
does not automatically retry ordinary cases; retrying a mutation would create
an unreviewed effect. An expected target cancellation is evidence, while
cancellation of the runner task propagates for graceful shutdown.

Each case retains per-metric pass state. A failed blocking case always makes
the report fail even when an aggregate threshold would otherwise pass. Target
exceptions and evaluator timeouts produce incomplete evidence, not an
application-level success or denial. Nondeterministic cases may be quarantined
only with an owner, reason, and concrete GitHub issue. A quarantine contributes
zero to every blocking metric and cannot make a report promotable.

Reports contain only case IDs, statuses, attempts, bounded durations, safe
failure codes, metric counts and scores, artifact bindings, and outcome and
telemetry digests. Ed25519 signs canonical sanitized JSON. Verification checks
the signature, key ID, exact five-part binding, dataset digest, and bundle
identity before any lifecycle decision.

Registry lifecycle policy is encoded in the bundle:

- experimental permits in-process or Streamable HTTP evidence, allows owned
  quarantine only when it does not satisfy a blocking gate, requires the
  metric thresholds above, and requires an evaluation owner;
- internal requires Streamable HTTP, every metric at 1.0, no quarantine, and
  independent evaluation and security reviewers; and
- GA requires Streamable HTTP, every metric at 1.0, no quarantine, at least
  three reviewers, and coverage of evaluation-owner, security-reviewer,
  Registry-owner, and release-reviewer roles.

Reviewer subjects are unique and the evidence author cannot review their own
run. `assess_evaluation_promotion` emits a decision; it deliberately does not
mutate Registry state. Publication or lifecycle mutation remains the owning
control-plane workflow's separately authorized action.

The reference bundle covers happy, boundary, denial, duplicate, application
timeout, cancellation, tenant-canary, and secret-canary scenarios. The CI
mutation benchmark breaks exactly one metric at a time and proves the intended
gate fails while unrelated metrics remain green.

## Options considered

### Copy evaluation fixtures into every MCP repository

Rejected. Metric meaning, canary handling, evidence shape, and reviewer policy
would drift. A versioned testkit lets servers add domain cases while reusing one
runner, schema, report, and promotion vocabulary.

### Store raw inputs and outputs for reviewer inspection

Rejected. That turns promotion evidence into a new tenant and credential breach
surface. Exact digests, safe failure codes, and reproducible cases are enough to
bind a review; local debugging can retain ephemeral data outside promotion
evidence under the owning service's policy.

### Use only aggregate averages

Rejected. A high-volume happy path could hide one authorization, tenancy, or
secret failure. Per-case blocking state remains authoritative before aggregate
thresholds are evaluated.

### Couple the runner to one runtime or server implementation

Rejected. A structural target protocol permits the same bundle against local
code, the reusable runtime, migrated FastMCP/ADK servers, and a deployed canary
without importing their internals.

### Let the evaluator update Registry lifecycle directly

Rejected. Evaluation and control-plane mutation have different authority and
failure domains. A signed decision is portable evidence; the Registry owner
retains the mutation, audit, idempotency, and rollback boundary.

## Failure behavior, rollout, and rollback

Malformed, oversized, secret-bearing, or stale-bound bundles fail before the
first target call. A target exception or runner timeout records an incomplete
case and continues with later cases; it cannot promote. An MCP application
timeout is promotable only when the case explicitly expects the target's stable
timeout error. A task cancellation from outside the runner is re-raised. A
missing metric, low score, blocking failure, disallowed mode or quarantine,
unknown signing key, invalid signature, insufficient reviewer count, missing
reviewer role, or self-review denies promotion.

Remote calls have one explicit timeout and no implicit retry. Duplicate delivery
is exercised only by an idempotency case using one stable key. If a process
crashes after a target effect and before evidence is recorded, the report is
incomplete; replay requires a new signed run and the target's idempotency
contract prevents a second effect. There is no cross-system transaction and no
claim of exactly-once delivery.

Rollout is additive: publish schema and runner, run the reference and mutation
gates in PR CI, adopt experimental evidence in server repositories, then enable
internal and GA policy in the owning Registry workflow. Rollback is one revert
of the CI/policy integration or one pin to the previous compatible testkit
version. No live route, credential, database, or Registry object is changed by
the evaluator. Existing reports remain verifiable against their original
bundle and artifact digests but cannot be relabeled for a different policy.

## Consequences

MCP authors get one reusable bundle and runner for local and deployed testing,
and Registry owners get signed lifecycle evidence with explicit independent
review. Strict digest binding makes stale evidence unusable by design. The
tradeoff is that every domain MCP still has to author meaningful expected
results and side-effect evidence; the reusable runtime cannot infer business
correctness. A new metric or breaking case meaning requires a new schema major,
while additive cases and stricter stage thresholds change the dataset digest
and therefore require a fresh run.
