# Evaluation bundles and Registry promotion

Evaluation contract v1 lets an MCP repository define domain behavior once and
run the same cases against local code and a deployed Streamable HTTP canary.
The reusable contract lives in `tesserix-mcp-testkit`; a server repository owns
only its cases, target adapter, artifact digests, and reviewers.

## What a bundle contains

Every `EvaluationCase` contains:

- a stable case ID, tool name, bounded JSON arguments, and scenario tags;
- one exact structured result, a set of JSON-pointer assertions, an expected
  error code, or expected cancellation;
- tenant, scopes, approval state, and optional idempotency key;
- required and forbidden telemetry event names;
- attempts, per-attempt timeout, and latency budget;
- evaluated metrics and the subset that blocks promotion; and
- optional quarantine with an owner, reason, and concrete GitHub issue.

The package ships the equivalent JSON schema at
`tesserix_mcp_testkit/schemas/evaluation-bundle-v1.schema.json`. Unknown fields
are rejected. `load_evaluation_bundle` accepts at most 1 MiB and rejects bearer
or secret-shaped input before a target is called.

Use `reference_evaluation_bundle()` as an executable example. It includes
happy, boundary, denial, duplicate, application-timeout, cancellation,
tenant-canary, and secret-canary cases and covers all eight metrics.

## Run the same bundle locally

```python
from tesserix_mcp_testkit import (
    EvaluationArtifactBinding,
    EvaluationObservation,
    EvaluationRunner,
    InProcessEvaluationTarget,
    reference_evaluation_bundle,
)

bundle = reference_evaluation_bundle()
binding = EvaluationArtifactBinding(
    source_digest="sha256:" + "1" * 64,
    runtime_digest="sha256:" + "2" * 64,
    manifest_digest="sha256:" + "3" * 64,
    image_digest="sha256:" + "4" * 64,
    dataset_digest=bundle.dataset_digest,
)


async def invoke(invocation):
    value = await application.invoke(
        invocation.tool,
        invocation.arguments,
        tenant=invocation.context.tenant,
        scopes=invocation.context.scopes,
    )
    return EvaluationObservation(
        structured_result=value,
        schema_valid=True,
        telemetry_events=("tool.completed",),
    )


report = await EvaluationRunner(
    bundle=bundle,
    binding=binding,
    target=InProcessEvaluationTarget(invoke),
).run()
```

The handler receives a frozen, validated `EvaluationInvocation`. It must return
an `EvaluationObservation`; target exceptions and evaluator timeouts become
incomplete evidence and cannot promote.

## Run against Streamable HTTP

Provide a per-case client factory when credentials or trusted headers depend on
tenant, scopes, or approval state:

```python
from contextlib import asynccontextmanager

import httpx2 as httpx
from tesserix_mcp_testkit import StreamableHttpEvaluationTarget


@asynccontextmanager
async def client_for(context):
    token = await credential_provider.issue(
        tenant=context.tenant,
        scopes=context.scopes,
        approval=context.approval,
    )
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        yield client


target = StreamableHttpEvaluationTarget(
    url="https://orders-mcp.canary.example/mcp",
    http_client_factory=client_for,
)
report = await EvaluationRunner(
    bundle=bundle,
    binding=binding,
    target=target,
).run()
```

The credential exists only inside the client context. It is absent from the
bundle and report. If the target creates its own client, pass an exact
`allowed_hosts` tuple; HTTP is accepted only with an injected test client or
factory, while owned network calls require HTTPS.

## Canary and idempotency cases

Use `SECRET_CANARY_PLACEHOLDER` or `TENANT_CANARY_PLACEHOLDER` in case
arguments. The runner replaces the placeholder immediately before invocation,
scans structured output and telemetry for the generated value, hashes the
observation, and discards the raw value. A leak fails its blocking metric while
JSON and Markdown remain safe.

An idempotency case must set at least two attempts and one idempotency key. Each
observation supplies a `side_effect_digest`. The gate requires identical
results and one stable side-effect digest across every attempt; matching result
bodies do not hide a duplicated effect.

## Sign and assess promotion

```python
from tesserix_mcp_testkit import (
    EvaluationReview,
    EvaluationReviewer,
    PromotionStage,
    ReviewerRole,
    assess_evaluation_promotion,
    sign_evaluation_report,
)

signed = sign_evaluation_report(
    report,
    key_id="evaluation-ci-2026-08",
    private_key=ci_signing_key,
)
review = EvaluationReview(
    author="orders-runtime-author",
    reviewers=(
        EvaluationReviewer(
            subject="quality-reviewer",
            roles=(ReviewerRole.EVALUATION_OWNER,),
        ),
        EvaluationReviewer(
            subject="security-reviewer",
            roles=(ReviewerRole.SECURITY_REVIEWER,),
        ),
        EvaluationReviewer(
            subject="release-reviewer",
            roles=(ReviewerRole.REGISTRY_OWNER, ReviewerRole.RELEASE_REVIEWER),
        ),
    ),
)
decision = assess_evaluation_promotion(
    signed,
    bundle=bundle,
    binding=binding,
    public_keys={"evaluation-ci-2026-08": ci_signing_key.public_key()},
    stage=PromotionStage.GA,
    review=review,
)
```

The default lifecycle policy is:

| Stage | Modes | Metrics | Quarantine | Review |
| --- | --- | --- | --- | --- |
| experimental | in-process or HTTP | security/correctness 1.0, latency 0.95, availability 0.99 | owned only; never satisfies a blocker | evaluation owner |
| internal | HTTP | all 1.0 | denied | evaluation owner + security reviewer |
| GA | HTTP | all 1.0 | denied | at least three independent reviewers covering evaluation, security, Registry, and release roles |

The author cannot review their own evidence. Assessment returns a sanitized
decision and never changes Registry state; the Registry control-plane workflow
retains separate authority, audit, idempotency, and rollback responsibility.

## Reports and CI

`report.to_json()` and `report.to_markdown()` contain only case IDs, statuses,
attempt counts, durations, safe failure codes, metric scores, exact artifact
bindings, and outcome/telemetry digests. Never attach local debug payloads to a
promotion report.

The repository runs `benchmarks/measure_evaluation.py` as a named CI gate. It
repeats the conforming reference run and every single-metric mutant 20 times,
requires zero false failures and zero false passes, and must complete within
five seconds. A changed bundle, policy, manifest, source, runtime, or image
requires a fresh signed report because its digest binding no longer matches.
