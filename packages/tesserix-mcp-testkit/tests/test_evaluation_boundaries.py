from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tesserix_mcp_testkit import (
    SECRET_CANARY_PLACEHOLDER,
    TENANT_CANARY_PLACEHOLDER,
    AssertionOperator,
    AssertionsExpectation,
    ErrorExpectation,
    EvaluationApproval,
    EvaluationArtifactBinding,
    EvaluationAssertion,
    EvaluationBundle,
    EvaluationCase,
    EvaluationContext,
    EvaluationContractError,
    EvaluationInvocation,
    EvaluationMetric,
    EvaluationMode,
    EvaluationObservation,
    EvaluationPromotionPolicy,
    EvaluationQuarantine,
    EvaluationReview,
    EvaluationReviewer,
    EvaluationRunner,
    EvaluationSignature,
    EvaluationVerificationError,
    InProcessEvaluationTarget,
    PromotionMetricGate,
    PromotionStage,
    PromotionStagePolicy,
    ReviewerRole,
    StreamableHttpEvaluationTarget,
    TelemetryExpectation,
    load_evaluation_bundle,
    sign_evaluation_report,
    verify_evaluation_report,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _context() -> EvaluationContext:
    return EvaluationContext(
        tenant="tenant-a",
        scopes=("orders:read",),
        approval=EvaluationApproval(required=False, granted=False),
    )


def _case(**updates: object) -> EvaluationCase:
    document: dict[str, object] = {
        "case_id": "orders.happy",
        "tool": "orders.get",
        "arguments": {},
        "expectation": {"kind": "structured_result", "value": {"status": "ready"}},
        "tags": ["happy"],
        "context": _context().model_dump(mode="json"),
        "metrics": ["correctness"],
        "blocking_metrics": ["correctness"],
        "latency_budget_ms": 250,
    }
    document.update(updates)
    return EvaluationCase.model_validate(document)


def _binding(bundle: EvaluationBundle) -> EvaluationArtifactBinding:
    return EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )


@pytest.mark.parametrize(
    "factory",
    (
        lambda: EvaluationApproval(required=True, granted=True),
        lambda: EvaluationContext(
            tenant="tenant-a",
            scopes=("orders:read", "orders:read"),
            approval=EvaluationApproval(required=False, granted=False),
        ),
        lambda: EvaluationAssertion(pointer="value", operator=AssertionOperator.EXISTS),
        lambda: EvaluationAssertion(
            pointer="/value",
            operator=AssertionOperator.EXISTS,
            value="unexpected",
        ),
        lambda: ErrorExpectation(code="Unsafe Error"),
        lambda: TelemetryExpectation(
            required_events=("tool.completed",),
            forbidden_events=("tool.completed",),
        ),
        lambda: EvaluationQuarantine(
            owner="Runtime Team",
            issue="https://github.com/tesserix/tesserix-mcp-runtime/issues/28",
            reason="race",
        ),
        lambda: EvaluationQuarantine(
            owner="runtime-team",
            issue="https://attacker.invalid/28",
            reason="race",
        ),
        lambda: EvaluationArtifactBinding(
            source_digest="sha256:not-a-digest",
            runtime_digest=_digest("2"),
            manifest_digest=_digest("3"),
            image_digest=_digest("4"),
            dataset_digest=_digest("5"),
        ),
        lambda: EvaluationObservation(
            error_code="forbidden",
            cancelled=True,
            schema_valid=True,
        ),
        lambda: EvaluationObservation(
            error_code="Unsafe Error",
            schema_valid=True,
        ),
        lambda: EvaluationObservation(
            schema_valid=True,
            telemetry_events=("tool.completed", "tool.completed"),
        ),
        lambda: EvaluationObservation(
            schema_valid=True,
            side_effect_digest="sha256:bad",
        ),
        lambda: EvaluationReviewer(
            subject="Invalid Reviewer", roles=(ReviewerRole.EVALUATION_OWNER,)
        ),
        lambda: EvaluationReviewer(
            subject="reviewer",
            roles=(ReviewerRole.EVALUATION_OWNER, ReviewerRole.EVALUATION_OWNER),
        ),
        lambda: EvaluationReview(author="Invalid Author", reviewers=()),
        lambda: EvaluationReview(
            author="author",
            reviewers=(
                EvaluationReviewer(
                    subject="reviewer",
                    roles=(ReviewerRole.EVALUATION_OWNER,),
                ),
                EvaluationReviewer(
                    subject="reviewer",
                    roles=(ReviewerRole.SECURITY_REVIEWER,),
                ),
            ),
        ),
        lambda: EvaluationSignature(key_id="Invalid Key", value="A" * 88),
    ),
)
def test_boundary_models_reject_ambiguous_or_unsafe_values(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ValueError):
        factory()


@pytest.mark.parametrize(
    "updates",
    (
        {"case_id": "Unsafe Case"},
        {"tags": ["happy", "happy"]},
        {"metrics": ["correctness", "correctness"]},
        {"blocking_metrics": ["availability"]},
        {"latency_budget_ms": 251, "timeout_ms": 250},
        {"arguments": {"value": SECRET_CANARY_PLACEHOLDER}},
        {"metrics": ["secret_leakage"], "blocking_metrics": ["secret_leakage"]},
        {"arguments": {"value": TENANT_CANARY_PLACEHOLDER}},
        {"metrics": ["tenant_isolation"], "blocking_metrics": ["tenant_isolation"]},
        {"metrics": ["idempotency"], "blocking_metrics": ["idempotency"]},
    ),
)
def test_case_cross_field_invariants_fail_closed(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _case(**updates)


def test_policy_and_bundle_identity_must_be_unique_and_versioned() -> None:
    gate = PromotionMetricGate(metric=EvaluationMetric.CORRECTNESS, minimum_score=1.0)
    stage = PromotionStagePolicy(
        stage=PromotionStage.EXPERIMENTAL,
        gates=(gate,),
        allowed_modes=(EvaluationMode.IN_PROCESS,),
        required_reviewer_roles=(ReviewerRole.EVALUATION_OWNER,),
        minimum_reviewers=1,
        allow_quarantine=True,
    )
    with pytest.raises(ValueError):
        PromotionStagePolicy(
            stage=PromotionStage.EXPERIMENTAL,
            gates=(gate, gate),
            allowed_modes=(EvaluationMode.IN_PROCESS,),
            required_reviewer_roles=(ReviewerRole.EVALUATION_OWNER,),
            minimum_reviewers=1,
            allow_quarantine=True,
        )
    with pytest.raises(ValueError):
        EvaluationPromotionPolicy(stages=(stage, stage))
    with pytest.raises(EvaluationContractError):
        EvaluationPromotionPolicy(stages=(stage,)).for_stage(PromotionStage.GA)
    with pytest.raises(ValueError):
        EvaluationBundle(name="Unsafe Bundle", version="1.0.0", cases=(_case(),))
    with pytest.raises(ValueError):
        EvaluationBundle(name="orders", version="latest", cases=(_case(),))
    with pytest.raises(ValueError):
        EvaluationBundle(name="orders", version="1.0.0", cases=(_case(), _case()))


def test_every_json_pointer_assertion_operator_runs_through_public_adapter() -> None:
    assertions = (
        EvaluationAssertion(pointer="/value", operator=AssertionOperator.EQUALS, value="ready"),
        EvaluationAssertion(
            pointer="/value",
            operator=AssertionOperator.NOT_EQUALS,
            value="wrong",
        ),
        EvaluationAssertion(pointer="/value", operator=AssertionOperator.EXISTS),
        EvaluationAssertion(pointer="/missing", operator=AssertionOperator.ABSENT),
        EvaluationAssertion(pointer="/items", operator=AssertionOperator.CONTAINS, value="a"),
        EvaluationAssertion(
            pointer="/items",
            operator=AssertionOperator.NOT_CONTAINS,
            value="z",
        ),
    )
    cases = tuple(
        _case(
            case_id=f"orders.assertion-{index}",
            expectation=AssertionsExpectation(assertions=(assertion,)),
        )
        for index, assertion in enumerate(assertions, start=1)
    )
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=cases)

    async def handler(invocation: EvaluationInvocation) -> EvaluationObservation:
        del invocation
        return EvaluationObservation(
            structured_result={"value": "ready", "items": ["a", "b"]},
            schema_valid=True,
        )

    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=_binding(bundle),
            target=InProcessEvaluationTarget(handler),
        ).run()
    )

    assert report.passed is True
    with pytest.raises(EvaluationContractError):
        report.metric(EvaluationMetric.AVAILABILITY)


def test_signature_verification_rejects_missing_unknown_and_wrong_binding() -> None:
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(_case(),))
    binding = _binding(bundle)

    async def handler(invocation: EvaluationInvocation) -> EvaluationObservation:
        del invocation
        return EvaluationObservation(
            structured_result={"status": "ready"},
            schema_valid=True,
        )

    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=InProcessEvaluationTarget(handler),
        ).run()
    )
    private_key = Ed25519PrivateKey.generate()
    with pytest.raises(EvaluationVerificationError, match="signature_missing"):
        verify_evaluation_report(report, bundle=bundle, binding=binding, public_keys={})
    signed = sign_evaluation_report(report, key_id="ci-key", private_key=private_key)
    with pytest.raises(EvaluationVerificationError, match="already_signed"):
        sign_evaluation_report(signed, key_id="ci-key", private_key=private_key)
    with pytest.raises(EvaluationVerificationError, match="signing_key_unknown"):
        verify_evaluation_report(signed, bundle=bundle, binding=binding, public_keys={})
    wrong_binding = binding.model_copy(update={"image_digest": _digest("9")})
    with pytest.raises(EvaluationVerificationError, match="binding_mismatch"):
        verify_evaluation_report(
            signed,
            bundle=bundle,
            binding=wrong_binding,
            public_keys={"ci-key": private_key.public_key()},
        )
    invalid_signature = signed.model_copy(
        update={
            "signature": EvaluationSignature(
                key_id="ci-key",
                value=base64.b64encode(b"\0" * 64).decode(),
            )
        }
    )
    with pytest.raises(EvaluationVerificationError, match="signature_invalid"):
        verify_evaluation_report(
            invalid_signature,
            bundle=bundle,
            binding=binding,
            public_keys={"ci-key": private_key.public_key()},
        )


def test_loader_and_http_configuration_are_bounded() -> None:
    untyped_loader = cast(Callable[[object], EvaluationBundle], load_evaluation_bundle)
    with pytest.raises(EvaluationContractError, match="bundle_type"):
        untyped_loader(42)
    with pytest.raises(EvaluationContractError, match="bundle_bounds"):
        load_evaluation_bundle(b"")
    with pytest.raises(EvaluationContractError, match="bundle_bounds"):
        load_evaluation_bundle(b" " * (1024 * 1024 + 1))
    with pytest.raises(EvaluationContractError, match="invalid_json"):
        load_evaluation_bundle("{")
    with pytest.raises(EvaluationContractError, match="invalid_bundle"):
        load_evaluation_bundle('{"schema_version":1}')
    with pytest.raises(EvaluationContractError, match="streamable_http_url"):
        StreamableHttpEvaluationTarget(url="http://gateway.example/mcp")
    with pytest.raises(EvaluationContractError, match="streamable_http_url"):
        StreamableHttpEvaluationTarget(url="https://user:pass@gateway.example/mcp")
    with pytest.raises(EvaluationContractError, match="streamable_http_host"):
        StreamableHttpEvaluationTarget(
            url="https://gateway.example/mcp",
            allowed_hosts=("INVALID HOST",),
        )
