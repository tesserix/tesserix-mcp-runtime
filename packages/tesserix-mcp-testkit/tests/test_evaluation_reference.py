from __future__ import annotations

import asyncio

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tesserix_mcp_testkit import (
    EvaluationArtifactBinding,
    EvaluationMetric,
    EvaluationMode,
    EvaluationReview,
    EvaluationReviewer,
    EvaluationRunner,
    PromotionStage,
    ReferenceEvaluationTarget,
    ReviewerRole,
    assess_evaluation_promotion,
    reference_evaluation_bundle,
    sign_evaluation_report,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def test_reference_bundle_covers_required_scenarios_and_metrics() -> None:
    bundle = reference_evaluation_bundle()
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )

    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=ReferenceEvaluationTarget(),
        ).run()
    )

    observed_tags = {tag for case in bundle.cases for tag in case.tags}
    assert {
        "happy",
        "boundary",
        "denial",
        "duplicate",
        "timeout",
        "cancellation",
        "tenant-canary",
        "secret-canary",
    } <= observed_tags
    assert {summary.metric for summary in report.metrics} == set(EvaluationMetric)
    assert all(summary.score == 1.0 for summary in report.metrics)
    assert report.passed is True


class _MutationClock:
    def __init__(self, *, slow_first_case: bool) -> None:
        self._call = 0
        self._slow_first_case = slow_first_case

    def __call__(self) -> float:
        call = self._call
        self._call += 1
        if self._slow_first_case and call == 1:
            return 0.300
        if self._slow_first_case and call > 1:
            return 0.300 + (call - 1) * 0.001
        return call * 0.001


@pytest.mark.parametrize("defect", tuple(EvaluationMetric), ids=lambda metric: metric.value)
def test_each_deliberately_broken_target_is_killed_by_exactly_its_gate(
    defect: EvaluationMetric,
) -> None:
    bundle = reference_evaluation_bundle()
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )

    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=ReferenceEvaluationTarget(defect=defect),
            monotonic=_MutationClock(slow_first_case=defect is EvaluationMetric.LATENCY),
        ).run()
    )

    assert report.metric(defect).score < 1.0
    assert report.passed is False
    assert all(summary.score == 1.0 for summary in report.metrics if summary.metric is not defect)


def test_default_ga_policy_requires_signed_remote_evidence_and_independent_roles() -> None:
    bundle = reference_evaluation_bundle()
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=ReferenceEvaluationTarget(mode=EvaluationMode.STREAMABLE_HTTP),
        ).run()
    )
    private_key = Ed25519PrivateKey.generate()
    signed = sign_evaluation_report(report, key_id="ci-evaluation", private_key=private_key)
    review = EvaluationReview(
        author="runtime-author",
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
        public_keys={"ci-evaluation": private_key.public_key()},
        stage=PromotionStage.GA,
        review=review,
    )

    assert decision.approved is True
    assert decision.reasons == ()
    with pytest.raises(ValueError, match="cannot approve their own"):
        EvaluationReview(
            author="runtime-author",
            reviewers=(
                EvaluationReviewer(
                    subject="runtime-author",
                    roles=(ReviewerRole.EVALUATION_OWNER,),
                ),
            ),
        )
