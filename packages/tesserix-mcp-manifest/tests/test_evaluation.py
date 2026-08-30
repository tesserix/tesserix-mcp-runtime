from __future__ import annotations

from pathlib import Path

import pytest
from tesserix_mcp_manifest import (
    DiscoveryEvaluationDataset,
    DiscoveryEvaluationMetrics,
    DiscoveryIntentCase,
    DiscoveryIntentResult,
    DiscoveryScenario,
    evaluate_discovery,
)


@pytest.mark.parametrize(
    "document",
    [
        {
            "case_id": "missing-no-match-tag",
            "intent": "Will it rain in Melbourne tomorrow?",
            "scenarios": (DiscoveryScenario.AMBIGUOUS,),
            "no_good_match": True,
        },
        {
            "case_id": "missing-forbidden-evidence",
            "intent": "Find one customer order.",
            "scenarios": (DiscoveryScenario.WRONG_TENANT,),
            "relevant_artifact_ids": (
                "arn:agentic:registry:tenant-orders:tools/tenant-orders/orders_get",
            ),
        },
        {
            "case_id": "missing-deprecated-evidence",
            "intent": "Find one supported customer order tool.",
            "scenarios": (DiscoveryScenario.DEPRECATED,),
            "relevant_artifact_ids": (
                "arn:agentic:registry:tenant-orders:tools/tenant-orders/orders_get",
            ),
        },
        {
            "case_id": "missing-incompatible-evidence",
            "intent": "Find one compatible customer order tool.",
            "scenarios": (DiscoveryScenario.INCOMPATIBLE,),
            "relevant_artifact_ids": (
                "arn:agentic:registry:tenant-orders:tools/tenant-orders/orders_get",
            ),
        },
    ],
)
def test_intent_case_requires_evidence_for_scenario_labels(
    document: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        DiscoveryIntentCase.model_validate(document)


def test_evaluation_records_macro_precision_at_k() -> None:
    expected = "arn:agentic:registry:tenant-orders:tools/tenant-orders/orders_get"
    distractor = "arn:agentic:registry:tenant-orders:tools/tenant-orders/orders_search"
    case = DiscoveryIntentCase(
        case_id="known-order",
        intent="Where is customer order A-123?",
        scenarios=(DiscoveryScenario.AMBIGUOUS,),
        relevant_artifact_ids=(expected,),
    )
    result = DiscoveryIntentResult(
        case_id=case.case_id,
        ranked_artifact_ids=(expected, distractor),
    )

    assert evaluate_discovery((case,), (result,), k=2) == DiscoveryEvaluationMetrics(
        k=2,
        case_count=1,
        positive_case_count=1,
        no_match_case_count=0,
        precision_at_k=0.5,
        no_match_accuracy=1.0,
        incompatible_recommendations=0,
        deprecated_recommendations=0,
        forbidden_exposure_count=0,
    )


def test_checked_in_dataset_covers_scenarios_and_records_safe_metrics() -> None:
    source = (Path(__file__).parents[1] / "evaluation" / "semantic-discovery.json").read_bytes()
    dataset = DiscoveryEvaluationDataset.model_validate_json(source)

    assert {scenario for case in dataset.cases for scenario in case.scenarios} == set(
        DiscoveryScenario
    )
    assert evaluate_discovery(
        dataset.cases,
        dataset.recorded_results,
        k=dataset.k,
    ) == DiscoveryEvaluationMetrics(
        k=1,
        case_count=6,
        positive_case_count=5,
        no_match_case_count=1,
        precision_at_k=1.0,
        no_match_accuracy=1.0,
        incompatible_recommendations=0,
        deprecated_recommendations=0,
        forbidden_exposure_count=0,
    )


def test_evaluation_records_no_match_and_unsafe_recommendations() -> None:
    expected = "arn:agentic:registry:tenant-orders:tools/tenant-orders/orders_get"
    forbidden = "arn:agentic:registry:tenant-other:tools/tenant-other/orders_get"
    incompatible = "arn:agentic:registry:tenant-orders:tools/tenant-orders/orders_delete"
    deprecated = "arn:agentic:registry:tenant-orders:tools/tenant-orders/orders_get_v1"
    cases = (
        DiscoveryIntentCase(
            case_id="unsupported-weather",
            intent="Will it rain in Melbourne tomorrow?",
            scenarios=(DiscoveryScenario.NO_GOOD_MATCH, DiscoveryScenario.WRONG_TENANT),
            forbidden_artifact_ids=(forbidden,),
            no_good_match=True,
        ),
        DiscoveryIntentCase(
            case_id="compatible-order-read",
            intent="Find one order without changing it.",
            scenarios=(DiscoveryScenario.INCOMPATIBLE, DiscoveryScenario.DEPRECATED),
            relevant_artifact_ids=(expected,),
            incompatible_artifact_ids=(incompatible,),
            deprecated_artifact_ids=(deprecated,),
        ),
    )
    results = (
        DiscoveryIntentResult(
            case_id="unsupported-weather",
            ranked_artifact_ids=(forbidden,),
        ),
        DiscoveryIntentResult(
            case_id="compatible-order-read",
            ranked_artifact_ids=(incompatible, deprecated),
        ),
    )

    assert evaluate_discovery(cases, results, k=2) == DiscoveryEvaluationMetrics(
        k=2,
        case_count=2,
        positive_case_count=1,
        no_match_case_count=1,
        precision_at_k=0.0,
        no_match_accuracy=0.0,
        incompatible_recommendations=1,
        deprecated_recommendations=1,
        forbidden_exposure_count=1,
    )
