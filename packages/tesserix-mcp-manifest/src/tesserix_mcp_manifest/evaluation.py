from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from tesserix_mcp_manifest.models import DiscoveryPhrase, ManifestModel, RegistryARN


class DiscoveryScenario(StrEnum):
    AMBIGUOUS = "ambiguous"
    NEAR_DUPLICATE = "near-duplicate"
    WRONG_TENANT = "wrong-tenant"
    DEPRECATED = "deprecated"
    INCOMPATIBLE = "incompatible"
    NO_GOOD_MATCH = "no-good-match"


class DiscoveryIntentCase(ManifestModel):
    case_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    intent: DiscoveryPhrase
    scenarios: tuple[DiscoveryScenario, ...] = Field(min_length=1, max_length=6)
    relevant_artifact_ids: tuple[RegistryARN, ...] = Field(default=(), max_length=20)
    forbidden_artifact_ids: tuple[RegistryARN, ...] = Field(default=(), max_length=20)
    incompatible_artifact_ids: tuple[RegistryARN, ...] = Field(default=(), max_length=20)
    deprecated_artifact_ids: tuple[RegistryARN, ...] = Field(default=(), max_length=20)
    no_good_match: bool = False

    @model_validator(mode="after")
    def validate_expected_results(self) -> Self:
        if self.no_good_match == bool(self.relevant_artifact_ids):
            raise ValueError("intent case must choose relevant artifacts or no-good-match")
        if (DiscoveryScenario.NO_GOOD_MATCH in self.scenarios) != self.no_good_match:
            raise ValueError("no-good-match scenario must match expected behavior")
        if (DiscoveryScenario.WRONG_TENANT in self.scenarios) != bool(self.forbidden_artifact_ids):
            raise ValueError("wrong-tenant scenario must identify forbidden artifacts")
        if (DiscoveryScenario.INCOMPATIBLE in self.scenarios) != bool(
            self.incompatible_artifact_ids
        ):
            raise ValueError("incompatible scenario must identify incompatible artifacts")
        if (DiscoveryScenario.DEPRECATED in self.scenarios) != bool(self.deprecated_artifact_ids):
            raise ValueError("deprecated scenario must identify deprecated artifacts")
        relevant = set(self.relevant_artifact_ids)
        if relevant.intersection(self.forbidden_artifact_ids):
            raise ValueError("relevant artifacts cannot be forbidden")
        if relevant.intersection(self.incompatible_artifact_ids):
            raise ValueError("relevant artifacts cannot be incompatible")
        if relevant.intersection(self.deprecated_artifact_ids):
            raise ValueError("relevant artifacts cannot be deprecated")
        return self


class DiscoveryIntentResult(ManifestModel):
    case_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    ranked_artifact_ids: tuple[RegistryARN, ...] = Field(default=(), max_length=50)

    @model_validator(mode="after")
    def reject_duplicate_candidates(self) -> Self:
        if len(set(self.ranked_artifact_ids)) != len(self.ranked_artifact_ids):
            raise ValueError("ranked artifact identifiers must be unique")
        return self


class DiscoveryEvaluationDataset(ManifestModel):
    dataset_version: Literal["1.0"] = "1.0"
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    k: int = Field(ge=1, le=20)
    cases: tuple[DiscoveryIntentCase, ...] = Field(min_length=1, max_length=100)
    recorded_results: tuple[DiscoveryIntentResult, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_coverage_and_results(self) -> Self:
        scenarios = {scenario for case in self.cases for scenario in case.scenarios}
        if scenarios != set(DiscoveryScenario):
            raise ValueError("evaluation dataset must cover every discovery scenario")
        case_ids = [case.case_id for case in self.cases]
        result_ids = [result.case_id for result in self.recorded_results]
        if len(set(case_ids)) != len(case_ids) or len(set(result_ids)) != len(result_ids):
            raise ValueError("evaluation dataset identifiers must be unique")
        if set(case_ids) != set(result_ids):
            raise ValueError("evaluation dataset results must match intent cases")
        return self


class DiscoveryEvaluationMetrics(ManifestModel):
    k: int = Field(ge=1, le=20)
    case_count: int = Field(ge=1)
    positive_case_count: int = Field(ge=0)
    no_match_case_count: int = Field(ge=0)
    precision_at_k: float = Field(ge=0.0, le=1.0)
    no_match_accuracy: float = Field(ge=0.0, le=1.0)
    incompatible_recommendations: int = Field(ge=0)
    deprecated_recommendations: int = Field(ge=0)
    forbidden_exposure_count: int = Field(ge=0)


def evaluate_discovery(
    cases: tuple[DiscoveryIntentCase, ...],
    results: tuple[DiscoveryIntentResult, ...],
    *,
    k: int,
) -> DiscoveryEvaluationMetrics:
    if not 1 <= k <= 20:
        raise ValueError("evaluation k must be between 1 and 20")
    if not cases:
        raise ValueError("evaluation requires at least one intent case")
    case_ids = [case.case_id for case in cases]
    result_ids = [result.case_id for result in results]
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("evaluation case identifiers must be unique")
    if len(set(result_ids)) != len(result_ids):
        raise ValueError("evaluation result identifiers must be unique")
    if set(case_ids) != set(result_ids):
        raise ValueError("evaluation results must match intent cases")

    results_by_id = {result.case_id: result for result in results}
    precision_total = 0.0
    positive_case_count = 0
    no_match_case_count = 0
    correct_no_match_count = 0
    incompatible_recommendations = 0
    deprecated_recommendations = 0
    forbidden_exposure_count = 0
    for case in cases:
        ranked = results_by_id[case.case_id].ranked_artifact_ids
        if case.relevant_artifact_ids:
            positive_case_count += 1
            relevant = set(case.relevant_artifact_ids)
            precision_total += sum(candidate in relevant for candidate in ranked[:k]) / k
        else:
            no_match_case_count += 1
            correct_no_match_count += not ranked
        incompatible = set(case.incompatible_artifact_ids)
        deprecated = set(case.deprecated_artifact_ids)
        forbidden = set(case.forbidden_artifact_ids)
        incompatible_recommendations += sum(candidate in incompatible for candidate in ranked)
        deprecated_recommendations += sum(candidate in deprecated for candidate in ranked)
        forbidden_exposure_count += sum(candidate in forbidden for candidate in ranked)

    return DiscoveryEvaluationMetrics(
        k=k,
        case_count=len(cases),
        positive_case_count=positive_case_count,
        no_match_case_count=no_match_case_count,
        precision_at_k=(precision_total / positive_case_count if positive_case_count else 1.0),
        no_match_accuracy=(
            correct_no_match_count / no_match_case_count if no_match_case_count else 1.0
        ),
        incompatible_recommendations=incompatible_recommendations,
        deprecated_recommendations=deprecated_recommendations,
        forbidden_exposure_count=forbidden_exposure_count,
    )


__all__ = [
    "DiscoveryEvaluationDataset",
    "DiscoveryEvaluationMetrics",
    "DiscoveryIntentCase",
    "DiscoveryIntentResult",
    "DiscoveryScenario",
    "evaluate_discovery",
]
