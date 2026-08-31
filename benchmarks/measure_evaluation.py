from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime

from tesserix_mcp_testkit import (
    EvaluationArtifactBinding,
    EvaluationMetric,
    EvaluationRunner,
    ReferenceEvaluationTarget,
    reference_evaluation_bundle,
)

REPETITIONS = 20
TARGET_TOTAL_SECONDS = 5


def _digest(character: str) -> str:
    return "sha256:" + character * 64


class _EvaluationClock:
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


async def _measure() -> dict[str, object]:
    bundle = reference_evaluation_bundle()
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    false_failures = 0
    false_passes = 0
    killed: set[str] = set()
    started = time.perf_counter()
    for _ in range(REPETITIONS):
        conforming = await EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=ReferenceEvaluationTarget(),
            monotonic=_EvaluationClock(slow_first_case=False),
            now=lambda: datetime(2026, 8, 31, tzinfo=UTC),
        ).run()
        if not conforming.passed or any(summary.score != 1.0 for summary in conforming.metrics):
            false_failures += 1
        for defect in EvaluationMetric:
            mutated = await EvaluationRunner(
                bundle=bundle,
                binding=binding,
                target=ReferenceEvaluationTarget(defect=defect),
                monotonic=_EvaluationClock(slow_first_case=defect is EvaluationMetric.LATENCY),
                now=lambda: datetime(2026, 8, 31, tzinfo=UTC),
            ).run()
            if mutated.passed or mutated.metric(defect).score == 1.0:
                false_passes += 1
            else:
                killed.add(defect.value)
    duration = time.perf_counter() - started
    passed = (
        false_failures == 0
        and false_passes == 0
        and killed == {metric.value for metric in EvaluationMetric}
        and duration < TARGET_TOTAL_SECONDS
    )
    return {
        "schema_version": 1,
        "dataset_digest": bundle.dataset_digest,
        "repetitions": REPETITIONS,
        "case_count": len(bundle.cases),
        "metric_count": len(EvaluationMetric),
        "false_failures": false_failures,
        "false_passes": false_passes,
        "killed_metrics": sorted(killed),
        "target_total_seconds": TARGET_TOTAL_SECONDS,
        "total_duration_seconds": round(duration, 6),
        "passed": passed,
    }


def main() -> int:
    report = asyncio.run(_measure())
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
