from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
MEASURE = ROOT / "benchmarks" / "measure_evaluation.py"
OBSERVATION = ROOT / "benchmarks" / "evaluation-observations.json"


def test_evaluation_measurement_is_repeatable_and_kills_every_metric_mutant() -> None:
    completed = subprocess.run(
        [sys.executable, str(MEASURE)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["schema_version"] == 1
    assert report["repetitions"] == 20
    assert report["false_failures"] == 0
    assert report["false_passes"] == 0
    assert report["target_total_seconds"] == 5
    assert report["total_duration_seconds"] < report["target_total_seconds"]
    assert set(report["killed_metrics"]) == {
        "authorization_denial",
        "availability",
        "correctness",
        "idempotency",
        "latency",
        "schema_conformance",
        "secret_leakage",
        "tenant_isolation",
    }
    assert report["passed"] is True


def test_checked_in_evaluation_observation_has_zero_false_results() -> None:
    report = json.loads(OBSERVATION.read_text(encoding="utf-8"))

    assert report["schema_version"] == 1
    assert report["repetitions"] >= 20
    assert report["false_failures"] == 0
    assert report["false_passes"] == 0
    assert report["total_duration_seconds"] < report["target_total_seconds"]
    assert report["passed"] is True
