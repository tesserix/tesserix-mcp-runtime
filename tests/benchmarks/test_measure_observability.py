from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
MEASURE = ROOT / "benchmarks" / "measure_observability.py"
OBSERVATION = ROOT / "benchmarks" / "observability-observations.json"


def test_observability_benchmark_reports_hot_path_p99_below_runtime_budget() -> None:
    completed = subprocess.run(
        [sys.executable, str(MEASURE), "--samples", "20", "--warmup", "2"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["schema_version"] == 1
    assert report["samples"] == 20
    assert report["warmup"] == 2
    assert report["target_p99_milliseconds"] == 15
    assert report["case"] == "successful_tool_call_observability"
    assert report["events_per_sample"] == 7
    assert report["latency_milliseconds"]["p50"] >= 0
    assert report["latency_milliseconds"]["p99"] < 15
    assert report["passed"] is True


def test_checked_in_observability_observation_meets_runtime_budget() -> None:
    report = json.loads(OBSERVATION.read_text(encoding="utf-8"))

    assert report["schema_version"] == 1
    assert report["samples"] >= 1_000
    assert report["target_p99_milliseconds"] == 15
    assert report["latency_milliseconds"]["p99"] < 15
    assert report["passed"] is True
