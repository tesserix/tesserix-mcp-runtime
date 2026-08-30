from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
MEASURE = ROOT / "benchmarks" / "measure_execution_limits.py"


def test_execution_limit_benchmark_reports_every_json_ceiling() -> None:
    completed = subprocess.run(
        [sys.executable, str(MEASURE), "--samples", "2"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["schema_version"] == 1
    assert report["samples_per_case"] == 2
    assert {case["name"] for case in report["cases"]} == {
        "input_bytes",
        "result_bytes",
        "json_depth",
        "object_properties",
        "array_items",
        "json_nodes",
    }
    for case in report["cases"]:
        assert case["configured_ceiling"] > 0
        assert case["observed_units"] == case["configured_ceiling"]
        assert case["encoded_bytes"] > 0
        assert case["latency_milliseconds"]["p50"] >= 0
        assert case["latency_milliseconds"]["p99"] >= 0
        assert case["peak_temporary_bytes"] >= 0
