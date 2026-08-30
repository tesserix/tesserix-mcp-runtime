from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
MEASURE = ROOT / "benchmarks" / "measure_conformance.py"
OBSERVATION = ROOT / "benchmarks" / "conformance-observations.json"


def test_conformance_measurement_runs_every_default_lane_and_kills_mutants() -> None:
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
    assert report["contract_version"] == "1.0"
    assert report["target_total_seconds"] == 10
    assert report["total_duration_seconds"] < report["target_total_seconds"]
    assert {lane["name"]: (lane["passed"], lane["skipped"]) for lane in report["lanes"]} == {
        "core": (24, 0),
        "external": (2, 22),
        "sdk": (2, 0),
    }
    assert {mutant["name"]: mutant["status"] for mutant in report["mutations"]} == {
        "policy_default_deny_bypass": "killed",
        "timeout_error_mapping_to_internal": "killed",
    }
    assert report["passed"] is True


def test_checked_in_conformance_observation_meets_the_pr_budget() -> None:
    report = json.loads(OBSERVATION.read_text(encoding="utf-8"))

    assert report["schema_version"] == 1
    assert report["contract_version"] == "1.0"
    assert report["total_duration_seconds"] < report["target_total_seconds"]
    assert all(mutant["status"] == "killed" for mutant in report["mutations"])
    assert report["passed"] is True
