from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).parents[2]
CHECKER = ROOT / "benchmarks" / "check_envelope.py"


def run_checker(
    tmp_path: Path, observed: dict[str, object]
) -> subprocess.CompletedProcess[str]:
    results_path = tmp_path / "observed.json"
    results_path.write_text(json.dumps({"observed": observed}), encoding="utf-8")
    return run_raw_checker(results_path)


def run_raw_checker(results_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), str(results_path)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )


@pytest.mark.parametrize(
    ("p99_milliseconds", "expected_code", "expected_passed"),
    [(15.0, 0, True), (15.1, 1, False)],
    ids=["at-target", "above-maximum"],
)
def test_compares_observations_with_the_committed_envelope(
    tmp_path: Path,
    p99_milliseconds: float,
    expected_code: int,
    expected_passed: bool,
) -> None:
    completed = run_checker(
        tmp_path,
        {
            "sustained_calls_per_second": 50,
            "burst_calls_per_second": 200,
            "supported_request_bytes": 65_536,
            "supported_response_bytes": 524_288,
            "runtime_added_p99_milliseconds": p99_milliseconds,
            "startup_seconds": 2,
            "idle_rss_mebibytes": 128,
            "monthly_invocation_availability_percent": 99.9,
        },
    )

    assert completed.returncode == expected_code
    report = json.loads(completed.stdout)
    assert report["passed"] is expected_passed
    checks = {check["metric"]: check for check in report["checks"]}
    assert checks["runtime_added_p99_milliseconds"]["passed"] is expected_passed


def test_rejects_an_incomplete_measurement_document(tmp_path: Path) -> None:
    completed = run_checker(tmp_path, {"sustained_calls_per_second": 50})

    assert completed.returncode == 2
    assert completed.stdout == ""
    error = json.loads(completed.stderr)
    assert error == {
        "code": "invalid_measurements",
        "message": "missing observation: burst_calls_per_second",
    }


def test_rejects_a_non_numeric_observation(tmp_path: Path) -> None:
    completed = run_checker(
        tmp_path,
        {
            "sustained_calls_per_second": 50,
            "burst_calls_per_second": 200,
            "supported_request_bytes": 65_536,
            "supported_response_bytes": 524_288,
            "runtime_added_p99_milliseconds": 15,
            "startup_seconds": "two",
            "idle_rss_mebibytes": 128,
            "monthly_invocation_availability_percent": 99.9,
        },
    )

    assert completed.returncode == 2
    error = json.loads(completed.stderr)
    assert error == {
        "code": "invalid_measurements",
        "message": "observation startup_seconds must be a finite number",
    }


def test_rejects_malformed_json_without_a_traceback(tmp_path: Path) -> None:
    results_path = tmp_path / "observed.json"
    results_path.write_text("{", encoding="utf-8")

    completed = run_raw_checker(results_path)

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert json.loads(completed.stderr) == {
        "code": "invalid_measurements",
        "message": "measurement document is not valid JSON",
    }
    assert "Traceback" not in completed.stderr


def test_rejects_a_document_without_an_observed_object(tmp_path: Path) -> None:
    results_path = tmp_path / "observed.json"
    results_path.write_text(json.dumps({"measurements": {}}), encoding="utf-8")

    completed = run_raw_checker(results_path)

    assert completed.returncode == 2
    assert json.loads(completed.stderr) == {
        "code": "invalid_measurements",
        "message": "measurement document requires an observed object",
    }
    assert "Traceback" not in completed.stderr
