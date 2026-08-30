from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from tesserix_mcp_testkit import CONFORMANCE_CONTRACT_VERSION

ROOT = Path(__file__).parents[1]
TARGET_TOTAL_SECONDS = 10.0
_COUNT = {name: re.compile(rf"(\d+) {name}") for name in ("passed", "skipped", "deselected")}
_DURATION = re.compile(r"in ([0-9]+(?:\.[0-9]+)?)s(?:\n|$)")
_OFFLINE_ADDITIONAL_OPTIONS = (
    "addopts=--strict-config --strict-markers --disable-socket --allow-unix-socket"
)


@dataclass(frozen=True, slots=True)
class _Probe:
    name: str
    test_path: str
    selection: str | None = None
    working_directory: Path = ROOT


class _ProbeResult(TypedDict):
    name: str
    passed: int
    skipped: int
    deselected: int
    duration_seconds: float


class _MutationResult(TypedDict):
    name: str
    duration_seconds: float
    status: str


def _pytest_command(probe: _Probe) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-o",
        _OFFLINE_ADDITIONAL_OPTIONS,
        probe.test_path,
    ]
    if probe.selection is not None:
        command.extend(["-k", probe.selection])
    return command


def _run(probe: _Probe) -> _ProbeResult:
    completed = subprocess.run(
        _pytest_command(probe),
        cwd=probe.working_directory,
        capture_output=True,
        check=False,
        text=True,
        timeout=TARGET_TOTAL_SECONDS,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{probe.name} failed: {completed.stdout}{completed.stderr}")
    duration_match = _DURATION.search(completed.stdout)
    if duration_match is None:
        raise RuntimeError(f"{probe.name} did not report a duration")
    return {
        "name": probe.name,
        "passed": _count(completed.stdout, "passed"),
        "skipped": _count(completed.stdout, "skipped"),
        "deselected": _count(completed.stdout, "deselected"),
        "duration_seconds": float(duration_match.group(1)),
    }


def _count(output: str, name: str) -> int:
    match = _COUNT[name].search(output)
    return 0 if match is None else int(match.group(1))


def main() -> int:
    lanes = [
        _run(
            _Probe(
                "core",
                "tests/conformance/test_runtime_contract.py",
                "core_runtime_conforms",
            )
        ),
        _run(_Probe("sdk", "tests/conformance/test_sdk_contract.py")),
        _run(
            _Probe(
                "external",
                "tests",
                working_directory=ROOT / "examples" / "conformance-server",
            )
        ),
    ]
    mutation_probes = (
        _Probe(
            "timeout_error_mapping_to_internal",
            "tests/conformance/test_runtime_contract.py",
            "kills_timeout_error_mapping_mutation",
        ),
        _Probe(
            "policy_default_deny_bypass",
            "tests/conformance/test_runtime_contract.py",
            "kills_policy_default_deny_mutation",
        ),
    )
    mutations: list[_MutationResult] = []
    for probe in mutation_probes:
        result = _run(probe)
        mutations.append(
            {
                "name": probe.name,
                "duration_seconds": result["duration_seconds"],
                "status": "killed",
            }
        )
    total_duration = sum(lane["duration_seconds"] for lane in lanes)
    report = {
        "schema_version": 1,
        "contract_version": CONFORMANCE_CONTRACT_VERSION,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "target_total_seconds": TARGET_TOTAL_SECONDS,
        "total_duration_seconds": total_duration,
        "lanes": lanes,
        "mutations": mutations,
        "passed": total_duration < TARGET_TOTAL_SECONDS,
    }
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
