from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
CHECKER = ROOT / "architecture" / "check_dependencies.py"
REPORT = ROOT / "architecture" / "dependency-report.json"


def run_checker(
    report: Path,
    *,
    wheel: Path | None = None,
    site_packages: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(CHECKER), "--report", str(report)]
    if wheel is not None:
        command.extend(["--wheel", str(wheel)])
    if site_packages is not None:
        command.extend(["--site-packages", str(site_packages)])
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )


def test_core_dependency_report_matches_frozen_resolution() -> None:
    completed = run_checker(REPORT)

    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert result["passed"] is True
    assert result["violations"] == []
    assert result["profiles"]["core"]["declared_dependencies"] == [
        "PyJWT[crypto]>=2.13,<3",
        "httpcore>=1.0.9,<2",
        "httpx>=0.28.1,<1",
        "mcp-types>=2.1.1,<3",
        "mcp>=2.1.1,<3",
        "opentelemetry-api>=1.44,<2",
        "uvicorn>=0.52.4,<1",
    ]
    assert result["profiles"]["core"]["distribution_count"] == 34
    assert result["profiles"]["core"]["wheel_bytes"] is None
    policy = json.loads(REPORT.read_text(encoding="utf-8"))
    assert policy["profiles"]["core"]["max_wheel_bytes"] == 98_304
    assert result["profiles"]["adk"]["declared_dependencies"][-2].startswith(
        "tesserix-adk @ https://github.com/tesserix/agent-development-kit/releases/"
    )
    assert result["profiles"]["adk"]["distribution_count"] == 35
    assert result["profiles"]["otel"]["distribution_count"] == 36
    assert result["profiles"]["otel"]["declared_dependencies"][-2:] == [
        "opentelemetry-sdk>=1.44,<2",
        "uvicorn>=0.52.4,<1",
    ]
    assert result["profiles"]["testkit"]["declared_dependencies"][-2:] == [
        "tesserix-mcp-testkit>=0.0.1.dev0,<1",
        "uvicorn>=0.52.4,<1",
    ]
    assert result["profiles"]["testkit"]["distribution_count"] == 42
    assert "pytest==9.0.3" in result["profiles"]["testkit"]["resolved_dependencies"]
    assert (
        "tesserix-mcp-testkit (workspace)" in result["profiles"]["testkit"]["resolved_dependencies"]
    )


def test_adk_is_forbidden_outside_its_explicit_dependency_profile(tmp_path: Path) -> None:
    policy = json.loads(REPORT.read_text(encoding="utf-8"))
    policy["profiles"]["adk"]["allowed_forbidden_dependencies"] = []
    drifted_report = tmp_path / "dependency-report.json"
    drifted_report.write_text(json.dumps(policy), encoding="utf-8")

    completed = run_checker(drifted_report)

    assert completed.returncode == 1
    result = json.loads(completed.stdout)
    assert {
        "dependency": "tesserix-adk",
        "profile": "adk",
        "reason": "forbidden dependency resolved",
    } in result["violations"]


def test_dependency_report_rejects_a_forbidden_resolved_package(
    tmp_path: Path,
) -> None:
    policy = json.loads(REPORT.read_text(encoding="utf-8"))
    policy["forbidden_dependencies"].append("mcp")
    drifted_report = tmp_path / "dependency-report.json"
    drifted_report.write_text(json.dumps(policy), encoding="utf-8")

    completed = run_checker(drifted_report)

    assert completed.returncode == 1
    result = json.loads(completed.stdout)
    assert {
        "dependency": "mcp",
        "profile": "core",
        "reason": "forbidden dependency resolved",
    } in result["violations"]


def test_dependency_report_enforces_wheel_and_installed_size_budgets(
    tmp_path: Path,
) -> None:
    policy = json.loads(REPORT.read_text(encoding="utf-8"))
    policy["profiles"]["core"]["max_wheel_bytes"] = 1
    policy["profiles"]["core"]["max_installed_bytes"] = 2
    constrained_report = tmp_path / "dependency-report.json"
    constrained_report.write_text(json.dumps(policy), encoding="utf-8")
    wheel = tmp_path / "runtime.whl"
    wheel.write_bytes(b"xx")
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    (site_packages / "runtime.py").write_bytes(b"xxx")

    completed = run_checker(
        constrained_report,
        wheel=wheel,
        site_packages=site_packages,
    )

    assert completed.returncode == 1
    result = json.loads(completed.stdout)
    assert {
        "actual_bytes": 2,
        "maximum_bytes": 1,
        "profile": "core",
        "reason": "wheel size budget exceeded",
    } in result["violations"]
    assert {
        "actual_bytes": 3,
        "maximum_bytes": 2,
        "profile": "core",
        "reason": "installed size budget exceeded",
    } in result["violations"]
