from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import tesserix_mcp_runtime

ROOT = Path(__file__).parents[1]
CHECKER = ROOT / "architecture" / "check_public_api.py"
SNAPSHOT = ROOT / "architecture" / "public-api.txt"


def run_snapshot_check(snapshot: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), str(snapshot)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )


def test_public_api_exports_only_the_stable_contract_surface() -> None:
    assert set(tesserix_mcp_runtime.__all__) == {
        "Authorizer",
        "CallContext",
        "Clock",
        "CredentialProvider",
        "JsonValue",
        "Lifecycle",
        "Telemetry",
        "Tool",
        "__version__",
    }
    for name in tesserix_mcp_runtime.__all__:
        assert getattr(tesserix_mcp_runtime, name) is not None


def test_checked_in_public_api_snapshot_matches_exports() -> None:
    completed = run_snapshot_check(SNAPSHOT)

    assert completed.returncode == 0
    assert completed.stdout == "Public API snapshot matches (9 exports).\n"
    assert completed.stderr == ""


def test_public_api_snapshot_reports_owner_drift(tmp_path: Path) -> None:
    drifted_snapshot = tmp_path / "public-api.txt"
    drifted_snapshot.write_text(
        SNAPSHOT.read_text(encoding="utf-8").replace(
            "Tool = tesserix_mcp_runtime.contracts.Tool",
            "Tool = tesserix_mcp_runtime.adapters.Tool",
        ),
        encoding="utf-8",
    )

    completed = run_snapshot_check(drifted_snapshot)

    assert completed.returncode == 1
    assert "-Tool = tesserix_mcp_runtime.adapters.Tool" in completed.stderr
    assert "+Tool = tesserix_mcp_runtime.contracts.Tool" in completed.stderr
