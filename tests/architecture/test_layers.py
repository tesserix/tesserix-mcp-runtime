from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
CHECKER = ROOT / "architecture" / "check_layers.py"


def run_checker(source: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), str(source)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )


def test_current_source_tree_respects_dependency_boundaries() -> None:
    completed = run_checker(ROOT / "src")

    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {"passed": True, "violations": []}


@pytest.mark.parametrize(
    "forbidden_import",
    [
        "httpx",
        "kubernetes",
        "mcp",
        "tesserix_mcp_runtime.adapters",
    ],
)
def test_reports_an_adapter_dependency_imported_by_core(
    tmp_path: Path,
    forbidden_import: str,
) -> None:
    source = tmp_path / "src"
    shutil.copytree(ROOT / "src", source)
    contracts = source / "tesserix_mcp_runtime" / "contracts.py"
    contracts.write_text(
        contracts.read_text(encoding="utf-8") + f"\nimport {forbidden_import}\n",
        encoding="utf-8",
    )

    completed = run_checker(source)

    assert completed.returncode == 1
    report = json.loads(completed.stdout)
    assert report == {
        "passed": False,
        "violations": [
            {
                "imported": forbidden_import,
                "module": "tesserix_mcp_runtime.contracts",
                "reason": "core cannot import adapter dependencies",
            }
        ],
    }
