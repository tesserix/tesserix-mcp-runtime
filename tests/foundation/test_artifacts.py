from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def built_artifacts(tmp_path_factory: pytest.TempPathFactory) -> Path:
    destination = tmp_path_factory.mktemp("dist")
    completed = subprocess.run(
        ["uv", "build", "--offline", "--out-dir", str(destination)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    return destination


def test_wheel_and_sdist_carry_version_license_and_typing_metadata(
    built_artifacts: Path,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "architecture" / "check_artifacts.py"),
            str(built_artifacts),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["distribution"] == "tesserix-mcp-runtime"
    assert report["version"] != "0.0.0"
    assert report["wheel_bytes"] > 0
    assert report["sdist_bytes"] > 0


def test_wheel_and_sdist_install_and_import_without_network(
    built_artifacts: Path,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "architecture" / "smoke_install_artifacts.py"),
            "--no-deps",
            "--offline",
            built_artifacts.name,
        ],
        cwd=built_artifacts.parent,
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["wheel"]["version"] == report["sdist"]["version"]
    assert report["wheel"]["typed"] is True
    assert report["sdist"]["typed"] is True
    assert report["wheel"]["dependencies_installed"] is False
    assert report["sdist"]["dependencies_installed"] is False
