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
        ["uv", "build", "--all-packages", "--offline", "--out-dir", str(destination)],
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
    assert report["version"] != "0.0.0"
    assert set(report["distributions"]) == {
        "tesserix-mcp-runtime",
        "tesserix-mcp-manifest",
        "tesserix-mcp-publisher",
        "tesserix-mcp-testkit",
    }
    for distribution in report["distributions"].values():
        assert distribution["version"] == report["version"]
        assert distribution["wheel_bytes"] > 0
        assert distribution["sdist_bytes"] > 0


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
    assert set(report) == {
        "tesserix-mcp-manifest",
        "tesserix-mcp-publisher",
        "tesserix-mcp-runtime",
        "tesserix-mcp-testkit",
    }
    for distribution in report.values():
        assert distribution["wheel"]["version"] == distribution["sdist"]["version"]
        assert distribution["wheel"]["typed"] is True
        assert distribution["sdist"]["typed"] is True
        assert distribution["wheel"]["dependencies_installed"] is False
        assert distribution["sdist"]["dependencies_installed"] is False
