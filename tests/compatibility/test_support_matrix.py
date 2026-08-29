from __future__ import annotations

import json
from pathlib import Path
import tomllib


ROOT = Path(__file__).parents[2]


def test_support_matrix_names_every_evidence_backed_lane() -> None:
    matrix = json.loads(
        (ROOT / "compatibility" / "support-matrix.json").read_text(encoding="utf-8")
    )

    assert matrix["as_of"] == "2026-08-30"
    assert matrix["runtime_python"] == "3.14"
    assert matrix["library_python"] == ["3.12", "3.13", "3.14"]
    assert matrix["server_sdk"] == {"constraint": ">=2.1.1,<3", "locked": "2.1.1"}
    assert matrix["client_lanes"] == [
        {
            "name": "devai",
            "sdk": "1.28.1",
            "support": "required",
        },
        {
            "name": "maintained-v1",
            "sdk": "1.29.1",
            "support": "required",
        },
        {
            "name": "current-v2",
            "sdk": "2.1.1",
            "support": "required",
        },
    ]
    assert matrix["protocol_revisions"] == {
        "legacy_latest": "2025-11-25",
        "modern": "2026-07-28",
    }
    assert matrix["adk"] == {
        "release": "0.53.1",
        "locked_mcp_sdk": "2.1.0",
        "bridge_status": "planned",
    }
    assert matrix["nonexistent_versions"] == ["1.34", "1.34.0"]


def test_project_metadata_excludes_unsupported_sdk_majors() -> None:
    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = document["project"]

    assert project["requires-python"] == ">=3.12,<3.15"
    assert project["dependencies"] == ["mcp>=2.1.1,<3"]


def locked_mcp_version(path: Path) -> str:
    lock = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = [package for package in lock["package"] if package["name"] == "mcp"]
    assert len(packages) == 1
    package = packages[0]
    assert package["sdist"]["hash"].startswith("sha256:")
    assert all(wheel["hash"].startswith("sha256:") for wheel in package["wheels"])
    return str(package["version"])


def test_every_compatibility_environment_locks_the_declared_sdk() -> None:
    assert locked_mcp_version(ROOT / "uv.lock") == "2.1.1"
    expected = {
        "server.py.lock": "2.1.1",
        "client_1_28.py.lock": "1.28.1",
        "client_1_29.py.lock": "1.29.1",
        "client_2_1.py.lock": "2.1.1",
    }

    actual = {
        filename: locked_mcp_version(ROOT / "compatibility" / filename)
        for filename in expected
    }

    assert actual == expected
