from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_support_matrix_names_every_evidence_backed_lane() -> None:
    matrix = json.loads(
        (ROOT / "compatibility" / "support-matrix.json").read_text(encoding="utf-8")
    )

    assert matrix["as_of"] == "2026-08-30"
    assert matrix["runtime_python"] == "3.14"
    assert matrix["library_python"] == ["3.12", "3.13", "3.14"]
    assert matrix["server_sdk"] == {"constraint": ">=2.1.1,<3", "locked": "2.1.1"}
    assert matrix["server_fixture"] == {
        "implementation": "tesserix-mcp-runtime",
        "network": "loopback",
        "path": "/mcp",
        "transport": "streamable-http",
    }
    assert matrix["inspector"] == {
        "mode": "cli",
        "support": "required",
        "version": "2.4.0",
    }
    assert matrix["gateway_proxy"] == {
        "client_sdk": "2.1.1",
        "path": "/gateway/runtime/mcp",
        "rewritten_path": "/mcp",
    }
    assert matrix["verified_operations"] == [
        "initialize",
        "list_tools",
        "paginate_tools",
        "call_tool",
        "cancel_work",
        "close",
    ]
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
        "bridge_status": "implemented",
    }
    assert matrix["nonexistent_versions"] == ["1.34", "1.34.0"]


def test_project_metadata_excludes_unsupported_sdk_majors() -> None:
    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = document["project"]

    assert project["requires-python"] == ">=3.12,<3.15"
    assert project["dependencies"] == [
        "httpcore>=1.0.9,<2",
        "httpx>=0.28.1,<1",
        "mcp>=2.1.1,<3",
        "mcp-types>=2.1.1,<3",
        "opentelemetry-api>=1.44,<2",
        "PyJWT[crypto]>=2.13,<3",
        "uvicorn>=0.52.4,<1",
    ]


def test_compatibility_server_uses_the_runtime_transport() -> None:
    source = (ROOT / "compatibility" / "server.py").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "compatibility.yml").read_text(encoding="utf-8")
    matrix_runner = (ROOT / "compatibility" / "run_matrix.py").read_text(encoding="utf-8")
    inspector_runner = (ROOT / "compatibility" / "run_inspector.py").read_text(encoding="utf-8")

    assert "StreamableHTTPTransport" in source
    assert "Application(" in source
    assert "MCPServer" not in source
    assert "CancellationProbeDefinition" in source
    assert not (ROOT / "compatibility" / "server.py.lock").exists()
    assert "uv lock --check --script compatibility/server.py" not in workflow
    assert {"paginate_tools", "cancel_work"} <= set(matrix_runner.split('"'))
    assert {"paginate_tools", "cancel_work"} <= set(inspector_runner.split('"'))
    assert "@modelcontextprotocol/inspector@{INSPECTOR_VERSION}" in inspector_runner


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
        "client_1_28.py.lock": "1.28.1",
        "client_1_29.py.lock": "1.29.1",
        "client_2_1.py.lock": "2.1.1",
    }

    actual = {
        filename: locked_mcp_version(ROOT / "compatibility" / filename) for filename in expected
    }

    assert actual == expected
