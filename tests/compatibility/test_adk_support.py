from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[2]
SIZE_REPORT = ROOT / "architecture" / "adk-bridge-size-report.json"


def test_public_metadata_keeps_the_private_adk_release_external() -> None:
    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = document["project"]

    assert project["dependencies"] == [
        "httpcore>=1.0.9,<2",
        "httpx>=0.28.1,<1",
        "mcp>=2.1.1,<3",
        "mcp-types>=2.1.1,<3",
        "opentelemetry-api>=1.42.1,<2",
        "PyJWT[crypto]>=2.13,<3",
        "uvicorn>=0.52.4,<1",
    ]
    assert project["optional-dependencies"] == {
        "adk": [],
        "manifest": ["tesserix-mcp-manifest>=0.0.1.dev0,<1"],
        "otel": ["opentelemetry-sdk>=1.42.1,<2"],
        "publisher": ["tesserix-mcp-publisher>=0.0.1.dev0,<1"],
        "testkit": ["tesserix-mcp-testkit>=0.0.1.dev0,<1"],
    }
    assert document["tool"]["hatch"]["metadata"] == {"allow-direct-references": True}
    assert "agent-development-kit" not in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_adk_workflow_verifies_the_downloaded_release_offline() -> None:
    workflow = (ROOT / ".github" / "workflows" / "compatibility.yml").read_text(encoding="utf-8")

    assert '--pattern "$ADK_BUNDLE"' in workflow
    assert '--bundle "$verified_dir/$ADK_BUNDLE"' in workflow
    assert '--with "$PWD/.compatibility/adk-release/$ADK_WHEEL"' in workflow


def test_adk_bridge_size_evidence_compares_opt_in_and_core_profiles() -> None:
    report = json.loads(SIZE_REPORT.read_text(encoding="utf-8"))

    assert report["adk_release"] == {
        "version": "0.53.1",
        "wheel_bytes": 1_136_375,
        "wheel_sha256": "eec6afc695518971f44723e520cf43f0997110d013ce4733f8d6d30ec96b8bdb",
        "attestation_verified": True,
    }
    dependencies = report["dependency_profiles"]
    assert (
        dependencies["adk"]["installed_file_bytes"] - dependencies["core"]["installed_file_bytes"]
        == dependencies["delta"]["installed_file_bytes"]
    )
    images = report["base_images"]
    assert images["core"]["index_digest"] == (
        "sha256:3854f5d9d00705b14077bf6715feb9c3bd6d1ad2e41d5594b3c09c0a74c22add"
    )
    assert images["adk"]["index_digest"] == (
        "sha256:5a6fd1863ed7f37f3929cc596d0ec063c3077c11713cd334f14d1df2b30ef386"
    )
    for architecture in ("amd64", "arm64"):
        assert (
            images["adk"]["platforms"][architecture]["compressed_bytes"]
            - images["core"]["platforms"][architecture]["compressed_bytes"]
            == images["delta"]["platforms"][architecture]["compressed_bytes"]
        )
