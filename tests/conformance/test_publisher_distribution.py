from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[2]
PUBLISHER = ROOT / "packages" / "tesserix-mcp-publisher"


def test_publisher_is_an_opt_in_workspace_distribution() -> None:
    runtime = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    publisher = tomllib.loads((PUBLISHER / "pyproject.toml").read_text(encoding="utf-8"))

    assert runtime["project"]["optional-dependencies"]["publisher"] == [
        "tesserix-mcp-publisher>=0.0.1.dev0,<1"
    ]
    assert runtime["tool"]["uv"]["sources"]["tesserix-mcp-publisher"] == {"workspace": True}
    assert publisher["project"]["name"] == "tesserix-mcp-publisher"
    assert publisher["project"]["requires-python"] == ">=3.12,<3.15"
    assert publisher["project"]["license-files"] == ["LICENSE"]
    assert publisher["project"]["dependencies"] == [
        "tesserix-mcp-manifest>=0.0.1.dev0,<1",
        "tesserix-mcp-runtime>=0.0.1.dev0,<1",
    ]
    assert publisher["project"]["scripts"] == {
        "tesserix-mcp-publish": "tesserix_mcp_publisher.cli:main"
    }
    assert publisher["tool"]["hatch"]["version"]["raw-options"] == {"root": "../.."}
    assert publisher["tool"]["pytest"]["ini_options"] == {
        "addopts": "-q --strict-config --strict-markers --disable-socket --allow-unix-socket",
        "testpaths": ["tests"],
    }
    assert (PUBLISHER / "LICENSE").read_text(encoding="utf-8") == (ROOT / "LICENSE").read_text(
        encoding="utf-8"
    )


def test_quality_workflow_enforces_publisher_package_gates() -> None:
    workflow = (ROOT / ".github" / "workflows" / "quality.yml").read_text(encoding="utf-8")

    assert "packages/tesserix-mcp-publisher/src" in workflow
    assert "packages/tesserix-mcp-publisher/tests" in workflow
    assert "working-directory: packages/tesserix-mcp-publisher" in workflow
    assert "--source=tesserix_mcp_publisher -m pytest" in workflow
    assert "architecture/publisher-public-api.txt" in workflow
    assert "--no-dev --extra publisher" in workflow
