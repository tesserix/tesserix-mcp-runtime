from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[2]
MANIFEST = ROOT / "packages" / "tesserix-mcp-manifest"


def test_manifest_compiler_is_an_opt_in_workspace_distribution() -> None:
    runtime = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    manifest = tomllib.loads((MANIFEST / "pyproject.toml").read_text(encoding="utf-8"))

    assert runtime["project"]["optional-dependencies"]["manifest"] == [
        "tesserix-mcp-manifest>=0.0.1.dev0,<1"
    ]
    assert runtime["tool"]["uv"]["sources"]["tesserix-mcp-manifest"] == {"workspace": True}
    assert manifest["project"]["name"] == "tesserix-mcp-manifest"
    assert manifest["project"]["requires-python"] == ">=3.12,<3.15"
    assert manifest["project"]["license-files"] == ["LICENSE"]
    assert manifest["project"]["dependencies"] == [
        "pydantic>=2.13,<3",
        "tesserix-mcp-runtime>=0.0.1.dev0,<1",
    ]
    assert manifest["tool"]["hatch"]["version"]["raw-options"] == {"root": "../.."}
    assert manifest["tool"]["pytest"]["ini_options"] == {
        "addopts": "-q --strict-config --strict-markers --disable-socket --allow-unix-socket",
        "testpaths": ["tests"],
    }
    assert (MANIFEST / "LICENSE").read_text(encoding="utf-8") == (ROOT / "LICENSE").read_text(
        encoding="utf-8"
    )


def test_quality_workflow_enforces_manifest_package_gates() -> None:
    workflow = (ROOT / ".github" / "workflows" / "quality.yml").read_text(encoding="utf-8")

    assert "packages/tesserix-mcp-manifest/src" in workflow
    assert "packages/tesserix-mcp-manifest/tests" in workflow
    assert "working-directory: packages/tesserix-mcp-manifest" in workflow
    assert "--source=tesserix_mcp_manifest -m pytest" in workflow
    assert "architecture/manifest-public-api.txt" in workflow
    assert "uv build --all-packages --clear --offline --no-create-gitignore" in workflow
