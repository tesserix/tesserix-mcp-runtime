from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[2]
TESTKIT = ROOT / "packages" / "tesserix-mcp-testkit"


def test_testkit_is_an_opt_in_workspace_distribution() -> None:
    runtime = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    testkit = tomllib.loads((TESTKIT / "pyproject.toml").read_text(encoding="utf-8"))

    assert runtime["project"]["optional-dependencies"]["testkit"] == [
        "tesserix-mcp-testkit>=0.0.1.dev0,<1"
    ]
    assert runtime["tool"]["uv"]["workspace"] == {
        "members": [
            "packages/tesserix-mcp-manifest",
            "packages/tesserix-mcp-publisher",
            "packages/tesserix-mcp-testkit",
        ]
    }
    assert runtime["tool"]["uv"]["sources"]["tesserix-mcp-testkit"] == {"workspace": True}

    assert testkit["project"]["name"] == "tesserix-mcp-testkit"
    assert testkit["project"]["requires-python"] == ">=3.12,<3.15"
    assert testkit["project"]["license-files"] == ["LICENSE"]
    assert testkit["project"]["dependencies"] == [
        "cryptography>=50,<51",
        "httpx2>=2.12,<3",
        "mcp>=2.1.1,<3",
        "pydantic>=2.13,<3",
        "pytest-socket>=0.8,<1",
        "pytest>=9,<10",
        "tesserix-mcp-runtime>=0.0.1.dev0,<1",
    ]
    assert testkit["project"]["entry-points"]["pytest11"] == {
        "tesserix_mcp_testkit": "tesserix_mcp_testkit.pytest_plugin"
    }
    assert testkit["tool"]["hatch"]["version"]["raw-options"] == {"root": "../.."}
    assert (TESTKIT / "LICENSE").read_text(encoding="utf-8") == (ROOT / "LICENSE").read_text(
        encoding="utf-8"
    )


def test_quality_workflow_enforces_standalone_testkit_branch_coverage() -> None:
    workflow = (ROOT / ".github" / "workflows" / "quality.yml").read_text(encoding="utf-8")

    assert "working-directory: packages/tesserix-mcp-testkit" in workflow
    assert "coverage run --branch \\" in workflow
    assert "--source=tesserix_mcp_testkit -m pytest" in workflow
    assert "coverage report \\" in workflow
    assert "--show-missing --fail-under=90" in workflow


def test_quality_workflow_runs_the_repeatable_evaluation_promotion_gate() -> None:
    workflow = (ROOT / ".github" / "workflows" / "quality.yml").read_text(encoding="utf-8")

    assert "Run evaluation promotion gates" in workflow
    assert "uv run --frozen python benchmarks/measure_evaluation.py" in workflow


def test_package_workflow_proves_offline_install_from_an_isolated_cache() -> None:
    workflow = (ROOT / ".github" / "workflows" / "quality.yml").read_text(encoding="utf-8")

    assert "package_cache=$(mktemp -d)" in workflow
    assert "--no-dev --extra testkit" in workflow
    assert "--no-emit-project --no-emit-workspace" in workflow
    assert 'UV_CACHE_DIR="$package_cache" uv pip install --offline' in workflow
