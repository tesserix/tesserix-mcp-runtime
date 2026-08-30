from __future__ import annotations

import shlex
import tomllib
from pathlib import Path
from typing import Any, TypeGuard

ROOT = Path(__file__).parents[2]


def project_document() -> dict[str, Any]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def is_object_dict(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def is_table(value: object) -> TypeGuard[dict[str, object]]:
    return is_object_dict(value) and all(isinstance(key, str) for key in value)


def table(value: object) -> dict[str, object]:
    assert is_table(value)
    return value


def is_object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def is_string_list(value: object) -> TypeGuard[list[str]]:
    return is_object_list(value) and all(isinstance(item, str) for item in value)


def test_project_declares_the_hermetic_quality_policy() -> None:
    document = project_document()
    project = table(document["project"])
    assert project["dynamic"] == ["version"]
    assert "version" not in project
    assert project["license-files"] == ["LICENSE"]
    assert project["scripts"] == {"tesserix-mcp-runtime": "tesserix_mcp_runtime.__main__:main"}

    build_system = table(document["build-system"])
    assert build_system["requires"] == [
        "hatchling==1.32.0",
        "hatch-vcs==0.5.0",
    ]

    dependency_groups = table(document["dependency-groups"])
    development_dependencies = dependency_groups["dev"]
    assert is_string_list(development_dependencies)
    assert set(development_dependencies) == {
        "hypothesis==6.165.10",
        "import-linter==2.14",
        "jsonschema==4.26.0",
        "mypy==2.3.1",
        "opentelemetry-sdk==1.44.0",
        "pip-audit==2.10.1",
        "pyright==1.1.411",
        "pytest-asyncio>=1,<2",
        "pytest==9.0.3",
        "pytest-cov==7.1.0",
        "pytest-socket==0.8.1",
        "ruff==0.16.5",
        "starlette==1.6.0",
        "tesserix-mcp-manifest",
        "tesserix-mcp-publisher",
        "tesserix-mcp-testkit",
        "twine==7.0.0",
        "types-jsonschema==4.26.0.20260518",
        "types-pyyaml>=6.0.12,<7",
        "pyyaml>=6.0.3,<7",
    }

    tool = table(document["tool"])
    assert tool["uv"] == {
        "required-version": ">=0.12,<0.13",
        "default-groups": ["dev"],
        "sources": {
            "tesserix-mcp-manifest": {"workspace": True},
            "tesserix-mcp-publisher": {"workspace": True},
            "tesserix-mcp-testkit": {"workspace": True},
        },
        "workspace": {
            "members": [
                "packages/tesserix-mcp-manifest",
                "packages/tesserix-mcp-publisher",
                "packages/tesserix-mcp-testkit",
            ]
        },
    }
    assert tool["mypy"] == {
        "python_version": "3.12",
        "strict": True,
        "warn_unreachable": True,
        "disallow_any_unimported": True,
        "files": ["src", "tests"],
    }
    assert tool["pyright"] == {
        "include": ["src", "tests"],
        "pythonVersion": "3.12",
        "typeCheckingMode": "strict",
    }

    pytest_options = table(table(tool["pytest"])["ini_options"])
    addopts_value = pytest_options["addopts"]
    assert isinstance(addopts_value, str)
    addopts = set(shlex.split(addopts_value))
    assert {
        "--allow-unix-socket",
        "--cov",
        "--cov-report=term-missing",
        "--disable-socket",
        "--strict-config",
        "--strict-markers",
        "-q",
        "-p",
        "no:tesserix_mcp_testkit",
    } <= addopts
    assert pytest_options["testpaths"] == ["tests"]
    assert pytest_options["xfail_strict"] is True

    coverage = table(tool["coverage"])
    assert coverage["run"] == {
        "branch": True,
        "source": ["src/tesserix_mcp_runtime"],
    }
    assert coverage["report"] == {
        "fail_under": 90,
        "show_missing": True,
    }
