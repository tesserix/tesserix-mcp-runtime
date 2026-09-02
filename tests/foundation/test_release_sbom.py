from __future__ import annotations

import json
from pathlib import Path

import pytest
from release.sbom import bind_python_sbom, verify_image_sbom

WORKSPACE_PACKAGES = (
    "tesserix-mcp-manifest",
    "tesserix-mcp-publisher",
    "tesserix-mcp-runtime",
    "tesserix-mcp-testkit",
)


def _component(name: str, version: str) -> dict[str, str]:
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name}@{version}",
    }


def _write_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def test_python_sbom_binds_release_version_and_proves_locked_dependencies(
    tmp_path: Path,
) -> None:
    artifact_sbom = tmp_path / "python-artifacts.cdx.json"
    raw_lock_sbom = tmp_path / "python-dependencies.raw.cdx.json"
    bound_lock_sbom = tmp_path / "python-dependencies.cdx.json"
    uv_lock = tmp_path / "uv.lock"
    _write_json(
        artifact_sbom,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {
                "component": {
                    "type": "file",
                    "name": "tesserix-mcp-python-distributions",
                    "version": "0.1.0rc1",
                }
            },
            "components": [_component(name, "0.1.0rc1") for name in WORKSPACE_PACKAGES],
        },
    )
    _write_json(
        raw_lock_sbom,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "library", "name": "tesserix-mcp-runtime"}},
            "components": [
                *({"type": "library", "name": name} for name in WORKSPACE_PACKAGES),
                _component("mcp", "2.1.1"),
            ],
        },
    )
    uv_lock.write_text(
        """version = 1

[[package]]
name = "mcp"
version = "2.1.1"

""",
        encoding="utf-8",
    )

    report = bind_python_sbom(
        source=raw_lock_sbom,
        target=bound_lock_sbom,
        artifact_sbom=artifact_sbom,
        uv_lock=uv_lock,
        version="0.1.0rc1",
    )

    bound = json.loads(bound_lock_sbom.read_text(encoding="utf-8"))
    workspace = {
        component["name"]: (component["version"], component["purl"])
        for component in bound["components"]
        if component["name"] in WORKSPACE_PACKAGES
    }
    assert workspace == {
        name: ("0.1.0rc1", f"pkg:pypi/{name}@0.1.0rc1") for name in WORKSPACE_PACKAGES
    }
    assert bound["metadata"]["component"]["version"] == "0.1.0rc1"
    assert report["workspace_packages"] == list(WORKSPACE_PACKAGES)
    assert report["locked_dependency_components"] == 1
    assert all(component["name"] != "tesserix-adk" for component in bound["components"])


def test_python_sbom_rejects_dependency_version_absent_from_lock(tmp_path: Path) -> None:
    artifact_sbom = tmp_path / "artifacts.json"
    lock_sbom = tmp_path / "lock.json"
    uv_lock = tmp_path / "uv.lock"
    _write_json(
        artifact_sbom,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [_component(name, "1.0.0") for name in WORKSPACE_PACKAGES],
        },
    )
    _write_json(
        lock_sbom,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"type": "library", "name": "tesserix-mcp-runtime"}},
            "components": [
                *({"type": "library", "name": name} for name in WORKSPACE_PACKAGES),
                _component("mcp", "9.9.9"),
            ],
        },
    )
    uv_lock.write_text(
        'version = 1\n[[package]]\nname = "mcp"\nversion = "2.1.1"\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"not present in uv\.lock"):
        bind_python_sbom(
            source=lock_sbom,
            target=tmp_path / "bound.json",
            artifact_sbom=artifact_sbom,
            uv_lock=uv_lock,
            version="1.0.0",
        )


def test_image_sbom_proves_base_subset_and_runtime_version(tmp_path: Path) -> None:
    base_sbom = tmp_path / "base.cdx.json"
    image_sbom = tmp_path / "image.cdx.json"
    base_reference = f"ghcr.io/tesserix/base-python-runtime-3.14:20260829@sha256:{'b' * 64}"
    image_reference = f"ghcr.io/tesserix/tesserix-mcp-runtime:0.1.0-rc.1-core@sha256:{'a' * 64}"
    base_component = {
        "type": "library",
        "name": "python",
        "version": "3.14.7",
        "purl": "pkg:generic/python@3.14.7",
    }
    pip_launcher = {
        "type": "application",
        "name": "Simple Launcher",
        "version": "1.1.0.14",
        "properties": [
            {
                "name": "syft:location:0:path",
                "value": "/usr/local/lib/python3.14/site-packages/pip/_vendor/distlib/t32.exe",
            }
        ],
    }
    _write_json(
        base_sbom,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {
                "component": {
                    "type": "container",
                    "name": base_reference,
                    "version": f"sha256:{'b' * 64}",
                }
            },
            "components": [base_component, _component("pip", "26.2.1"), pip_launcher],
        },
    )
    _write_json(
        image_sbom,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {
                "component": {
                    "type": "container",
                    "name": image_reference,
                    "version": f"sha256:{'a' * 64}",
                }
            },
            "components": [base_component, _component("tesserix-mcp-runtime", "0.1.0rc1")],
        },
    )

    report = verify_image_sbom(
        image_sbom=image_sbom,
        base_sbom=base_sbom,
        image=image_reference,
        base_image=base_reference,
        variant="core",
        version="0.1.0rc1",
    )

    assert report["base_components"] == 3
    assert report["image_components"] == 2
    assert report["removed_base_components"] == [
        "application:Simple Launcher@1.1.0.14",
        "pkg:pypi/pip@26.2.1",
    ]
    assert report["runtime_version"] == "0.1.0rc1"
    assert report["variant"] == "core"


def test_image_sbom_rejects_missing_base_component(tmp_path: Path) -> None:
    base_sbom = tmp_path / "base.cdx.json"
    image_sbom = tmp_path / "image.cdx.json"
    base_reference = f"ghcr.io/tesserix/base:1@sha256:{'b' * 64}"
    image_reference = f"ghcr.io/tesserix/runtime:1-core@sha256:{'a' * 64}"
    base_component = _component("base-library", "1.0")
    _write_json(
        base_sbom,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {"component": {"name": base_reference, "version": f"sha256:{'b' * 64}"}},
            "components": [base_component],
        },
    )
    _write_json(
        image_sbom,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {"component": {"name": image_reference, "version": f"sha256:{'a' * 64}"}},
            "components": [_component("tesserix-mcp-runtime", "1.0.0")],
        },
    )

    with pytest.raises(ValueError, match="omits base-image components"):
        verify_image_sbom(
            image_sbom=image_sbom,
            base_sbom=base_sbom,
            image=image_reference,
            base_image=base_reference,
            variant="core",
            version="1.0.0",
        )
