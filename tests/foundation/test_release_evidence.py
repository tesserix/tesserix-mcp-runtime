from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from release.evidence import ImageEvidence, write_release_evidence
from release.identity import ReleaseIdentity

DISTRIBUTIONS = (
    "tesserix_mcp_manifest",
    "tesserix_mcp_publisher",
    "tesserix_mcp_runtime",
    "tesserix_mcp_testkit",
)
EVIDENCE_NAMES = {
    f"{variant}{suffix}"
    for variant in ("core", "adk")
    for suffix in (
        "-base.cdx.json",
        "-github-sbom.sigstore.json",
        "-provenance.sigstore.json",
        "-runtime.json",
        "-sbom-verification.json",
        "-sbom.sigstore.json",
        "-signature.sigstore.json",
        "-trivy-policy.json",
        "-trivy.json",
        ".cdx.json",
        ".spdx.json",
    )
} | {
    "python-artifacts.cdx.json",
    "python-artifacts.spdx.json",
    "python-dependencies.cdx.json",
    "python-provenance.sigstore.json",
    "python-sbom-verification.json",
    "python-sbom.sigstore.json",
    "release-notes.md",
    "releasing.md",
    "support-matrix.json",
}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_required_assets(root: Path, version: str) -> set[str]:
    names = EVIDENCE_NAMES | {
        name
        for distribution in DISTRIBUTIONS
        for name in (
            f"{distribution}-{version}-py3-none-any.whl",
            f"{distribution}-{version}.tar.gz",
        )
    }
    for name in names:
        (root / name).write_bytes(name.encode())
    return names


def test_release_evidence_binds_artifacts_images_source_and_workflow(
    tmp_path: Path,
) -> None:
    secret_canary = b"Bearer must-not-enter-the-release-manifest"
    identity = ReleaseIdentity.parse("v0.1.0-rc.1")
    expected_names = _write_required_assets(tmp_path, identity.version)
    wheel = tmp_path / f"tesserix_mcp_runtime-{identity.version}-py3-none-any.whl"
    sbom = tmp_path / "python-artifacts.cdx.json"
    wheel.write_bytes(secret_canary)
    sbom.write_text('{"bomFormat":"CycloneDX"}\n', encoding="utf-8")

    document = write_release_evidence(
        tmp_path,
        identity=identity,
        images=(
            ImageEvidence(
                variant="adk",
                reference=(
                    f"ghcr.io/tesserix/tesserix-mcp-runtime:0.1.0-rc.1-adk@sha256:{'b' * 64}"
                ),
            ),
            ImageEvidence(
                variant="core",
                reference=(
                    f"ghcr.io/tesserix/tesserix-mcp-runtime:0.1.0-rc.1-core@sha256:{'a' * 64}"
                ),
            ),
        ),
        repository="tesserix/tesserix-mcp-runtime",
        source_sha="1" * 40,
        workflow_ref=(
            "tesserix/tesserix-mcp-runtime/.github/workflows/release.yml@refs/tags/v0.1.0-rc.1"
        ),
    )

    artifact_values = cast(list[dict[str, object]], document["artifacts"])
    artifacts = {cast(str, artifact["name"]): artifact for artifact in artifact_values}
    assert set(artifacts) == expected_names
    assert artifacts[sbom.name] == {
        "name": sbom.name,
        "sha256": _sha256(sbom.read_bytes()),
        "size_bytes": sbom.stat().st_size,
    }
    assert artifacts[wheel.name] == {
        "name": wheel.name,
        "sha256": _sha256(secret_canary),
        "size_bytes": len(secret_canary),
    }
    assert document | {"artifacts": []} == {
        "artifacts": [],
        "images": [
            {
                "digest": f"sha256:{'b' * 64}",
                "reference": (
                    f"ghcr.io/tesserix/tesserix-mcp-runtime:0.1.0-rc.1-adk@sha256:{'b' * 64}"
                ),
                "variant": "adk",
            },
            {
                "digest": f"sha256:{'a' * 64}",
                "reference": (
                    f"ghcr.io/tesserix/tesserix-mcp-runtime:0.1.0-rc.1-core@sha256:{'a' * 64}"
                ),
                "variant": "core",
            },
        ],
        "prerelease": True,
        "repository": "tesserix/tesserix-mcp-runtime",
        "schema_version": 1,
        "source_sha": "1" * 40,
        "tag": "v0.1.0-rc.1",
        "version": "0.1.0rc1",
        "workflow_ref": (
            "tesserix/tesserix-mcp-runtime/.github/workflows/release.yml@refs/tags/v0.1.0-rc.1"
        ),
    }
    encoded = (tmp_path / "release-manifest.json").read_text(encoding="utf-8")
    assert json.loads(encoded) == document
    assert secret_canary.decode() not in encoded
    checksums = (tmp_path / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert checksums == sorted(checksums)
    assert any(line.endswith("  release-manifest.json") for line in checksums)
    assert not any(line.endswith("  SHA256SUMS") for line in checksums)


def test_release_evidence_rejects_mutable_or_mismatched_image_identity(tmp_path: Path) -> None:
    _write_required_assets(tmp_path, "1.2.3")

    with pytest.raises(ValueError, match="image reference"):
        write_release_evidence(
            tmp_path,
            identity=ReleaseIdentity.parse("v1.2.3"),
            images=(
                ImageEvidence(
                    variant="adk",
                    reference=(
                        f"ghcr.io/tesserix/tesserix-mcp-runtime:1.2.3-adk@sha256:{'b' * 64}"
                    ),
                ),
                ImageEvidence(
                    variant="core",
                    reference=(f"ghcr.io/tesserix/tesserix-mcp-runtime:latest@sha256:{'a' * 64}"),
                ),
            ),
            repository="tesserix/tesserix-mcp-runtime",
            source_sha="1" * 40,
            workflow_ref=(
                "tesserix/tesserix-mcp-runtime/.github/workflows/release.yml@refs/tags/v1.2.3"
            ),
        )


def test_release_evidence_requires_core_and_adk_images(tmp_path: Path) -> None:
    _write_required_assets(tmp_path, "1.2.3")

    with pytest.raises(ValueError, match="exactly core and adk"):
        write_release_evidence(
            tmp_path,
            identity=ReleaseIdentity.parse("v1.2.3"),
            images=(
                ImageEvidence(
                    variant="core",
                    reference=(
                        f"ghcr.io/tesserix/tesserix-mcp-runtime:1.2.3-core@sha256:{'a' * 64}"
                    ),
                ),
            ),
            repository="tesserix/tesserix-mcp-runtime",
            source_sha="1" * 40,
            workflow_ref=(
                "tesserix/tesserix-mcp-runtime/.github/workflows/release.yml@refs/tags/v1.2.3"
            ),
        )


def test_release_evidence_rejects_an_incomplete_asset_inventory(tmp_path: Path) -> None:
    (tmp_path / "artifact.whl").write_bytes(b"artifact")

    with pytest.raises(ValueError, match="release asset inventory"):
        write_release_evidence(
            tmp_path,
            identity=ReleaseIdentity.parse("v1.2.3"),
            images=(
                ImageEvidence(
                    variant="core",
                    reference=(
                        f"ghcr.io/tesserix/tesserix-mcp-runtime:1.2.3-core@sha256:{'a' * 64}"
                    ),
                ),
                ImageEvidence(
                    variant="adk",
                    reference=(
                        f"ghcr.io/tesserix/tesserix-mcp-runtime:1.2.3-adk@sha256:{'b' * 64}"
                    ),
                ),
            ),
            repository="tesserix/tesserix-mcp-runtime",
            source_sha="1" * 40,
            workflow_ref=(
                "tesserix/tesserix-mcp-runtime/.github/workflows/release.yml@refs/tags/v1.2.3"
            ),
        )


def test_release_evidence_rejects_an_unexpected_asset(tmp_path: Path) -> None:
    _write_required_assets(tmp_path, "1.2.3")
    (tmp_path / "unreviewed.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="release asset inventory"):
        write_release_evidence(
            tmp_path,
            identity=ReleaseIdentity.parse("v1.2.3"),
            images=(
                ImageEvidence(
                    variant="core",
                    reference=(
                        f"ghcr.io/tesserix/tesserix-mcp-runtime:1.2.3-core@sha256:{'a' * 64}"
                    ),
                ),
                ImageEvidence(
                    variant="adk",
                    reference=(
                        f"ghcr.io/tesserix/tesserix-mcp-runtime:1.2.3-adk@sha256:{'b' * 64}"
                    ),
                ),
            ),
            repository="tesserix/tesserix-mcp-runtime",
            source_sha="1" * 40,
            workflow_ref=(
                "tesserix/tesserix-mcp-runtime/.github/workflows/release.yml@refs/tags/v1.2.3"
            ),
        )
