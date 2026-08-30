from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from release.identity import ReleaseIdentity

_ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IMAGE = re.compile(
    r"(?P<name>ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+):(?P<tag>[A-Za-z0-9._-]+)@(?P<digest>sha256:[0-9a-f]{64})\Z"
)
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SOURCE_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_ARTIFACT_BYTES = 536_870_912
_MAX_ARTIFACTS = 64
_OUTPUT_NAMES = frozenset({"release-manifest.json", "SHA256SUMS"})
_DISTRIBUTIONS = (
    "tesserix_mcp_manifest",
    "tesserix_mcp_publisher",
    "tesserix_mcp_runtime",
    "tesserix_mcp_testkit",
)
_REQUIRED_EVIDENCE_NAMES = frozenset(
    {
        "adk-base.cdx.json",
        "adk-github-sbom.sigstore.json",
        "adk-provenance.sigstore.json",
        "adk-runtime.json",
        "adk-sbom-verification.json",
        "adk-sbom.sigstore.json",
        "adk-signature.sigstore.json",
        "adk-trivy-policy.json",
        "adk-trivy.json",
        "adk.cdx.json",
        "adk.spdx.json",
        "core-base.cdx.json",
        "core-github-sbom.sigstore.json",
        "core-provenance.sigstore.json",
        "core-runtime.json",
        "core-sbom-verification.json",
        "core-sbom.sigstore.json",
        "core-signature.sigstore.json",
        "core-trivy-policy.json",
        "core-trivy.json",
        "core.cdx.json",
        "core.spdx.json",
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
)


class ArtifactEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=256)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1, le=_MAX_ARTIFACT_BYTES)


class ImageEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    variant: Literal["core", "adk"]
    reference: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_reference(self) -> ImageEvidence:
        if _IMAGE.fullmatch(self.reference) is None:
            raise ValueError("image reference must contain an exact OCI tag and sha256 digest")
        return self

    @property
    def digest(self) -> str:
        match = _IMAGE.fullmatch(self.reference)
        if match is None:
            raise ValueError("image reference must contain an exact OCI tag and sha256 digest")
        return match.group("digest")


class ReleaseEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    tag: str
    version: str
    prerelease: bool
    repository: str
    source_sha: str
    workflow_ref: str
    artifacts: tuple[ArtifactEvidence, ...]
    images: tuple[dict[str, str], ...]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _required_artifact_names(identity: ReleaseIdentity) -> frozenset[str]:
    distributions = {
        name
        for distribution in _DISTRIBUTIONS
        for name in (
            f"{distribution}-{identity.version}-py3-none-any.whl",
            f"{distribution}-{identity.version}.tar.gz",
        )
    }
    return _REQUIRED_EVIDENCE_NAMES | distributions


def _artifacts(
    root: Path,
    *,
    identity: ReleaseIdentity,
) -> tuple[ArtifactEvidence, ...]:
    paths = sorted(
        (path for path in root.iterdir() if path.name not in _OUTPUT_NAMES),
        key=lambda path: path.name,
    )
    if not 1 <= len(paths) <= _MAX_ARTIFACTS:
        raise ValueError("release artifact count is invalid")
    artifacts: list[ArtifactEvidence] = []
    for path in paths:
        if path.is_symlink() or not path.is_file() or _ARTIFACT_NAME.fullmatch(path.name) is None:
            raise ValueError("release artifact must be a regular file with a safe name")
        size = path.stat().st_size
        if not 1 <= size <= _MAX_ARTIFACT_BYTES:
            raise ValueError("release artifact size is invalid")
        artifacts.append(ArtifactEvidence(name=path.name, sha256=_sha256(path), size_bytes=size))
    if frozenset(artifact.name for artifact in artifacts) != _required_artifact_names(identity):
        raise ValueError("release asset inventory is incomplete or contains unexpected files")
    return tuple(artifacts)


def _images(
    values: tuple[ImageEvidence, ...],
    *,
    identity: ReleaseIdentity,
    repository: str,
) -> tuple[dict[str, str], ...]:
    if len(values) != 2 or {value.variant for value in values} != {"core", "adk"}:
        raise ValueError("release images must contain exactly core and adk variants")
    images: list[dict[str, str]] = []
    for value in sorted(values, key=lambda item: item.variant):
        expected = f"ghcr.io/{repository}:{identity.oci_tag}-{value.variant}@{value.digest}"
        if value.reference != expected:
            raise ValueError("image reference does not match the release identity")
        images.append(
            {
                "digest": value.digest,
                "reference": value.reference,
                "variant": value.variant,
            }
        )
    return tuple(images)


def write_release_evidence(
    directory: Path,
    *,
    identity: ReleaseIdentity,
    images: tuple[ImageEvidence, ...],
    repository: str,
    source_sha: str,
    workflow_ref: str,
) -> dict[str, object]:
    root = directory.resolve(strict=True)
    if not root.is_dir() or _REPOSITORY.fullmatch(repository) is None:
        raise ValueError("release repository or artifact directory is invalid")
    if _SOURCE_SHA.fullmatch(source_sha) is None:
        raise ValueError("release source SHA is invalid")
    expected_workflow = f"{repository}/.github/workflows/release.yml@refs/tags/{identity.tag}"
    if workflow_ref != expected_workflow:
        raise ValueError("release workflow identity is invalid")
    targets = tuple(root / name for name in _OUTPUT_NAMES)
    if any(target.is_symlink() or (target.exists() and not target.is_file()) for target in targets):
        raise ValueError("release evidence target is invalid")
    evidence = ReleaseEvidence(
        tag=identity.tag,
        version=identity.version,
        prerelease=identity.prerelease,
        repository=repository,
        source_sha=source_sha,
        workflow_ref=workflow_ref,
        artifacts=_artifacts(root, identity=identity),
        images=_images(images, identity=identity, repository=repository),
    )
    document: dict[str, object] = evidence.model_dump(mode="json")
    manifest = root / "release-manifest.json"
    manifest.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum_paths = sorted(
        (path for path in root.iterdir() if path.name != "SHA256SUMS"),
        key=lambda path: path.name,
    )
    checksums = "".join(sorted(f"{_sha256(path)}  {path.name}\n" for path in checksum_paths))
    (root / "SHA256SUMS").write_text(checksums, encoding="utf-8")
    return document


__all__ = ["ArtifactEvidence", "ImageEvidence", "ReleaseEvidence", "write_release_evidence"]
