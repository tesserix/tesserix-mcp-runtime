from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

from release.evidence import ImageEvidence
from release.identity import ReleaseIdentity
from tesserix_mcp_runtime import JsonValue

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SOURCE_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_MATRIX_BYTES = 262_144
_MAX_NOTES_BYTES = 65_536


def _string_list(document: dict[str, JsonValue], name: str) -> tuple[str, ...]:
    value = document.get(name)
    if not isinstance(value, list) or not value:
        raise ValueError(f"support matrix {name} is invalid")
    items = tuple(item for item in value if isinstance(item, str) and 0 < len(item) <= 32)
    if len(items) != len(value) or len(set(items)) != len(items):
        raise ValueError(f"support matrix {name} is invalid")
    return items


def _client_sdks(document: dict[str, JsonValue]) -> tuple[str, ...]:
    value = document.get("client_lanes")
    if not isinstance(value, list) or not value:
        raise ValueError("support matrix client lanes are invalid")
    sdks: list[str] = []
    for lane in value:
        if not isinstance(lane, dict):
            raise ValueError("support matrix client lanes are invalid")
        sdk = lane.get("sdk")
        if not isinstance(sdk, str) or not sdk or len(sdk) > 32:
            raise ValueError("support matrix client lanes are invalid")
        if sdk not in sdks:
            sdks.append(sdk)
    return tuple(sdks)


def write_release_notes(
    target: Path,
    *,
    identity: ReleaseIdentity,
    images: tuple[ImageEvidence, ...],
    repository: str,
    source_sha: str,
    support_matrix: Path,
) -> str:
    if _REPOSITORY.fullmatch(repository) is None or _SOURCE_SHA.fullmatch(source_sha) is None:
        raise ValueError("release notes source identity is invalid")
    if len(images) != 2 or {image.variant for image in images} != {"core", "adk"}:
        raise ValueError("release notes require exactly core and adk images")
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise ValueError("release notes target is invalid")
    if support_matrix.is_symlink() or not support_matrix.is_file():
        raise ValueError("support matrix is invalid")
    encoded_matrix = support_matrix.read_bytes()
    if not encoded_matrix or len(encoded_matrix) > _MAX_MATRIX_BYTES:
        raise ValueError("support matrix size is invalid")
    document = cast(JsonValue, json.loads(encoded_matrix))
    if not isinstance(document, dict):
        raise ValueError("support matrix must be an object")
    python_versions = _string_list(document, "library_python")
    client_sdks = _client_sdks(document)
    image_lines = "\n".join(
        f"- `{image.variant}`: `{image.reference}`"
        for image in sorted(images, key=lambda value: value.variant)
    )
    status = "Release candidate" if identity.prerelease else "Release"
    workflow = f"{repository}/.github/workflows/release.yml"
    notes = f"""# Tesserix MCP runtime {identity.tag}

{status} built from `{source_sha}` by `{workflow}`.

## Artifacts

Four Apache-2.0 Python distributions and the following digest-pinned images are attached:

{image_lines}

`release-manifest.json` and `SHA256SUMS` bind every downloadable file to this source.

## Compatibility

- Python {", ".join(python_versions)}
- MCP SDK {", ".join(client_sdks)}
- MCP 1.34 does not exist; no dependency or support claim uses that version.
- The attached `support-matrix.json` is the complete executable compatibility policy.

## Migration

This is a pre-1.0 release. Pin an exact wheel version and image digest, run the
compatibility and conformance suites, canary the new route, and preserve the previous
digest until the activation probe succeeds. Never replace bytes under this tag.

## Verify before installation

```bash
gh release download {identity.tag} --repo {repository}
sha256sum --check SHA256SUMS
for artifact in ./*.whl ./*.tar.gz; do
  gh attestation verify "$artifact" \\
    --repo {repository} \\
    --signer-workflow {workflow} \\
    --source-ref refs/tags/{identity.tag} \\
    --source-digest {source_sha}
  gh attestation verify "$artifact" \\
    --repo {repository} \\
    --signer-workflow {workflow} \\
    --source-ref refs/tags/{identity.tag} \\
    --source-digest {source_sha} \\
    --predicate-type https://cyclonedx.org/bom
done
cosign verify \\
  --certificate-identity https://github.com/{workflow}@refs/tags/{identity.tag} \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
  --certificate-github-workflow-ref refs/tags/{identity.tag} \\
  --certificate-github-workflow-repository {repository} \\
  --certificate-github-workflow-sha {source_sha} \\
  <image@sha256:digest>
```

The operator and CVE/yank/revocation procedures are in `docs/releasing.md` at this tag.
"""
    if len(notes.encode()) > _MAX_NOTES_BYTES:
        raise ValueError("release notes are too large")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(notes, encoding="utf-8")
    return notes


__all__ = ["write_release_notes"]
