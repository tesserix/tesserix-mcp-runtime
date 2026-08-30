from __future__ import annotations

import json
from pathlib import Path

import pytest
from release.evidence import ImageEvidence
from release.identity import ReleaseIdentity
from release.notes import write_release_notes


def test_release_notes_name_compatibility_migration_and_verification(tmp_path: Path) -> None:
    matrix = tmp_path / "support-matrix.json"
    matrix.write_text(
        json.dumps(
            {
                "library_python": ["3.12", "3.13", "3.14"],
                "server_sdk": {"locked": "2.1.1"},
                "client_lanes": [
                    {"name": "devai-sdk", "sdk": "1.28.1"},
                    {"name": "maintained-v1", "sdk": "1.29.1"},
                    {"name": "current-v2", "sdk": "2.1.1"},
                ],
                "gateway": {"implementation": "agentgateway"},
            }
        ),
        encoding="utf-8",
    )
    target = tmp_path / "release-notes.md"

    encoded = write_release_notes(
        target,
        identity=ReleaseIdentity.parse("v0.1.0-rc.1"),
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
        support_matrix=matrix,
    )

    assert target.read_text(encoding="utf-8") == encoded
    assert "# Tesserix MCP runtime v0.1.0-rc.1" in encoded
    assert "Release candidate" in encoded
    assert "Python 3.12, 3.13, 3.14" in encoded
    assert "MCP SDK 1.28.1, 1.29.1, 2.1.1" in encoded
    assert "MCP 1.34 does not exist" in encoded
    assert "## Migration" in encoded
    assert "## Verify before installation" in encoded
    assert "gh attestation verify" in encoded
    assert "--predicate-type https://cyclonedx.org/bom" in encoded
    assert "cosign verify" in encoded
    assert "sha256:" + "a" * 64 in encoded


def test_release_notes_require_both_image_variants(tmp_path: Path) -> None:
    matrix = tmp_path / "support-matrix.json"
    matrix.write_text(
        json.dumps(
            {
                "library_python": ["3.14"],
                "client_lanes": [{"name": "current-v2", "sdk": "2.1.1"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exactly core and adk"):
        write_release_notes(
            tmp_path / "release-notes.md",
            identity=ReleaseIdentity.parse("v1.0.0"),
            images=(
                ImageEvidence(
                    variant="core",
                    reference=(f"ghcr.io/tesserix/runtime:1.0.0-core@sha256:{'a' * 64}"),
                ),
            ),
            repository="tesserix/runtime",
            source_sha="1" * 40,
            support_matrix=matrix,
        )
