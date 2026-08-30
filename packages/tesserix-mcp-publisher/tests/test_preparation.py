from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from tesserix_mcp_publisher import (
    EvidenceReference,
    PublicationErrorCode,
    PublicationEvidence,
    PublicationValidationError,
    prepare_publication,
)

from tesserix_mcp_runtime import JsonValue, registry_artifact_digest

ROOT = Path(__file__).parents[3]
AUTHORING = (
    ROOT
    / "packages"
    / "tesserix-mcp-manifest"
    / "tests"
    / "goldens"
    / "oci-private-native"
    / "authoring.json"
)
SERVER_JSON = AUTHORING.with_name("server.json")


def evidence(*, artifact_digest: str | None = None) -> PublicationEvidence:
    resolved_artifact_digest = artifact_digest or f"sha256:{'c' * 64}"
    return PublicationEvidence(
        artifact=EvidenceReference(
            uri=(f"oci://ghcr.io/tesserix/settlements-mcp:3.1.0@{resolved_artifact_digest}"),
            digest=resolved_artifact_digest,
            media_type="application/vnd.oci.image.manifest.v1+json",
        ),
        sbom=EvidenceReference(
            uri="https://artifacts.example.com/settlements/3.1.0/sbom.spdx.json",
            digest=f"sha256:{'d' * 64}",
            media_type="application/spdx+json",
        ),
        provenance=EvidenceReference(
            uri="https://artifacts.example.com/settlements/3.1.0/provenance.intoto.jsonl",
            digest=f"sha256:{'e' * 64}",
            media_type="application/vnd.in-toto+jsonl",
        ),
    )


def test_prepare_publication_binds_immutable_supply_chain_evidence() -> None:
    prepared = prepare_publication(
        AUTHORING.read_bytes(),
        runtime_version="3.1.0",
        evidence=evidence(),
    )

    assert prepared.name == "io.github.tesserix/settlements"
    assert prepared.namespace == "tenant-settlements"
    assert prepared.version == "3.1.0"
    assert prepared.ref == ("mcpservers/tenant-settlements/io.github.tesserix/settlements@3.1.0")
    assert prepared.evidence == evidence()
    assert prepared.server_json == SERVER_JSON.read_bytes()
    assert prepared.registry_manifest.endswith(b"\n") is False

    document = cast(dict[str, JsonValue], json.loads(prepared.registry_manifest))
    metadata = cast(dict[str, JsonValue], document["metadata"])
    spec = cast(dict[str, JsonValue], document["spec"])
    extension = cast(dict[str, JsonValue], spec["x-tesserix"])
    assert extension["publication"] == {
        "artifact": {
            "digest": f"sha256:{'c' * 64}",
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "uri": (f"oci://ghcr.io/tesserix/settlements-mcp:3.1.0@sha256:{'c' * 64}"),
        },
        "provenance": {
            "digest": f"sha256:{'e' * 64}",
            "mediaType": "application/vnd.in-toto+jsonl",
            "uri": ("https://artifacts.example.com/settlements/3.1.0/provenance.intoto.jsonl"),
        },
        "sbom": {
            "digest": f"sha256:{'d' * 64}",
            "mediaType": "application/spdx+json",
            "uri": "https://artifacts.example.com/settlements/3.1.0/sbom.spdx.json",
        },
    }
    manifest_labels = cast(dict[str, str], metadata["labels"])
    normalized_labels = dict(manifest_labels)
    normalized_labels.update(
        {
            "registry.agentic.dev/org": "tesserix",
            "registry.agentic.dev/tenant": "tenant-settlements",
            "registry.agentic.dev/visibility": "private",
        }
    )
    assert not any(label.startswith("registry.agentic.dev/") for label in manifest_labels)
    assert prepared.registry_digest == registry_artifact_digest(
        kind=cast(str, document["kind"]),
        name=cast(str, metadata["name"]),
        namespace=cast(str, metadata["namespace"]),
        tag=cast(str, metadata["tag"]),
        labels=normalized_labels,
        spec=spec,
    )


def test_prepare_publication_rejects_evidence_that_does_not_match_the_image() -> None:
    with pytest.raises(PublicationValidationError) as caught:
        prepare_publication(
            AUTHORING.read_bytes(),
            runtime_version="3.1.0",
            evidence=evidence(artifact_digest=f"sha256:{'a' * 64}"),
        )

    assert caught.value.code is PublicationErrorCode.ARTIFACT_DIGEST_MISMATCH
    assert str(caught.value) == "artifact_digest_mismatch"


def test_prepare_publication_requires_complete_supply_chain_evidence() -> None:
    with pytest.raises(PublicationValidationError) as caught:
        prepare_publication(
            AUTHORING.read_bytes(),
            runtime_version="3.1.0",
            evidence=None,
        )

    assert caught.value.code is PublicationErrorCode.EVIDENCE_REQUIRED


def test_manifest_failures_never_echo_secret_canaries() -> None:
    source = AUTHORING.read_text(encoding="utf-8").replace(
        '"owner": "payments-platform"',
        '"api_token": "PPPPPPPPPPPPPPPP"',
    )

    with pytest.raises(PublicationValidationError) as caught:
        prepare_publication(
            source.encode(),
            runtime_version="3.1.0",
            evidence=evidence(),
        )

    assert caught.value.code is PublicationErrorCode.MANIFEST_INVALID
    assert "PPPPPPPPPPPPPPPP" not in str(caught.value)
