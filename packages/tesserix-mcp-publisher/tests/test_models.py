from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import cast

import pytest
from tesserix_mcp_publisher import (
    EvidenceReference,
    OfficialPublicationStatus,
    PreparedPublication,
    PublicationEvidence,
    PublicationOutcome,
    PublicationStatus,
    PublicationValidationError,
    PublishedArtifact,
    PublishReceipt,
)


def reference() -> EvidenceReference:
    return EvidenceReference(
        uri="https://artifacts.example.com/evidence.json",
        digest=f"sha256:{'a' * 64}",
        media_type="application/json",
    )


def evidence() -> PublicationEvidence:
    item = reference()
    return PublicationEvidence(artifact=item, sbom=item, provenance=item)


def prepared() -> PreparedPublication:
    return PreparedPublication(
        name="io.github.tesserix/orders",
        namespace="tenant-orders",
        version="1.2.3",
        ref="mcpservers/tenant-orders/io.github.tesserix/orders@1.2.3",
        server_json=b"{}",
        registry_manifest=b"{}",
        registry_digest=f"sha256:{'b' * 64}",
        evidence=evidence(),
    )


def artifact() -> PublishedArtifact:
    return PublishedArtifact(
        name="io.github.tesserix/orders",
        namespace="tenant-orders",
        version="1.2.3",
        ref="mcpservers/tenant-orders/io.github.tesserix/orders@1.2.3",
        digest=f"sha256:{'b' * 64}",
        signature="c2lnbmF0dXJl",
        signed_by="registry-key-2026-08",
    )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: EvidenceReference(
            uri="http://artifacts.example.com/evidence.json",
            digest=f"sha256:{'a' * 64}",
            media_type="application/json",
        ),
        lambda: EvidenceReference(
            uri="https://user:password@artifacts.example.com/evidence.json",
            digest=f"sha256:{'a' * 64}",
            media_type="application/json",
        ),
        lambda: EvidenceReference(
            uri="https://artifacts.example.com/evidence.json?token=value",
            digest=f"sha256:{'a' * 64}",
            media_type="application/json",
        ),
        lambda: EvidenceReference(
            uri="https://artifacts.example.com/evidence.json",
            digest="sha256:not-a-digest",
            media_type="application/json",
        ),
        lambda: EvidenceReference(
            uri="https://artifacts.example.com/evidence.json",
            digest=f"sha256:{'a' * 64}",
            media_type="invalid media type",
        ),
    ],
)
def test_evidence_reference_rejects_mutable_or_ambiguous_identity(
    factory: Callable[[], EvidenceReference],
) -> None:
    with pytest.raises(PublicationValidationError):
        factory()


def test_publication_evidence_rejects_untyped_members() -> None:
    with pytest.raises(PublicationValidationError):
        PublicationEvidence(
            artifact=cast(EvidenceReference, object()),
            sbom=reference(),
            provenance=reference(),
        )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: replace(prepared(), name=""),
        lambda: replace(prepared(), ref="https://registry.example.com/orders"),
        lambda: replace(prepared(), server_json=cast(bytes, "{}")),
        lambda: replace(prepared(), registry_manifest=b"x" * (1024 * 1024 + 1)),
        lambda: replace(prepared(), registry_digest="sha256:invalid"),
    ],
)
def test_prepared_publication_rejects_unbounded_or_untyped_fields(
    factory: Callable[[], PreparedPublication],
) -> None:
    with pytest.raises(PublicationValidationError):
        factory()


def test_publish_receipt_requires_a_boolean_created_flag() -> None:
    with pytest.raises(PublicationValidationError):
        PublishReceipt(created=cast(bool, 1))


@pytest.mark.parametrize(
    "factory",
    [
        lambda: replace(artifact(), name=""),
        lambda: replace(artifact(), ref="unsafe ref"),
        lambda: replace(artifact(), digest="sha256:invalid"),
        lambda: replace(artifact(), signature=""),
        lambda: replace(artifact(), signed_by="registry\nkey"),
    ],
)
def test_published_artifact_rejects_unverifiable_identity(
    factory: Callable[[], PublishedArtifact],
) -> None:
    with pytest.raises(PublicationValidationError):
        factory()


def test_publication_outcome_rejects_inconsistent_external_state() -> None:
    valid = PublicationOutcome(
        status=PublicationStatus.VERIFIED,
        official_status=OfficialPublicationStatus.NOT_REQUESTED,
        request_id="request-model",
        idempotency_key="publish-run-42",
        ref=artifact().ref,
        digest=artifact().digest,
        version=artifact().version,
        created=True,
        artifact=artifact(),
    )

    factories: tuple[Callable[[], PublicationOutcome], ...] = (
        lambda: replace(valid, status=cast(PublicationStatus, "verified")),
        lambda: replace(valid, request_id=""),
        lambda: replace(valid, created=cast(bool | None, 1)),
        lambda: replace(valid, artifact=cast(PublishedArtifact | None, object())),
    )
    for factory in factories:
        with pytest.raises(PublicationValidationError):
            factory()
