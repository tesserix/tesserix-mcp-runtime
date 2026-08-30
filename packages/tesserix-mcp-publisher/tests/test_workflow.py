from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from tesserix_mcp_publisher import (
    EvidenceReference,
    OfficialPublicationStatus,
    PreparedPublication,
    PublicationError,
    PublicationErrorCode,
    PublicationEvidence,
    PublicationStatus,
    PublicationUnknownOutcomeError,
    PublicationValidationError,
    PublishedArtifact,
    PublisherWorkflow,
    PublishReceipt,
    prepare_publication,
)

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


def prepared_publication() -> PreparedPublication:
    evidence = PublicationEvidence(
        artifact=EvidenceReference(
            uri=(f"oci://ghcr.io/tesserix/settlements-mcp:3.1.0@sha256:{'c' * 64}"),
            digest=f"sha256:{'c' * 64}",
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
    return prepare_publication(
        AUTHORING.read_bytes(),
        runtime_version="3.1.0",
        evidence=evidence,
    )


class FakeTesserixPublisher:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.fail_fetch = False
        self.keys: list[str] = []
        self.receipts: dict[str, PublishReceipt] = {}

    async def remote_validate(
        self,
        prepared: PreparedPublication,
        *,
        idempotency_key: str,
        request_id: str,
    ) -> None:
        del prepared, idempotency_key, request_id
        self.events.append("tesserix.validate")

    async def publish(
        self,
        prepared: PreparedPublication,
        *,
        idempotency_key: str,
        request_id: str,
    ) -> PublishReceipt:
        del prepared, request_id
        self.events.append("tesserix.publish")
        self.keys.append(idempotency_key)
        return self.receipts.setdefault(idempotency_key, PublishReceipt(created=True))

    async def fetch(
        self,
        prepared: PreparedPublication,
        *,
        request_id: str,
    ) -> PublishedArtifact:
        self.events.append("tesserix.fetch")
        if self.fail_fetch:
            raise PublicationError(
                PublicationErrorCode.UNAVAILABLE,
                request_id=request_id,
                retryable=True,
            )
        return PublishedArtifact(
            name=prepared.name,
            namespace=prepared.namespace,
            version=prepared.version,
            ref=prepared.ref,
            digest=prepared.registry_digest,
            signature="c2lnbmF0dXJl",
            signed_by="registry-key-2026-08",
        )

    async def verify(
        self,
        artifact: PublishedArtifact,
        *,
        request_id: str,
    ) -> None:
        del artifact, request_id
        self.events.append("tesserix.verify")


class FakeOfficialPublisher:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.fail_publish = False

    async def validate(self, prepared: PreparedPublication, *, request_id: str) -> None:
        del prepared, request_id
        self.events.append("official.validate")

    async def publish(self, prepared: PreparedPublication, *, request_id: str) -> None:
        del prepared
        self.events.append("official.publish")
        if self.fail_publish:
            raise PublicationError(
                PublicationErrorCode.OFFICIAL_PUBLICATION_FAILED,
                request_id=request_id,
            )


def test_dry_run_performs_remote_reads_and_validation_without_writes() -> None:
    events: list[str] = []
    workflow = PublisherWorkflow(
        tesserix=FakeTesserixPublisher(events),
        official=FakeOfficialPublisher(events),
    )

    outcome = asyncio.run(
        workflow.execute(
            prepared_publication(),
            idempotency_key="publish-run-42",
            request_id="request-publish-dry-run",
            dry_run=True,
            publish_official=True,
        )
    )

    assert events == ["tesserix.validate", "official.validate"]
    assert outcome.status is PublicationStatus.DRY_RUN
    assert outcome.official_status is OfficialPublicationStatus.VALIDATED
    assert outcome.artifact is None
    assert outcome.ref == prepared_publication().ref
    assert outcome.digest == prepared_publication().registry_digest


def test_publish_verifies_tesserix_before_explicit_official_target() -> None:
    events: list[str] = []
    workflow = PublisherWorkflow(
        tesserix=FakeTesserixPublisher(events),
        official=FakeOfficialPublisher(events),
    )

    outcome = asyncio.run(
        workflow.execute(
            prepared_publication(),
            idempotency_key="publish-run-42",
            request_id="request-publish",
            dry_run=False,
            publish_official=True,
        )
    )

    assert events == [
        "tesserix.publish",
        "tesserix.fetch",
        "tesserix.verify",
        "official.validate",
        "official.publish",
    ]
    assert outcome.status is PublicationStatus.VERIFIED
    assert outcome.official_status is OfficialPublicationStatus.PUBLISHED
    assert outcome.created is True
    assert outcome.artifact is not None
    assert outcome.artifact.ref == prepared_publication().ref
    assert outcome.to_dict() == {
        "artifact_digest": prepared_publication().evidence.artifact.digest,
        "created": True,
        "digest": prepared_publication().registry_digest,
        "idempotency_key": "publish-run-42",
        "official_status": "published",
        "ref": prepared_publication().ref,
        "request_id": "request-publish",
        "signed_by": "registry-key-2026-08",
        "status": "verified",
        "version": "3.1.0",
    }


def test_repeated_publish_reuses_the_key_and_original_artifact() -> None:
    events: list[str] = []
    tesserix = FakeTesserixPublisher(events)
    workflow = PublisherWorkflow(tesserix=tesserix)

    first = asyncio.run(
        workflow.execute(
            prepared_publication(),
            idempotency_key="publish-run-42",
            request_id="request-first",
        )
    )
    second = asyncio.run(
        workflow.execute(
            prepared_publication(),
            idempotency_key="publish-run-42",
            request_id="request-second",
        )
    )

    assert tesserix.keys == ["publish-run-42", "publish-run-42"]
    assert first.ref == second.ref
    assert first.digest == second.digest
    assert first.created is True
    assert second.created is True


def test_verification_read_failure_reports_an_unknown_outcome() -> None:
    events: list[str] = []
    tesserix = FakeTesserixPublisher(events)
    tesserix.fail_fetch = True
    workflow = PublisherWorkflow(tesserix=tesserix)

    with pytest.raises(PublicationUnknownOutcomeError) as caught:
        asyncio.run(
            workflow.execute(
                prepared_publication(),
                idempotency_key="publish-run-42",
                request_id="request-ambiguous",
            )
        )

    assert caught.value.request_id == "request-ambiguous"
    assert caught.value.code is PublicationErrorCode.UNKNOWN_OUTCOME
    assert caught.value.retryable is False
    assert events == ["tesserix.publish", "tesserix.fetch"]


def test_official_failure_preserves_the_verified_tesserix_result() -> None:
    events: list[str] = []
    official = FakeOfficialPublisher(events)
    official.fail_publish = True
    workflow = PublisherWorkflow(
        tesserix=FakeTesserixPublisher(events),
        official=official,
    )

    outcome = asyncio.run(
        workflow.execute(
            prepared_publication(),
            idempotency_key="publish-run-42",
            request_id="request-partial",
            publish_official=True,
        )
    )

    assert outcome.status is PublicationStatus.PARTIAL
    assert outcome.official_status is OfficialPublicationStatus.FAILED
    assert outcome.artifact is not None
    assert outcome.artifact.ref == prepared_publication().ref


def test_unsafe_idempotency_key_fails_before_any_delegate_call() -> None:
    events: list[str] = []
    workflow = PublisherWorkflow(tesserix=FakeTesserixPublisher(events))

    with pytest.raises(PublicationValidationError) as caught:
        asyncio.run(
            workflow.execute(
                prepared_publication(),
                idempotency_key="unsafe\nkey",
                request_id="request-invalid",
            )
        )

    assert caught.value.code is PublicationErrorCode.MANIFEST_INVALID
    assert events == []
