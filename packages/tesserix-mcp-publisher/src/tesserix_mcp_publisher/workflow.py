"""Fail-closed publication state machine."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from .contracts import OfficialPublicationClient, TesserixPublicationClient
from .errors import (
    PublicationError,
    PublicationErrorCode,
    PublicationUnknownOutcomeError,
    PublicationValidationError,
)
from .models import (
    OfficialPublicationStatus,
    PreparedPublication,
    PublicationOutcome,
    PublicationStatus,
    PublishedArtifact,
    PublishReceipt,
)

_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{7,199}\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


class PublisherWorkflow:
    """Publish Tesserix first, verify exactly, then optionally publish official."""

    def __init__(
        self,
        *,
        tesserix: TesserixPublicationClient,
        official: OfficialPublicationClient | None = None,
    ) -> None:
        if not _is_runtime_instance(tesserix, TesserixPublicationClient):
            raise TypeError("tesserix must implement TesserixPublicationClient")
        if official is not None and not _is_runtime_instance(official, OfficialPublicationClient):
            raise TypeError("official must implement OfficialPublicationClient")
        self._tesserix = tesserix
        self._official = official

    async def execute(
        self,
        prepared: PreparedPublication,
        *,
        idempotency_key: str,
        request_id: str,
        dry_run: bool = False,
        publish_official: bool = False,
    ) -> PublicationOutcome:
        if (
            not _is_runtime_instance(prepared, PreparedPublication)
            or not _is_runtime_instance(idempotency_key, str)
            or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
            or not _is_runtime_instance(request_id, str)
            or _REQUEST_ID.fullmatch(request_id) is None
            or not _is_runtime_instance(dry_run, bool)
            or not _is_runtime_instance(publish_official, bool)
            or (publish_official and self._official is None)
        ):
            raise PublicationValidationError(
                PublicationErrorCode.MANIFEST_INVALID,
                request_id=(
                    request_id
                    if _is_runtime_instance(request_id, str)
                    and _REQUEST_ID.fullmatch(request_id) is not None
                    else "publication-validation"
                ),
            )

        if dry_run:
            await self._tesserix.remote_validate(
                prepared,
                idempotency_key=idempotency_key,
                request_id=request_id,
            )
            official_status = OfficialPublicationStatus.NOT_REQUESTED
            if publish_official:
                assert self._official is not None
                await self._official.validate(prepared, request_id=request_id)
                official_status = OfficialPublicationStatus.VALIDATED
            return PublicationOutcome(
                status=PublicationStatus.DRY_RUN,
                official_status=official_status,
                request_id=request_id,
                idempotency_key=idempotency_key,
                ref=prepared.ref,
                digest=prepared.registry_digest,
                artifact_digest=prepared.evidence.artifact.digest,
                version=prepared.version,
                created=None,
                artifact=None,
            )

        receipt = await self._tesserix.publish(
            prepared,
            idempotency_key=idempotency_key,
            request_id=request_id,
        )
        if not _is_runtime_instance(receipt, PublishReceipt):
            raise PublicationUnknownOutcomeError(request_id=request_id)
        try:
            artifact = await self._tesserix.fetch(prepared, request_id=request_id)
            if (
                not _is_runtime_instance(artifact, PublishedArtifact)
                or artifact.name != prepared.name
                or artifact.namespace != prepared.namespace
                or artifact.version != prepared.version
                or artifact.ref != prepared.ref
                or artifact.digest != prepared.registry_digest
            ):
                raise PublicationError(
                    PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                    request_id=request_id,
                )
            await self._tesserix.verify(artifact, request_id=request_id)
        except (PublicationError, asyncio.CancelledError, TypeError, ValueError):
            raise PublicationUnknownOutcomeError(request_id=request_id) from None

        official_status = OfficialPublicationStatus.NOT_REQUESTED
        status = PublicationStatus.VERIFIED
        if publish_official:
            assert self._official is not None
            try:
                await self._official.validate(prepared, request_id=request_id)
                await self._official.publish(prepared, request_id=request_id)
                official_status = OfficialPublicationStatus.PUBLISHED
            except PublicationError:
                official_status = OfficialPublicationStatus.FAILED
                status = PublicationStatus.PARTIAL

        return PublicationOutcome(
            status=status,
            official_status=official_status,
            request_id=request_id,
            idempotency_key=idempotency_key,
            ref=artifact.ref,
            digest=artifact.digest,
            artifact_digest=prepared.evidence.artifact.digest,
            version=artifact.version,
            created=receipt.created,
            artifact=artifact,
        )
