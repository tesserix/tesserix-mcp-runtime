"""Immutable publication values."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from tesserix_mcp_runtime import JsonValue

from .errors import PublicationErrorCode, PublicationValidationError

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MEDIA_TYPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+\-/]{0,126}\Z")
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,2047}\Z")


def _fail(code: PublicationErrorCode) -> PublicationValidationError:
    return PublicationValidationError(code)


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceReference:
    """One immutable externally stored artifact, SBOM, or provenance record."""

    uri: str
    digest: str
    media_type: str

    def __post_init__(self) -> None:
        parsed = urlsplit(self.uri)
        if (
            len(self.uri) > 2_048
            or parsed.scheme not in {"https", "oci"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "\\" in self.uri
        ):
            raise _fail(PublicationErrorCode.MANIFEST_INVALID)
        if _DIGEST.fullmatch(self.digest) is None:
            raise _fail(PublicationErrorCode.MANIFEST_INVALID)
        if _MEDIA_TYPE.fullmatch(self.media_type) is None:
            raise _fail(PublicationErrorCode.MANIFEST_INVALID)

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "digest": self.digest,
            "mediaType": self.media_type,
            "uri": self.uri,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class PublicationEvidence:
    """Complete immutable supply-chain evidence required for publication."""

    artifact: EvidenceReference
    sbom: EvidenceReference
    provenance: EvidenceReference

    def __post_init__(self) -> None:
        if not all(
            _is_runtime_instance(value, EvidenceReference)
            for value in (self.artifact, self.sbom, self.provenance)
        ):
            raise _fail(PublicationErrorCode.EVIDENCE_REQUIRED)

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "artifact": self.artifact.to_document(),
            "provenance": self.provenance.to_document(),
            "sbom": self.sbom.to_document(),
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class PreparedPublication:
    """Validated byte-stable manifests ready for delegated publication."""

    name: str
    namespace: str
    version: str
    ref: str
    server_json: bytes
    registry_manifest: bytes
    registry_digest: str
    evidence: PublicationEvidence

    def __post_init__(self) -> None:
        if (
            not self.name
            or not self.namespace
            or not self.version
            or len(self.ref) > 2_048
            or not self.ref.startswith("mcpservers/")
            or not _is_runtime_instance(self.server_json, bytes)
            or not _is_runtime_instance(self.registry_manifest, bytes)
            or len(self.server_json) > 512 * 1024
            or len(self.registry_manifest) > 1024 * 1024
            or _DIGEST.fullmatch(self.registry_digest) is None
            or not _is_runtime_instance(self.evidence, PublicationEvidence)
        ):
            raise _fail(PublicationErrorCode.MANIFEST_INVALID)


class PublicationStatus(StrEnum):
    """Externally meaningful state of one workflow execution."""

    DRY_RUN = "dry_run"
    PARTIAL = "partial"
    VERIFIED = "verified"


class OfficialPublicationStatus(StrEnum):
    """Explicit official Registry target state."""

    FAILED = "failed"
    NOT_REQUESTED = "not_requested"
    PUBLISHED = "published"
    VALIDATED = "validated"


@dataclass(frozen=True, slots=True, kw_only=True)
class PublishReceipt:
    """Result of the atomic Agentic Registry apply before read-back."""

    created: bool

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.created, bool):
            raise _fail(PublicationErrorCode.COMMAND_OUTPUT_INVALID)


@dataclass(frozen=True, slots=True, kw_only=True)
class PublishedArtifact:
    """Exact signed Agentic Registry object returned after publication."""

    name: str
    namespace: str
    version: str
    ref: str
    digest: str
    signature: str
    signed_by: str

    def __post_init__(self) -> None:
        if (
            not all(
                _is_runtime_instance(value, str)
                for value in (
                    self.name,
                    self.namespace,
                    self.version,
                    self.ref,
                    self.digest,
                    self.signature,
                    self.signed_by,
                )
            )
            or not self.name
            or not self.namespace
            or not self.version
            or _SAFE_ID.fullmatch(self.ref) is None
            or _DIGEST.fullmatch(self.digest) is None
            or not 1 <= len(self.signature) <= 512
            or not 1 <= len(self.signed_by) <= 256
            or any(not character.isprintable() for character in self.signed_by)
        ):
            raise _fail(PublicationErrorCode.COMMAND_OUTPUT_INVALID)


@dataclass(frozen=True, slots=True, kw_only=True)
class PublicationOutcome:
    """Safe complete result for CLI JSON and CI reconciliation."""

    status: PublicationStatus
    official_status: OfficialPublicationStatus
    request_id: str
    idempotency_key: str
    ref: str
    digest: str
    version: str
    created: bool | None
    artifact: PublishedArtifact | None

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.status, PublicationStatus)
            or not _is_runtime_instance(self.official_status, OfficialPublicationStatus)
            or not all(
                _is_runtime_instance(value, str)
                for value in (
                    self.request_id,
                    self.idempotency_key,
                    self.ref,
                    self.digest,
                    self.version,
                )
            )
            or not self.request_id
            or not self.idempotency_key
            or _SAFE_ID.fullmatch(self.ref) is None
            or _DIGEST.fullmatch(self.digest) is None
            or (self.created is not None and not _is_runtime_instance(self.created, bool))
            or (
                self.artifact is not None
                and not _is_runtime_instance(self.artifact, PublishedArtifact)
            )
        ):
            raise _fail(PublicationErrorCode.COMMAND_OUTPUT_INVALID)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "created": self.created,
            "digest": self.digest,
            "idempotency_key": self.idempotency_key,
            "official_status": self.official_status.value,
            "ref": self.ref,
            "request_id": self.request_id,
            "signed_by": self.artifact.signed_by if self.artifact is not None else None,
            "status": self.status.value,
            "version": self.version,
        }
