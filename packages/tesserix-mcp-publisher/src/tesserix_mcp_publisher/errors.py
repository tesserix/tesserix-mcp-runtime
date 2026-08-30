"""Payload-free publication failures."""

from __future__ import annotations

from enum import StrEnum

from tesserix_mcp_runtime import JsonValue


class PublicationErrorCode(StrEnum):
    """Stable public publication failure codes."""

    ACTIVATION_CONTRACT_INVALID = "activation_contract_invalid"
    ACTIVATION_FAILED = "activation_failed"
    ACTIVATION_SUPERSEDED = "activation_superseded"
    ACTIVATION_TIMEOUT = "activation_timeout"
    ARTIFACT_DIGEST_MISMATCH = "artifact_digest_mismatch"
    COMMAND_FAILED = "command_failed"
    COMMAND_OUTPUT_INVALID = "command_output_invalid"
    CONFLICT = "immutable_version_conflict"
    EVIDENCE_REQUIRED = "evidence_required"
    INVALID_ARGUMENT = "invalid_argument"
    MANIFEST_INVALID = "manifest_invalid"
    OFFICIAL_PUBLICATION_FAILED = "official_publication_failed"
    SECRET_MATERIAL = "secret_material"
    UNKNOWN_OUTCOME = "publication_outcome_unknown"
    UNAVAILABLE = "publisher_unavailable"


_MESSAGES: dict[PublicationErrorCode, str] = {
    PublicationErrorCode.ACTIVATION_CONTRACT_INVALID: "Activation status contract is invalid.",
    PublicationErrorCode.ACTIVATION_FAILED: "Gateway activation reached a terminal state.",
    PublicationErrorCode.ACTIVATION_SUPERSEDED: "Activation target was superseded.",
    PublicationErrorCode.ACTIVATION_TIMEOUT: "Gateway activation did not complete before deadline.",
    PublicationErrorCode.ARTIFACT_DIGEST_MISMATCH: "Artifact evidence does not match delivery.",
    PublicationErrorCode.COMMAND_FAILED: "Delegated publisher command failed.",
    PublicationErrorCode.COMMAND_OUTPUT_INVALID: "Delegated publisher returned invalid output.",
    PublicationErrorCode.CONFLICT: "Immutable version already has different content.",
    PublicationErrorCode.EVIDENCE_REQUIRED: "Complete supply-chain evidence is required.",
    PublicationErrorCode.INVALID_ARGUMENT: "Command arguments are invalid.",
    PublicationErrorCode.MANIFEST_INVALID: "Publication manifest is invalid.",
    PublicationErrorCode.OFFICIAL_PUBLICATION_FAILED: "Official Registry publication failed.",
    PublicationErrorCode.SECRET_MATERIAL: "Publisher output contained protected material.",
    PublicationErrorCode.UNKNOWN_OUTCOME: "Publication outcome must be reconciled.",
    PublicationErrorCode.UNAVAILABLE: "Delegated publisher is unavailable.",
}


class PublicationError(RuntimeError):
    """One stable payload-free failure at the publication boundary."""

    def __init__(
        self,
        code: PublicationErrorCode,
        *,
        request_id: str = "publication-validation",
        retryable: bool = False,
    ) -> None:
        self.code = code
        self.request_id = request_id
        self.retryable = retryable
        super().__init__(code.value)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "code": self.code.value,
            "message": _MESSAGES[self.code],
            "request_id": self.request_id,
            "retryable": self.retryable,
        }


class PublicationValidationError(PublicationError):
    """Local publication validation failed before any external write."""


class PublicationUnknownOutcomeError(PublicationError):
    """Registry accepted a write but exact verification did not finish."""

    def __init__(self, *, request_id: str) -> None:
        super().__init__(
            PublicationErrorCode.UNKNOWN_OUTCOME,
            request_id=request_id,
            retryable=False,
        )
