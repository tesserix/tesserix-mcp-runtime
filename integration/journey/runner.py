from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from mcp.types import CallToolResult, TextContent
from tesserix_mcp_publisher import EvidenceReference, PublicationEvidence

from integration.journey.registry import decode_json_object
from tesserix_mcp_runtime import ErrorCode, ErrorResponse, JsonValue, SecretValue

_AUTHORITY_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TRACEPARENT = re.compile(r"00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(
    r"(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
_MAX_TOOL_RESULT_BYTES = 64 * 1024
_REGISTRY_COMMIT = "6921474591b6c59e89025370c310c7f85859246f"
_GATEWAY_DIGEST = "sha256:efd79355b89094a8225a9db465d9a01dc656b377f0bab458761b935a13231d29"


class JourneyRunError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"journey_run:{code}")


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class MCPAuthority:
    token: SecretValue
    run_id: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.token, SecretValue)
            or not isinstance(self.run_id, str)
            or _AUTHORITY_TEXT.fullmatch(self.run_id) is None
        ):
            raise ValueError("MCP authority must be bounded")

    def headers(
        self,
        *,
        request_id: str,
        traceparent: str,
        timeout_ms: int,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
    ) -> dict[str, str]:
        if (
            not isinstance(request_id, str)
            or _AUTHORITY_TEXT.fullmatch(request_id) is None
            or not isinstance(traceparent, str)
            or _TRACEPARENT.fullmatch(traceparent) is None
            or isinstance(timeout_ms, bool)
            or not isinstance(timeout_ms, int)
            or not 1 <= timeout_ms <= 300_000
            or not self._optional_authority(idempotency_key)
            or not self._optional_authority(approval_id)
        ):
            raise ValueError("invocation authority is invalid")
        headers = {
            "authorization": "Bearer " + self.token.reveal(),
            "traceparent": traceparent,
            "x-request-id": request_id,
            "x-tesserix-run-id": self.run_id,
            "x-tesserix-timeout-ms": str(timeout_ms),
        }
        if idempotency_key is not None:
            headers["idempotency-key"] = idempotency_key
        if approval_id is not None:
            headers["x-tesserix-approval-id"] = approval_id
        return headers

    @staticmethod
    def _optional_authority(value: str | None) -> bool:
        return value is None or (
            isinstance(value, str) and _AUTHORITY_TEXT.fullmatch(value) is not None
        )

    def __repr__(self) -> str:
        return f"MCPAuthority(run_id={self.run_id!r}, token=[redacted])"


def _text_document(result: CallToolResult) -> dict[str, object]:
    if (
        not isinstance(result, CallToolResult)
        or not isinstance(result.content, list)
        or len(result.content) != 1
        or not isinstance(result.content[0], TextContent)
    ):
        raise JourneyRunError("tool_result_invalid")
    try:
        return dict(
            decode_json_object(
                result.content[0].text.encode(),
                maximum=_MAX_TOOL_RESULT_BYTES,
            )
        )
    except (RuntimeError, UnicodeError, ValueError):
        raise JourneyRunError("tool_result_invalid") from None


def decode_success(result: CallToolResult) -> dict[str, JsonValue]:
    document = _text_document(result)
    structured = result.structured_content
    if result.is_error or not isinstance(structured, dict) or document != structured:
        raise JourneyRunError("tool_result_invalid")
    return cast(dict[str, JsonValue], document)


def decode_failure(result: CallToolResult) -> str:
    document = _text_document(result)
    code = document.get("code")
    request_id = document.get("request_id")
    if (
        result.is_error is not True
        or result.structured_content is not None
        or not isinstance(code, str)
        or not isinstance(request_id, str)
    ):
        raise JourneyRunError("tool_result_invalid")
    try:
        expected = ErrorResponse.from_code(
            ErrorCode(code),
            request_id=request_id,
        ).to_dict()
    except ValueError:
        raise JourneyRunError("tool_result_invalid") from None
    if document != expected:
        raise JourneyRunError("tool_result_invalid")
    return code


def has_backing_correlation(
    observations: object,
    *,
    request_id: str,
    trace_id: str,
) -> bool:
    if not isinstance(observations, list):
        return False
    for item in observations:
        if not isinstance(item, dict):
            continue
        context = item.get("context")
        if (
            isinstance(context, dict)
            and context.get("request_id") == request_id
            and context.get("trace_id") == trace_id
        ):
            return True
    return False


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )


def _evidence_reference(path: Path, *, media_type: str) -> EvidenceReference:
    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return EvidenceReference(
        uri=f"https://evidence.journey.invalid/{path.name}@{digest}",
        digest=digest,
        media_type=media_type,
    )


def create_publication_evidence(
    *,
    output_dir: Path,
    artifact_digest: str,
    created_at: str,
) -> PublicationEvidence:
    if (
        not isinstance(output_dir, Path)
        or not output_dir.is_absolute()
        or not output_dir.is_dir()
        or not isinstance(artifact_digest, str)
        or _DIGEST.fullmatch(artifact_digest) is None
        or not isinstance(created_at, str)
        or _TIMESTAMP.fullmatch(created_at) is None
    ):
        raise ValueError("publication evidence inputs are invalid")
    digest_value = artifact_digest.removeprefix("sha256:")
    sbom_path = output_dir / "journey.spdx.json"
    provenance_path = output_dir / "journey.intoto.json"
    sbom_path.write_bytes(
        _canonical_json(
            {
                "SPDXID": "SPDXRef-DOCUMENT",
                "creationInfo": {
                    "created": created_at,
                    "creators": ["Tool: tesserix-mcp-runtime-journey"],
                },
                "dataLicense": "CC0-1.0",
                "documentNamespace": ("https://evidence.journey.invalid/spdx/" + digest_value),
                "name": "tesserix-mcp-release-journey",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-RuntimeImage",
                        "checksums": [{"algorithm": "SHA256", "checksumValue": digest_value}],
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                        "name": "ghcr.io/tesserix/tesserix-mcp-journey",
                        "versionInfo": "1.0.0",
                    }
                ],
                "spdxVersion": "SPDX-2.3",
            }
        )
    )
    provenance_path.write_bytes(
        _canonical_json(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "predicate": {
                    "buildDefinition": {
                        "buildType": "https://tesserix.dev/buildtypes/mcp-release-journey/v1",
                        "externalParameters": {
                            "agentgateway": _GATEWAY_DIGEST,
                            "agenticRegistryCommit": _REGISTRY_COMMIT,
                        },
                    },
                    "runDetails": {
                        "builder": {"id": "https://github.com/tesserix/tesserix-mcp-runtime"}
                    },
                },
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [
                    {
                        "digest": {"sha256": digest_value},
                        "name": "ghcr.io/tesserix/tesserix-mcp-journey:1.0.0",
                    }
                ],
            }
        )
    )
    return PublicationEvidence(
        artifact=EvidenceReference(
            uri=("oci://ghcr.io/tesserix/tesserix-mcp-journey@" + artifact_digest),
            digest=artifact_digest,
            media_type="application/vnd.oci.image.manifest.v1+json",
        ),
        sbom=_evidence_reference(sbom_path, media_type="application/spdx+json"),
        provenance=_evidence_reference(
            provenance_path,
            media_type="application/vnd.in-toto+json",
        ),
    )


__all__ = [
    "JourneyRunError",
    "MCPAuthority",
    "create_publication_evidence",
    "decode_failure",
    "decode_success",
    "has_backing_correlation",
]
