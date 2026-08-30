from __future__ import annotations

import json
from pathlib import Path

import pytest
from integration.journey.runner import (
    JourneyRunError,
    MCPAuthority,
    create_publication_evidence,
    decode_failure,
    decode_success,
    has_backing_correlation,
)
from mcp.types import CallToolResult, TextContent

from tesserix_mcp_runtime import SecretValue

TRACE_ID = "1" * 32
TRACEPARENT = f"00-{TRACE_ID}-{'2' * 16}-01"


def test_mcp_authority_builds_exact_per_request_headers_without_rendering_token() -> None:
    authority = MCPAuthority(
        token=SecretValue("header.payload.signature"),
        run_id="journey-run-001",
    )

    headers = authority.headers(
        request_id="request-write-001",
        traceparent=TRACEPARENT,
        timeout_ms=250,
        idempotency_key="write-order-001",
        approval_id="approval-order-001",
    )

    assert headers == {
        "authorization": "Bearer header.payload.signature",
        "idempotency-key": "write-order-001",
        "traceparent": TRACEPARENT,
        "x-request-id": "request-write-001",
        "x-tesserix-approval-id": "approval-order-001",
        "x-tesserix-run-id": "journey-run-001",
        "x-tesserix-timeout-ms": "250",
    }
    assert "header.payload.signature" not in repr(authority)


@pytest.mark.parametrize(
    ("request_id", "traceparent", "timeout_ms"),
    [
        ("", TRACEPARENT, 250),
        ("request-001", "00-bad", 250),
        ("request-001", TRACEPARENT, 0),
        ("request-001", TRACEPARENT, 300_001),
    ],
    ids=["request", "trace", "zero-timeout", "unbounded-timeout"],
)
def test_mcp_authority_rejects_ambiguous_request_authority(
    request_id: str,
    traceparent: str,
    timeout_ms: int,
) -> None:
    authority = MCPAuthority(token=SecretValue("header.payload.signature"), run_id="run-001")

    with pytest.raises(ValueError, match="invocation authority"):
        authority.headers(
            request_id=request_id,
            traceparent=traceparent,
            timeout_ms=timeout_ms,
        )


def test_tool_result_decoders_require_consistent_bounded_documents() -> None:
    value = {"order_id": "order-001", "status": "missing"}
    success = CallToolResult(
        content=[TextContent(type="text", text=json.dumps(value, sort_keys=True))],
        structured_content=value,
        is_error=False,
    )
    failure = CallToolResult(
        content=[
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "code": "approval_required",
                        "message": "Approval is required.",
                        "request_id": "request-approval-001",
                        "retryability": "never",
                    },
                    sort_keys=True,
                ),
            )
        ],
        is_error=True,
    )

    assert decode_success(success) == value
    assert decode_failure(failure) == "approval_required"


def test_backing_correlation_uses_the_sanitized_nested_context() -> None:
    observations = [
        {
            "context": {
                "request_id": "request-write-001",
                "trace_id": TRACE_ID,
            },
            "operation": "write",
            "replayed": False,
        }
    ]

    assert has_backing_correlation(
        observations,
        request_id="request-write-001",
        trace_id=TRACE_ID,
    )
    assert not has_backing_correlation(
        [{"request_id": "request-write-001", "trace_id": TRACE_ID}],
        request_id="request-write-001",
        trace_id=TRACE_ID,
    )


@pytest.mark.parametrize(
    "result",
    [
        CallToolResult(content=[], structured_content={}, is_error=False),
        CallToolResult(
            content=[TextContent(type="text", text='{"value":1}')],
            structured_content={"value": 2},
            is_error=False,
        ),
        CallToolResult(
            content=[TextContent(type="text", text='{"code":"failure"}')],
            is_error=False,
        ),
    ],
    ids=["missing-content", "inconsistent", "wrong-status"],
)
def test_success_decoder_fails_closed_on_gateway_contract_drift(result: CallToolResult) -> None:
    with pytest.raises(JourneyRunError, match="journey_run:tool_result_invalid"):
        decode_success(result)


def test_publication_evidence_is_canonical_digest_bound_and_locally_retained(
    tmp_path: Path,
) -> None:
    artifact_digest = "sha256:" + "a" * 64

    evidence = create_publication_evidence(
        output_dir=tmp_path,
        artifact_digest=artifact_digest,
        created_at="2026-08-31T12:34:56Z",
    )

    sbom = (tmp_path / "journey.spdx.json").read_bytes()
    provenance = (tmp_path / "journey.intoto.json").read_bytes()
    sbom_document = json.loads(sbom)
    provenance_document = json.loads(provenance)
    assert sbom.endswith(b"\n")
    assert provenance.endswith(b"\n")
    assert sbom_document["packages"][0]["checksums"] == [
        {"algorithm": "SHA256", "checksumValue": "a" * 64}
    ]
    assert provenance_document["subject"][0]["digest"] == {"sha256": "a" * 64}
    assert evidence.artifact.digest == artifact_digest
    assert evidence.sbom.digest.startswith("sha256:")
    assert evidence.provenance.digest.startswith("sha256:")
    assert evidence.sbom.digest != evidence.provenance.digest
