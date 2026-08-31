from __future__ import annotations

import pytest
from integration.journey.real import (
    _call_is_rejected,  # pyright: ignore[reportPrivateUsage]  # test denial classifier
    _is_rejected,  # pyright: ignore[reportPrivateUsage]  # test denial classifier
)
from integration.journey.security import (
    black_box_security_results,
    host_security_results_from_reports,
    surface_security_results,
)
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult
from tesserix_mcp_publisher import PublicationError, PublicationErrorCode
from tesserix_mcp_testkit import (
    REQUIRED_SECURITY_SURFACES,
    SecurityEvidenceKind,
    SecuritySurface,
)

CI_CASES = {
    "ci.immutable_actions",
    "ci.least_privilege_permissions",
    "ci.untrusted_pull_request",
    "dependency.release_policy",
}
EGRESS_CASES = {
    "egress.alternate_port",
    "egress.dns_rebinding",
    "egress.encoded_ip",
    "egress.ipv6",
    "egress.loopback",
    "egress.metadata",
    "egress.private_range",
    "egress.redirect",
}


def test_host_security_reports_become_exact_payload_free_case_evidence() -> None:
    results = host_security_results_from_reports(
        ci_report=dict.fromkeys(CI_CASES, True),
        ssrf_report={"cases": sorted(EGRESS_CASES), "connections": 5, "passed": True},
    )

    assert {result.case_id for result in results} == CI_CASES | EGRESS_CASES
    assert all(result.passed for result in results)
    assert {result.evidence_kind for result in results if result.case_id in CI_CASES} == {
        SecurityEvidenceKind.STATIC
    }
    assert {result.evidence_kind for result in results if result.case_id in EGRESS_CASES} == {
        SecurityEvidenceKind.ISOLATED_NETWORK
    }
    assert all(
        result.request_id == "ssrf-harness" for result in results if result.case_id in EGRESS_CASES
    )


def test_surface_security_results_bind_every_redaction_case_to_named_bytes() -> None:
    raw = {surface: f"{surface.value}=sanitized".encode() for surface in REQUIRED_SECURITY_SURFACES}

    surfaces, results = surface_security_results(
        raw,
        canaries=("SyntheticSecurityCanary8Kq3",),
    )

    assert tuple(surface.surface for surface in surfaces) == REQUIRED_SECURITY_SURFACES
    assert {result.case_id for result in results} == {
        f"redaction.{surface.value}" for surface in SecuritySurface
    }
    digests = {f"redaction.{surface.surface.value}": surface.digest for surface in surfaces}
    assert all(result.evidence_digest == digests[result.case_id] for result in results)


def test_black_box_observation_can_prove_multiple_boundaries_without_payloads() -> None:
    results = black_box_security_results(
        (
            "tenant.route_non_disclosure",
            "tenant.tool_non_disclosure",
            "tenant.backing_non_disclosure",
        ),
        request_id="request-tenant-other",
        observation={"backing_calls": 0, "disclosures": 0, "rejected": True},
    )

    assert [result.case_id for result in results] == [
        "tenant.backing_non_disclosure",
        "tenant.route_non_disclosure",
        "tenant.tool_non_disclosure",
    ]
    assert all(result.evidence_kind is SecurityEvidenceKind.BLACK_BOX for result in results)
    assert all(result.passed for result in results)
    assert len({result.evidence_digest for result in results}) == 1


async def test_rejection_helpers_do_not_classify_harness_defects_as_denials() -> None:
    async def broken_operation() -> object:
        raise ValueError("synthetic harness defect")

    async def broken_tool_call() -> CallToolResult:
        raise ValueError("synthetic client defect")

    with pytest.raises(ValueError, match="harness defect"):
        await _is_rejected(broken_operation())
    with pytest.raises(ValueError, match="client defect"):
        await _call_is_rejected(broken_tool_call())


async def test_rejection_helpers_accept_only_expected_boundary_failures() -> None:
    async def rejected_publication() -> object:
        raise PublicationError(PublicationErrorCode.MANIFEST_INVALID)

    async def rejected_tool_call() -> CallToolResult:
        raise ExceptionGroup(
            "MCP transport rejection",
            [MCPError(code=-32_000, message="synthetic denial")],
        )

    assert await _is_rejected(rejected_publication())
    assert await _call_is_rejected(rejected_tool_call())
