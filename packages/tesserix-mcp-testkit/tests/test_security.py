from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import cast

import pytest
from tesserix_mcp_testkit import (
    REQUIRED_SECURITY_SURFACES,
    SECURITY_CASES,
    SECURITY_CONTRACT_VERSION,
    JourneyComponent,
    SecurityArea,
    SecurityCase,
    SecurityEvidenceKind,
    SecurityExpectation,
    SecurityFinding,
    SecurityFindingDisposition,
    SecurityReport,
    SecurityReportError,
    SecurityResult,
    SecurityReview,
    SecuritySeverity,
    SecuritySubject,
    SecuritySurface,
    SecuritySurfaceEvidence,
    make_security_result,
    scan_security_surfaces,
)

EXPECTED_CASE_IDS = {
    "authority.approval_replay",
    "authority.claim_disagreement",
    "authority.confirm_bypass",
    "authority.idempotency_replay",
    "authority.scope_escalation",
    "authority.trusted_header_spoof",
    "ci.immutable_actions",
    "ci.least_privilege_permissions",
    "ci.untrusted_pull_request",
    "control_plane.forged_metadata",
    "control_plane.route_scope_missing",
    "control_plane.unsigned_artifact",
    "dependency.release_policy",
    "egress.alternate_port",
    "egress.dns_rebinding",
    "egress.encoded_ip",
    "egress.ipv6",
    "egress.loopback",
    "egress.metadata",
    "egress.private_range",
    "egress.redirect",
    "identity.expired",
    "identity.forged_signature",
    "identity.malformed",
    "identity.revoked_key",
    "identity.verifier_outage_known_key",
    "identity.verifier_outage_unknown_key",
    "identity.wrong_algorithm",
    "identity.wrong_audience",
    "identity.wrong_issuer",
    "redaction.audit",
    "redaction.crash_dump",
    "redaction.errors",
    "redaction.logs",
    "redaction.manifest",
    "redaction.metrics",
    "redaction.release_assets",
    "redaction.results",
    "redaction.sbom",
    "redaction.schema",
    "redaction.semantic_annotations",
    "redaction.traces",
    "tenant.audit_non_disclosure",
    "tenant.backing_non_disclosure",
    "tenant.cache_non_disclosure",
    "tenant.discovery_non_disclosure",
    "tenant.exact_fetch_non_disclosure",
    "tenant.metrics_non_disclosure",
    "tenant.route_non_disclosure",
    "tenant.session_non_reuse",
    "tenant.tool_non_disclosure",
}


def test_security_contract_v1_covers_every_required_adversarial_boundary() -> None:
    assert SECURITY_CONTRACT_VERSION == "1.0"
    assert {case.id for case in SECURITY_CASES} == EXPECTED_CASE_IDS
    assert len(SECURITY_CASES) == len(EXPECTED_CASE_IDS)
    assert all(isinstance(case.area, SecurityArea) for case in SECURITY_CASES)
    assert all(isinstance(case.severity, SecuritySeverity) for case in SECURITY_CASES)
    assert all(isinstance(case.expectation, SecurityExpectation) for case in SECURITY_CASES)
    assert all(isinstance(case.evidence_kind, SecurityEvidenceKind) for case in SECURITY_CASES)
    assert all(case.blocking for case in SECURITY_CASES)


def complete_report() -> SecurityReport:
    surfaces = scan_security_surfaces(
        {surface: f"{surface.value}=sanitized" for surface in REQUIRED_SECURITY_SURFACES},
        canaries=("SyntheticSecurityCanary8Kq3",),
    )
    surface_digests = {f"redaction.{surface.surface.value}": surface.digest for surface in surfaces}
    return SecurityReport(
        run_id="security-20260831-001",
        created_at="2026-08-31T12:34:56Z",
        prepared_by="ci/tesserix-mcp-runtime",
        subject=SecuritySubject(
            source_revision="1" * 40,
            package_digest=f"sha256:{'2' * 64}",
            image_digest=f"sha256:{'3' * 64}",
            manifest_digest=f"sha256:{'4' * 64}",
            sbom_digest=f"sha256:{'5' * 64}",
        ),
        components=(
            JourneyComponent(
                name="agentgateway",
                version="1.4.1",
                revision=f"sha256:{'6' * 64}",
            ),
            JourneyComponent(
                name="agentic-registry",
                version="6921474",
                revision="6921474591b6c59e89025370c310c7f85859246f",
            ),
            JourneyComponent(
                name="tesserix-mcp-runtime",
                version="0.1.0rc1",
                revision=f"sha256:{'3' * 64}",
            ),
        ),
        results=tuple(
            SecurityResult(
                case_id=case.id,
                evidence_kind=case.evidence_kind,
                evidence_digest=surface_digests.get(case.id, f"sha256:{index:064x}"),
                passed=True,
                request_id=f"security-case-{index:03d}",
            )
            for index, case in enumerate(reversed(SECURITY_CASES), start=1)
        ),
        surfaces=surfaces,
    )


def test_complete_security_report_is_canonical_and_binds_exact_subject_digests() -> None:
    encoded = complete_report().to_json()

    document = json.loads(encoded)
    assert document["contract_version"] == "1.0"
    assert document["subject"] == {
        "image_digest": f"sha256:{'3' * 64}",
        "manifest_digest": f"sha256:{'4' * 64}",
        "package_digest": f"sha256:{'2' * 64}",
        "sbom_digest": f"sha256:{'5' * 64}",
        "source_revision": "1" * 40,
    }
    assert [result["case_id"] for result in document["results"]] == sorted(EXPECTED_CASE_IDS)
    assert encoded.endswith(b"\n")
    assert len(encoded) < 1024 * 1024


def test_named_surface_scan_is_complete_digest_bound_and_payload_free() -> None:
    evidence = scan_security_surfaces(
        {surface: f"{surface.value}=sanitized" for surface in reversed(REQUIRED_SECURITY_SURFACES)},
        canaries=("SyntheticSecurityCanary8Kq3",),
    )

    assert all(isinstance(item, SecuritySurfaceEvidence) for item in evidence)
    assert tuple(item.surface for item in evidence) == REQUIRED_SECURITY_SURFACES
    assert {item.surface for item in evidence} == set(SecuritySurface)
    assert all(item.digest.startswith("sha256:") for item in evidence)
    assert all(item.size_bytes > 0 for item in evidence)


def test_redaction_results_must_reference_the_exact_named_surface_digest() -> None:
    report = complete_report()
    results = tuple(
        replace(result, evidence_digest=f"sha256:{'f' * 64}")
        if result.case_id == "redaction.logs"
        else result
        for result in report.results
    )

    with pytest.raises(SecurityReportError) as captured:
        replace(report, results=results).to_json()

    assert captured.value.code == "surface_identity:redaction.logs"


def test_ga_evidence_requires_an_independent_review_bound_to_the_exact_report() -> None:
    report = complete_report()

    with pytest.raises(SecurityReportError) as missing:
        report.to_json(require_independent_review=True)
    assert missing.value.code == "review_missing"

    self_review = SecurityReview(
        reviewer=report.prepared_by,
        reviewed_at="2026-08-31T12:40:00Z",
        scope_digest=report.review_scope_digest(),
        approved=True,
    )
    with pytest.raises(SecurityReportError) as not_independent:
        replace(report, review=self_review).to_json(require_independent_review=True)
    assert not_independent.value.code == "review_not_independent"

    independent = replace(self_review, reviewer="security/reviewer")
    encoded = replace(report, review=independent).to_json(require_independent_review=True)
    assert json.loads(encoded)["review"]["reviewer"] == "security/reviewer"


def test_result_factory_hashes_observed_evidence_without_retaining_the_payload() -> None:
    observed = b'{"status":401,"tool_effects":0,"disclosures":0}'

    result = make_security_result(
        case_id="identity.malformed",
        evidence_kind=SecurityEvidenceKind.BLACK_BOX,
        evidence=observed,
        passed=True,
        request_id="request-malformed-token",
    )

    assert result.evidence_digest == "sha256:" + hashlib.sha256(observed).hexdigest()
    assert observed.decode() not in json.dumps(result.to_document())


def test_failed_blocking_case_requires_an_owned_finding_and_cannot_be_release_evidence() -> None:
    report = complete_report()
    failed_case = "identity.forged_signature"
    failed_results = tuple(
        replace(result, passed=False) if result.case_id == failed_case else result
        for result in report.results
    )

    with pytest.raises(SecurityReportError) as captured:
        replace(report, results=failed_results).to_json()

    assert captured.value.code == f"finding_missing:{failed_case}"
    assert str(captured.value) == f"security_report:finding_missing:{failed_case}"


def test_failed_blocking_case_remains_blocked_after_owned_remediation_is_recorded() -> None:
    report = complete_report()
    failed_case = "identity.forged_signature"
    failed_results = tuple(
        replace(result, passed=False) if result.case_id == failed_case else result
        for result in report.results
    )
    failed_result = next(result for result in failed_results if result.case_id == failed_case)
    finding = SecurityFinding(
        id="SEC-0001",
        case_id=failed_case,
        severity=SecuritySeverity.CRITICAL,
        disposition=SecurityFindingDisposition.REMEDIATED,
        owner="security/runtime",
        remediation="Retest the forged-signature denial through the pinned gateway.",
        retest_digest=failed_result.evidence_digest,
    )

    with pytest.raises(SecurityReportError) as captured:
        replace(report, results=failed_results, findings=(finding,)).to_json()

    assert captured.value.code == f"failed:{failed_case}"


@pytest.mark.parametrize(
    "factory",
    (
        lambda: SecurityCase(
            id="invalid",
            area=SecurityArea.IDENTITY,
            severity=SecuritySeverity.CRITICAL,
            expectation=SecurityExpectation.DENIED_BEFORE_EFFECT,
            evidence_kind=SecurityEvidenceKind.BLACK_BOX,
        ),
        lambda: SecuritySubject(
            source_revision="not-a-revision",
            package_digest=f"sha256:{'2' * 64}",
            image_digest=f"sha256:{'3' * 64}",
            manifest_digest=f"sha256:{'4' * 64}",
            sbom_digest=f"sha256:{'5' * 64}",
        ),
        lambda: SecurityResult(
            case_id="identity.malformed",
            evidence_kind=SecurityEvidenceKind.BLACK_BOX,
            evidence_digest=f"sha256:{'1' * 64}",
            passed=True,
        ),
        lambda: SecurityFinding(
            id="invalid",
            case_id="identity.malformed",
            severity=SecuritySeverity.CRITICAL,
            disposition=SecurityFindingDisposition.OPEN,
            owner="security/runtime",
            remediation="Investigate the denial boundary.",
        ),
        lambda: SecuritySurfaceEvidence(
            surface=SecuritySurface.LOG,
            digest=f"sha256:{'1' * 64}",
            size_bytes=-1,
        ),
        lambda: SecurityReview(
            reviewer="invalid reviewer",
            reviewed_at="2026-08-31T12:40:00Z",
            scope_digest=f"sha256:{'1' * 64}",
            approved=True,
        ),
    ),
    ids=("case", "subject", "result", "finding", "surface", "review"),
)
def test_security_models_reject_ambiguous_or_unbounded_values(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ValueError):
        factory()


def test_result_factory_rejects_unknown_mismatched_unbounded_and_secret_evidence() -> None:
    with pytest.raises(SecurityReportError) as unknown:
        make_security_result(
            case_id="identity.unknown",
            evidence_kind=SecurityEvidenceKind.BLACK_BOX,
            evidence=b"denied",
            passed=True,
            request_id="request-unknown",
        )
    assert unknown.value.code == "unknown_case"

    with pytest.raises(SecurityReportError) as wrong_kind:
        make_security_result(
            case_id="identity.malformed",
            evidence_kind=SecurityEvidenceKind.STATIC,
            evidence=b"denied",
            passed=True,
            request_id="request-wrong-kind",
        )
    assert wrong_kind.value.code == "evidence_kind:identity.malformed"

    with pytest.raises(SecurityReportError) as wrong_value:
        make_security_result(
            case_id="identity.malformed",
            evidence_kind=SecurityEvidenceKind.BLACK_BOX,
            evidence=cast(str | bytes, object()),
            passed=True,
            request_id="request-wrong-value",
        )
    assert wrong_value.value.code == "evidence_value"

    with pytest.raises(SecurityReportError) as empty:
        make_security_result(
            case_id="identity.malformed",
            evidence_kind=SecurityEvidenceKind.BLACK_BOX,
            evidence=b"",
            passed=True,
            request_id="request-empty",
        )
    assert empty.value.code == "evidence_bounds"

    with pytest.raises(SecurityReportError) as forbidden:
        make_security_result(
            case_id="identity.malformed",
            evidence_kind=SecurityEvidenceKind.BLACK_BOX,
            evidence="SyntheticSecurityCanary8Kq3",
            passed=True,
            request_id="request-forbidden",
            canaries=("SyntheticSecurityCanary8Kq3",),
        )
    assert forbidden.value.code == "forbidden_material"


def test_surface_scanner_rejects_incomplete_invalid_unbounded_and_secret_sinks() -> None:
    valid = dict.fromkeys(REQUIRED_SECURITY_SURFACES, b"sanitized")

    with pytest.raises(SecurityReportError) as incomplete:
        scan_security_surfaces({SecuritySurface.LOG: b"sanitized"})
    assert incomplete.value.code == "surface_set"

    invalid = dict(valid)
    invalid[SecuritySurface.LOG] = cast(bytes, object())
    with pytest.raises(SecurityReportError) as invalid_value:
        scan_security_surfaces(cast(Mapping[SecuritySurface, str | bytes], invalid))
    assert invalid_value.value.code == "surface_value"

    oversized = dict(valid)
    oversized[SecuritySurface.LOG] = b"x" * (1024 * 1024 + 1)
    with pytest.raises(SecurityReportError) as too_large:
        scan_security_surfaces(oversized)
    assert too_large.value.code == "surface_bounds"

    secret = dict(valid)
    secret[SecuritySurface.LOG] = b"SyntheticSecurityCanary8Kq3"
    with pytest.raises(SecurityReportError) as forbidden:
        scan_security_surfaces(
            secret,
            canaries=("SyntheticSecurityCanary8Kq3",),
        )
    assert forbidden.value.code == "forbidden_material"


def test_report_rejects_missing_unexpected_and_incomplete_evidence_sets() -> None:
    report = complete_report()
    missing_case = sorted(EXPECTED_CASE_IDS)[0]
    missing_results = tuple(result for result in report.results if result.case_id != missing_case)
    with pytest.raises(SecurityReportError) as missing:
        replace(report, results=missing_results).to_json()
    assert missing.value.code == f"missing:{missing_case}"

    unexpected_result = SecurityResult(
        case_id="custom.unknown",
        evidence_kind=SecurityEvidenceKind.STATIC,
        evidence_digest=f"sha256:{'a' * 64}",
        passed=True,
    )
    with pytest.raises(SecurityReportError) as unexpected:
        replace(report, results=(*report.results, unexpected_result)).to_json()
    assert unexpected.value.code == "unexpected:custom.unknown"

    missing_surface = REQUIRED_SECURITY_SURFACES[0]
    incomplete_surfaces = tuple(
        surface for surface in report.surfaces if surface.surface is not missing_surface
    )
    with pytest.raises(SecurityReportError) as incomplete:
        replace(report, surfaces=incomplete_surfaces).to_json()
    assert incomplete.value.code == f"surface_missing:{missing_surface.value}"


def test_report_enforces_finding_ownership_severity_disposition_and_retest() -> None:
    report = complete_report()
    case_id = "identity.malformed"
    result = next(item for item in report.results if item.case_id == case_id)
    base = SecurityFinding(
        id="SEC-0001",
        case_id=case_id,
        severity=SecuritySeverity.CRITICAL,
        disposition=SecurityFindingDisposition.REMEDIATED,
        owner="security/runtime",
        remediation="Retest the malformed-token denial through the pinned gateway.",
        retest_digest=result.evidence_digest,
    )

    unknown = replace(
        base,
        case_id="custom.unknown",
        severity=SecuritySeverity.HIGH,
    )
    with pytest.raises(SecurityReportError) as unknown_case:
        replace(report, findings=(unknown,)).to_json()
    assert unknown_case.value.code == "finding_case:custom.unknown"

    with pytest.raises(SecurityReportError) as wrong_severity:
        replace(report, findings=(replace(base, severity=SecuritySeverity.HIGH),)).to_json()
    assert wrong_severity.value.code == "finding_severity:SEC-0001"

    open_finding = replace(
        base,
        disposition=SecurityFindingDisposition.OPEN,
        retest_digest="",
    )
    with pytest.raises(SecurityReportError) as still_open:
        replace(report, findings=(open_finding,)).to_json()
    assert still_open.value.code == "finding_open:SEC-0001"

    with pytest.raises(SecurityReportError) as wrong_retest:
        replace(
            report,
            findings=(replace(base, retest_digest=f"sha256:{'f' * 64}"),),
        ).to_json()
    assert wrong_retest.value.code == "finding_retest:SEC-0001"

    document = json.loads(replace(report, findings=(base,)).to_json())
    assert document["findings"] == [base.to_document()]


def test_report_rejects_evidence_kind_drift_and_runtime_digest_drift() -> None:
    report = complete_report()
    changed_results = tuple(
        replace(result, evidence_kind=SecurityEvidenceKind.STATIC)
        if result.case_id == "identity.malformed"
        else result
        for result in report.results
    )
    with pytest.raises(SecurityReportError) as wrong_kind:
        replace(report, results=changed_results).to_json()
    assert wrong_kind.value.code == "evidence_kind:identity.malformed"

    changed_components = tuple(
        replace(component, revision=f"sha256:{'f' * 64}")
        if component.name == "tesserix-mcp-runtime"
        else component
        for component in report.components
    )
    with pytest.raises(SecurityReportError) as wrong_runtime:
        replace(report, components=changed_components).to_json()
    assert wrong_runtime.value.code == "runtime_identity"


def test_review_policy_rejects_denial_stale_scope_and_pre_evidence_timestamps() -> None:
    report = complete_report()
    review = SecurityReview(
        reviewer="security/reviewer",
        reviewed_at="2026-08-31T12:40:00Z",
        scope_digest=report.review_scope_digest(),
        approved=True,
    )

    with pytest.raises(TypeError, match="must be boolean"):
        report.to_json(require_independent_review=cast(bool, "yes"))

    with pytest.raises(SecurityReportError) as denied:
        replace(report, review=replace(review, approved=False)).to_json()
    assert denied.value.code == "review_not_approved"

    with pytest.raises(SecurityReportError) as early:
        replace(
            report,
            review=replace(review, reviewed_at="2026-08-31T12:00:00Z"),
        ).to_json()
    assert early.value.code == "review_timestamp"

    with pytest.raises(SecurityReportError) as wrong_scope:
        replace(
            report,
            review=replace(review, scope_digest=f"sha256:{'f' * 64}"),
        ).to_json()
    assert wrong_scope.value.code == "review_scope"


def test_report_constructor_rejects_duplicate_component_identities() -> None:
    report = complete_report()

    with pytest.raises(ValueError, match="bounded immutable values"):
        replace(report, components=(*report.components, report.components[0]))
