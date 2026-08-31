from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, cast

from tesserix_mcp_runtime import JsonValue
from tesserix_mcp_testkit.journey import (
    JourneyComponent,
    JourneyEvidenceError,
    scan_journey_surfaces,
)

SECURITY_CONTRACT_VERSION: Final = "1.0"

_CASE_ID = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\Z")
_FINDING_ID = re.compile(r"SEC-[0-9]{4}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TIMESTAMP = re.compile(
    r"(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
_MAX_REPORT_BYTES = 1024 * 1024
_MAX_SURFACE_BYTES = 1024 * 1024
_OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@+-]{0,127}\Z")


def _is_runtime_instance(
    value: object,
    expected: type[Any] | tuple[type[Any], ...],
) -> bool:
    return isinstance(value, expected)


class SecurityArea(StrEnum):
    TENANCY = "tenancy"
    IDENTITY = "identity"
    AUTHORITY = "authority"
    EGRESS = "egress"
    REDACTION = "redaction"
    CONTROL_PLANE = "control_plane"
    SUPPLY_CHAIN = "supply_chain"


class SecuritySeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SecurityExpectation(StrEnum):
    NON_DISCLOSING_DENIAL = "non_disclosing_denial"
    DENIED_BEFORE_EFFECT = "denied_before_effect"
    AUTHORITY_UNCHANGED = "authority_unchanged"
    ONE_EFFECT_REPLAYED = "one_effect_replayed"
    CONNECTION_BLOCKED = "connection_blocked"
    CANARY_ABSENT = "canary_absent"
    ACTIVATION_BLOCKED = "activation_blocked"
    POLICY_ENFORCED = "policy_enforced"
    BOUNDED_LOCAL_VERIFICATION = "bounded_local_verification"


class SecurityEvidenceKind(StrEnum):
    BLACK_BOX = "black_box"
    ISOLATED_NETWORK = "isolated_network"
    ARTIFACT = "artifact"
    STATIC = "static"


class SecurityFindingDisposition(StrEnum):
    OPEN = "open"
    REMEDIATED = "remediated"


class SecuritySurface(StrEnum):
    MANIFEST = "manifest"
    SEMANTIC_ANNOTATIONS = "semantic_annotations"
    SCHEMA = "schema"
    ERROR = "errors"
    RESULT = "results"
    LOG = "logs"
    TRACE = "traces"
    METRIC = "metrics"
    AUDIT = "audit"
    CRASH_DUMP = "crash_dump"
    SBOM = "sbom"
    RELEASE_ASSET = "release_assets"


REQUIRED_SECURITY_SURFACES: Final = tuple(SecuritySurface)


@dataclass(frozen=True, slots=True, kw_only=True)
class SecurityCase:
    id: str
    area: SecurityArea
    severity: SecuritySeverity
    expectation: SecurityExpectation
    evidence_kind: SecurityEvidenceKind
    blocking: bool = True

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.id, str)
            or _CASE_ID.fullmatch(self.id) is None
            or not _is_runtime_instance(self.area, SecurityArea)
            or not _is_runtime_instance(self.severity, SecuritySeverity)
            or not _is_runtime_instance(self.expectation, SecurityExpectation)
            or not _is_runtime_instance(self.evidence_kind, SecurityEvidenceKind)
            or not _is_runtime_instance(self.blocking, bool)
        ):
            raise ValueError("security case must use bounded contract values")


def _case(
    case_id: str,
    area: SecurityArea,
    severity: SecuritySeverity,
    expectation: SecurityExpectation,
) -> SecurityCase:
    return SecurityCase(
        id=case_id,
        area=area,
        severity=severity,
        expectation=expectation,
        evidence_kind=_required_evidence(case_id, area),
    )


def _required_evidence(case_id: str, area: SecurityArea) -> SecurityEvidenceKind:
    if area in {
        SecurityArea.TENANCY,
        SecurityArea.IDENTITY,
        SecurityArea.AUTHORITY,
        SecurityArea.CONTROL_PLANE,
    }:
        return SecurityEvidenceKind.BLACK_BOX
    if area is SecurityArea.EGRESS:
        return SecurityEvidenceKind.ISOLATED_NETWORK
    if area is SecurityArea.REDACTION and case_id in {
        "redaction.manifest",
        "redaction.release_assets",
        "redaction.sbom",
        "redaction.schema",
        "redaction.semantic_annotations",
    }:
        return SecurityEvidenceKind.ARTIFACT
    if area is SecurityArea.REDACTION:
        return SecurityEvidenceKind.BLACK_BOX
    return SecurityEvidenceKind.STATIC


SECURITY_CASES: Final = (
    *(
        _case(
            case_id,
            SecurityArea.TENANCY,
            SecuritySeverity.CRITICAL,
            SecurityExpectation.NON_DISCLOSING_DENIAL,
        )
        for case_id in (
            "tenant.audit_non_disclosure",
            "tenant.backing_non_disclosure",
            "tenant.cache_non_disclosure",
            "tenant.discovery_non_disclosure",
            "tenant.exact_fetch_non_disclosure",
            "tenant.metrics_non_disclosure",
            "tenant.route_non_disclosure",
            "tenant.session_non_reuse",
            "tenant.tool_non_disclosure",
        )
    ),
    *(
        _case(
            case_id,
            SecurityArea.IDENTITY,
            SecuritySeverity.CRITICAL,
            SecurityExpectation.DENIED_BEFORE_EFFECT,
        )
        for case_id in (
            "identity.expired",
            "identity.forged_signature",
            "identity.malformed",
            "identity.revoked_key",
            "identity.verifier_outage_unknown_key",
            "identity.wrong_algorithm",
            "identity.wrong_audience",
            "identity.wrong_issuer",
        )
    ),
    _case(
        "identity.verifier_outage_known_key",
        SecurityArea.IDENTITY,
        SecuritySeverity.HIGH,
        SecurityExpectation.BOUNDED_LOCAL_VERIFICATION,
    ),
    *(
        _case(
            case_id,
            SecurityArea.AUTHORITY,
            SecuritySeverity.CRITICAL,
            SecurityExpectation.DENIED_BEFORE_EFFECT,
        )
        for case_id in (
            "authority.approval_replay",
            "authority.claim_disagreement",
            "authority.confirm_bypass",
            "authority.scope_escalation",
        )
    ),
    _case(
        "authority.trusted_header_spoof",
        SecurityArea.AUTHORITY,
        SecuritySeverity.CRITICAL,
        SecurityExpectation.AUTHORITY_UNCHANGED,
    ),
    _case(
        "authority.idempotency_replay",
        SecurityArea.AUTHORITY,
        SecuritySeverity.CRITICAL,
        SecurityExpectation.ONE_EFFECT_REPLAYED,
    ),
    *(
        _case(
            case_id,
            SecurityArea.EGRESS,
            SecuritySeverity.HIGH,
            SecurityExpectation.CONNECTION_BLOCKED,
        )
        for case_id in (
            "egress.alternate_port",
            "egress.dns_rebinding",
            "egress.encoded_ip",
            "egress.ipv6",
            "egress.loopback",
            "egress.metadata",
            "egress.private_range",
            "egress.redirect",
        )
    ),
    *(
        _case(
            case_id,
            SecurityArea.REDACTION,
            SecuritySeverity.HIGH,
            SecurityExpectation.CANARY_ABSENT,
        )
        for case_id in (
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
        )
    ),
    *(
        _case(
            case_id,
            SecurityArea.CONTROL_PLANE,
            SecuritySeverity.CRITICAL,
            SecurityExpectation.ACTIVATION_BLOCKED,
        )
        for case_id in (
            "control_plane.forged_metadata",
            "control_plane.route_scope_missing",
            "control_plane.unsigned_artifact",
        )
    ),
    *(
        _case(
            case_id,
            SecurityArea.SUPPLY_CHAIN,
            SecuritySeverity.HIGH,
            SecurityExpectation.POLICY_ENFORCED,
        )
        for case_id in (
            "ci.immutable_actions",
            "ci.least_privilege_permissions",
            "ci.untrusted_pull_request",
            "dependency.release_policy",
        )
    ),
)

_SECURITY_CASES_BY_ID: Final = {case.id: case for case in SECURITY_CASES}


class SecurityReportError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"security_report:{code}")


@dataclass(frozen=True, slots=True, kw_only=True)
class SecuritySubject:
    source_revision: str
    package_digest: str
    image_digest: str
    manifest_digest: str
    sbom_digest: str

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.source_revision, str)
            or _REVISION.fullmatch(self.source_revision) is None
            or any(
                not _is_runtime_instance(value, str) or _DIGEST.fullmatch(value) is None
                for value in (
                    self.package_digest,
                    self.image_digest,
                    self.manifest_digest,
                    self.sbom_digest,
                )
            )
        ):
            raise ValueError("security subject must use exact immutable identities")

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "image_digest": self.image_digest,
            "manifest_digest": self.manifest_digest,
            "package_digest": self.package_digest,
            "sbom_digest": self.sbom_digest,
            "source_revision": self.source_revision,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SecurityResult:
    case_id: str
    evidence_kind: SecurityEvidenceKind
    evidence_digest: str
    passed: bool
    request_id: str = ""

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.case_id, str)
            or _CASE_ID.fullmatch(self.case_id) is None
            or not _is_runtime_instance(self.evidence_kind, SecurityEvidenceKind)
            or not _is_runtime_instance(self.evidence_digest, str)
            or _DIGEST.fullmatch(self.evidence_digest) is None
            or not _is_runtime_instance(self.passed, bool)
            or not _is_runtime_instance(self.request_id, str)
            or (self.request_id != "" and _REQUEST_ID.fullmatch(self.request_id) is None)
            or (
                self.evidence_kind
                in {SecurityEvidenceKind.BLACK_BOX, SecurityEvidenceKind.ISOLATED_NETWORK}
                and self.request_id == ""
            )
        ):
            raise ValueError("security result must use bounded evidence values")

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "case_id": self.case_id,
            "evidence_digest": self.evidence_digest,
            "evidence_kind": self.evidence_kind.value,
            "passed": self.passed,
            "request_id": self.request_id,
        }


def make_security_result(
    *,
    case_id: str,
    evidence_kind: SecurityEvidenceKind,
    evidence: str | bytes,
    passed: bool,
    request_id: str = "",
    canaries: tuple[str, ...] = (),
) -> SecurityResult:
    case = _SECURITY_CASES_BY_ID.get(case_id)
    if case is None:
        raise SecurityReportError("unknown_case")
    if evidence_kind is not case.evidence_kind:
        raise SecurityReportError(f"evidence_kind:{case_id}")
    if _is_runtime_instance(evidence, str):
        encoded = cast(str, evidence).encode()
    elif _is_runtime_instance(evidence, bytes):
        encoded = cast(bytes, evidence)
    else:
        raise SecurityReportError("evidence_value")
    if not 1 <= len(encoded) <= _MAX_SURFACE_BYTES:
        raise SecurityReportError("evidence_bounds")
    try:
        scan_journey_surfaces((encoded,), canaries=canaries)
    except JourneyEvidenceError:
        raise SecurityReportError("forbidden_material") from None
    return SecurityResult(
        case_id=case_id,
        evidence_kind=evidence_kind,
        evidence_digest="sha256:" + hashlib.sha256(encoded).hexdigest(),
        passed=passed,
        request_id=request_id,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class SecurityFinding:
    id: str
    case_id: str
    severity: SecuritySeverity
    disposition: SecurityFindingDisposition
    owner: str
    remediation: str
    retest_digest: str = ""

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.id, str)
            or _FINDING_ID.fullmatch(self.id) is None
            or not _is_runtime_instance(self.case_id, str)
            or _CASE_ID.fullmatch(self.case_id) is None
            or not _is_runtime_instance(self.severity, SecuritySeverity)
            or not _is_runtime_instance(self.disposition, SecurityFindingDisposition)
            or not _is_runtime_instance(self.owner, str)
            or _OWNER.fullmatch(self.owner) is None
            or not _is_runtime_instance(self.remediation, str)
            or not 1 <= len(self.remediation) <= 2_048
            or self.remediation != self.remediation.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in self.remediation)
            or not _is_runtime_instance(self.retest_digest, str)
            or (self.disposition is SecurityFindingDisposition.OPEN and self.retest_digest != "")
            or (
                self.disposition is SecurityFindingDisposition.REMEDIATED
                and _DIGEST.fullmatch(self.retest_digest) is None
            )
        ):
            raise ValueError("security finding must carry bounded remediation evidence")

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "case_id": self.case_id,
            "disposition": self.disposition.value,
            "id": self.id,
            "owner": self.owner,
            "remediation": self.remediation,
            "retest_digest": self.retest_digest,
            "severity": self.severity.value,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SecuritySurfaceEvidence:
    surface: SecuritySurface
    digest: str
    size_bytes: int

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.surface, SecuritySurface)
            or not _is_runtime_instance(self.digest, str)
            or _DIGEST.fullmatch(self.digest) is None
            or _is_runtime_instance(self.size_bytes, bool)
            or not _is_runtime_instance(self.size_bytes, int)
            or not 0 <= self.size_bytes <= _MAX_SURFACE_BYTES
        ):
            raise ValueError("security surface evidence must be exact and bounded")

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "digest": self.digest,
            "size_bytes": self.size_bytes,
            "surface": self.surface.value,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SecurityReview:
    reviewer: str
    reviewed_at: str
    scope_digest: str
    approved: bool

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.reviewer, str)
            or _OWNER.fullmatch(self.reviewer) is None
            or not _is_runtime_instance(self.reviewed_at, str)
            or _TIMESTAMP.fullmatch(self.reviewed_at) is None
            or not _is_runtime_instance(self.scope_digest, str)
            or _DIGEST.fullmatch(self.scope_digest) is None
            or not _is_runtime_instance(self.approved, bool)
        ):
            raise ValueError("security review must use bounded immutable evidence")

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "approved": self.approved,
            "reviewed_at": self.reviewed_at,
            "reviewer": self.reviewer,
            "scope_digest": self.scope_digest,
        }


def scan_security_surfaces(
    surfaces: Mapping[SecuritySurface, str | bytes],
    *,
    canaries: tuple[str, ...] = (),
) -> tuple[SecuritySurfaceEvidence, ...]:
    if not _is_runtime_instance(surfaces, Mapping) or set(surfaces) != set(
        REQUIRED_SECURITY_SURFACES
    ):
        raise SecurityReportError("surface_set")
    raw: list[bytes] = []
    evidence: list[SecuritySurfaceEvidence] = []
    for surface in REQUIRED_SECURITY_SURFACES:
        value = surfaces[surface]
        if _is_runtime_instance(value, str):
            encoded = cast(str, value).encode()
        elif _is_runtime_instance(value, bytes):
            encoded = cast(bytes, value)
        else:
            raise SecurityReportError("surface_value")
        if len(encoded) > _MAX_SURFACE_BYTES:
            raise SecurityReportError("surface_bounds")
        raw.append(encoded)
        evidence.append(
            SecuritySurfaceEvidence(
                surface=surface,
                digest="sha256:" + hashlib.sha256(encoded).hexdigest(),
                size_bytes=len(encoded),
            )
        )
    try:
        scan_journey_surfaces(raw, canaries=canaries)
    except JourneyEvidenceError:
        raise SecurityReportError("forbidden_material") from None
    return tuple(evidence)


@dataclass(frozen=True, slots=True, kw_only=True)
class SecurityReport:
    run_id: str
    created_at: str
    prepared_by: str
    subject: SecuritySubject
    components: tuple[JourneyComponent, ...]
    results: tuple[SecurityResult, ...]
    surfaces: tuple[SecuritySurfaceEvidence, ...]
    findings: tuple[SecurityFinding, ...] = ()
    review: SecurityReview | None = None

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.run_id, str)
            or _RUN_ID.fullmatch(self.run_id) is None
            or not _is_runtime_instance(self.created_at, str)
            or _TIMESTAMP.fullmatch(self.created_at) is None
            or not _is_runtime_instance(self.prepared_by, str)
            or _OWNER.fullmatch(self.prepared_by) is None
            or not _is_runtime_instance(self.subject, SecuritySubject)
            or not _is_runtime_instance(self.components, tuple)
            or not 1 <= len(self.components) <= 32
            or any(
                not _is_runtime_instance(component, JourneyComponent)
                for component in self.components
            )
            or len({component.name for component in self.components}) != len(self.components)
            or not _is_runtime_instance(self.results, tuple)
            or not 1 <= len(self.results) <= 128
            or any(not _is_runtime_instance(result, SecurityResult) for result in self.results)
            or len({result.case_id for result in self.results}) != len(self.results)
            or not _is_runtime_instance(self.surfaces, tuple)
            or any(
                not _is_runtime_instance(surface, SecuritySurfaceEvidence)
                for surface in self.surfaces
            )
            or len({surface.surface for surface in self.surfaces}) != len(self.surfaces)
            or not _is_runtime_instance(self.findings, tuple)
            or len(self.findings) > 128
            or any(not _is_runtime_instance(finding, SecurityFinding) for finding in self.findings)
            or len({finding.id for finding in self.findings}) != len(self.findings)
            or len({finding.case_id for finding in self.findings}) != len(self.findings)
            or (self.review is not None and not _is_runtime_instance(self.review, SecurityReview))
        ):
            raise ValueError("security report must use bounded immutable values")

    def _assert_complete(self, *, require_independent_review: bool) -> None:
        if not _is_runtime_instance(require_independent_review, bool):
            raise TypeError("require_independent_review must be boolean")
        by_case = {result.case_id: result for result in self.results}
        missing = sorted(set(_SECURITY_CASES_BY_ID).difference(by_case))
        if missing:
            raise SecurityReportError(f"missing:{missing[0]}")
        unexpected = sorted(set(by_case).difference(_SECURITY_CASES_BY_ID))
        if unexpected:
            raise SecurityReportError(f"unexpected:{unexpected[0]}")
        observed_surfaces = {surface.surface for surface in self.surfaces}
        missing_surfaces = [
            surface.value
            for surface in REQUIRED_SECURITY_SURFACES
            if surface not in observed_surfaces
        ]
        if missing_surfaces:
            raise SecurityReportError(f"surface_missing:{missing_surfaces[0]}")
        surface_digests = {
            f"redaction.{surface.surface.value}": surface.digest for surface in self.surfaces
        }
        findings = {finding.case_id: finding for finding in self.findings}
        unexpected_findings = sorted(set(findings).difference(_SECURITY_CASES_BY_ID))
        if unexpected_findings:
            raise SecurityReportError(f"finding_case:{unexpected_findings[0]}")
        for case in SECURITY_CASES:
            result = by_case[case.id]
            if result.evidence_kind is not case.evidence_kind:
                raise SecurityReportError(f"evidence_kind:{case.id}")
            if case.area is SecurityArea.REDACTION and (
                result.evidence_digest != surface_digests.get(case.id)
            ):
                raise SecurityReportError(f"surface_identity:{case.id}")
            finding = findings.get(case.id)
            if not result.passed and finding is None:
                raise SecurityReportError(f"finding_missing:{case.id}")
            if finding is not None:
                if finding.severity is not case.severity:
                    raise SecurityReportError(f"finding_severity:{finding.id}")
                if finding.disposition is SecurityFindingDisposition.OPEN:
                    raise SecurityReportError(f"finding_open:{finding.id}")
                if finding.retest_digest != result.evidence_digest:
                    raise SecurityReportError(f"finding_retest:{finding.id}")
            if case.blocking and not result.passed:
                raise SecurityReportError(f"failed:{case.id}")
        runtime = next(
            (
                component
                for component in self.components
                if component.name == "tesserix-mcp-runtime"
            ),
            None,
        )
        if runtime is None or runtime.revision != self.subject.image_digest:
            raise SecurityReportError("runtime_identity")
        if self.review is None:
            if require_independent_review:
                raise SecurityReportError("review_missing")
            return
        if self.review.reviewer == self.prepared_by:
            raise SecurityReportError("review_not_independent")
        if not self.review.approved:
            raise SecurityReportError("review_not_approved")
        if self.review.reviewed_at < self.created_at:
            raise SecurityReportError("review_timestamp")
        if self.review.scope_digest != self.review_scope_digest():
            raise SecurityReportError("review_scope")

    def _scope_document(self) -> dict[str, JsonValue]:
        return {
            "components": [
                component.to_document()
                for component in sorted(self.components, key=lambda value: value.name)
            ],
            "contract_version": SECURITY_CONTRACT_VERSION,
            "created_at": self.created_at,
            "findings": [
                finding.to_document()
                for finding in sorted(self.findings, key=lambda value: value.id)
            ],
            "results": [
                result.to_document()
                for result in sorted(self.results, key=lambda value: value.case_id)
            ],
            "prepared_by": self.prepared_by,
            "run_id": self.run_id,
            "surfaces": [
                surface.to_document()
                for surface in sorted(self.surfaces, key=lambda value: value.surface.value)
            ],
            "subject": self.subject.to_document(),
        }

    def review_scope_digest(self) -> str:
        encoded = json.dumps(
            self._scope_document(),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def to_document(
        self,
        *,
        require_independent_review: bool = False,
    ) -> dict[str, JsonValue]:
        self._assert_complete(require_independent_review=require_independent_review)
        return {
            **self._scope_document(),
            "review": None if self.review is None else self.review.to_document(),
        }

    def to_json(self, *, require_independent_review: bool = False) -> bytes:
        encoded = (
            json.dumps(
                self.to_document(require_independent_review=require_independent_review),
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            + b"\n"
        )
        if len(encoded) > _MAX_REPORT_BYTES:
            raise SecurityReportError("report_too_large")
        return encoded


__all__ = [
    "REQUIRED_SECURITY_SURFACES",
    "SECURITY_CASES",
    "SECURITY_CONTRACT_VERSION",
    "SecurityArea",
    "SecurityCase",
    "SecurityEvidenceKind",
    "SecurityExpectation",
    "SecurityFinding",
    "SecurityFindingDisposition",
    "SecurityReport",
    "SecurityReportError",
    "SecurityResult",
    "SecurityReview",
    "SecuritySeverity",
    "SecuritySubject",
    "SecuritySurface",
    "SecuritySurfaceEvidence",
    "make_security_result",
    "scan_security_surfaces",
]
