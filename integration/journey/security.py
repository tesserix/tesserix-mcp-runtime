from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from security.check_ci_attack_paths import check_ci_attack_paths
from security.ssrf_harness import run_ssrf_harness
from tesserix_mcp_testkit import (
    SECURITY_CASES,
    SecurityArea,
    SecurityEvidenceKind,
    SecurityResult,
    SecuritySurface,
    SecuritySurfaceEvidence,
    make_security_result,
    scan_security_surfaces,
)

_CI_CASES = frozenset(
    {
        "ci.immutable_actions",
        "ci.least_privilege_permissions",
        "ci.untrusted_pull_request",
        "dependency.release_policy",
    }
)
_EGRESS_CASES = frozenset(
    {
        "egress.alternate_port",
        "egress.dns_rebinding",
        "egress.encoded_ip",
        "egress.ipv6",
        "egress.loopback",
        "egress.metadata",
        "egress.private_range",
        "egress.redirect",
    }
)
_CASES_BY_ID = {case.id: case for case in SECURITY_CASES}


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


def black_box_security_results(
    case_ids: tuple[str, ...],
    *,
    request_id: str,
    observation: Mapping[str, object],
    passed: bool = True,
    canaries: tuple[str, ...] = (),
) -> tuple[SecurityResult, ...]:
    if (
        not isinstance(case_ids, tuple)
        or not 1 <= len(case_ids) <= len(SECURITY_CASES)
        or len(set(case_ids)) != len(case_ids)
        or not isinstance(observation, Mapping)
        or any(not isinstance(key, str) for key in observation)
    ):
        raise ValueError("black-box evidence must be bounded and unambiguous")
    selected = []
    for case_id in sorted(case_ids):
        case = _CASES_BY_ID.get(case_id)
        if case is None or case.evidence_kind is not SecurityEvidenceKind.BLACK_BOX:
            raise ValueError("black-box evidence case has the wrong execution mode")
        selected.append(case)
    try:
        evidence = _canonical_json(dict(observation))
    except (TypeError, ValueError):
        raise ValueError("black-box observation must be canonical JSON") from None
    return tuple(
        make_security_result(
            case_id=case.id,
            evidence_kind=SecurityEvidenceKind.BLACK_BOX,
            evidence=evidence,
            passed=passed,
            request_id=request_id,
            canaries=canaries,
        )
        for case in selected
    )


def host_security_results_from_reports(
    *,
    ci_report: Mapping[str, bool],
    ssrf_report: Mapping[str, object],
) -> tuple[SecurityResult, ...]:
    if set(ci_report) != _CI_CASES or any(
        not isinstance(value, bool) for value in ci_report.values()
    ):
        raise ValueError("CI security report must cover the exact attack-path contract")
    raw_cases = ssrf_report.get("cases")
    connections = ssrf_report.get("connections")
    passed = ssrf_report.get("passed")
    if (
        not isinstance(raw_cases, list)
        or any(not isinstance(case_id, str) for case_id in raw_cases)
        or set(raw_cases) != _EGRESS_CASES
        or len(raw_cases) != len(_EGRESS_CASES)
        or isinstance(connections, bool)
        or not isinstance(connections, int)
        or not 0 <= connections <= 64
        or not isinstance(passed, bool)
    ):
        raise ValueError("SSRF report must cover the exact isolated-network contract")
    ci_evidence = _canonical_json(dict(sorted(ci_report.items())))
    ssrf_evidence = _canonical_json(
        {"cases": sorted(raw_cases), "connections": connections, "passed": passed}
    )
    results = [
        make_security_result(
            case_id=case_id,
            evidence_kind=SecurityEvidenceKind.STATIC,
            evidence=ci_evidence,
            passed=ci_report[case_id],
        )
        for case_id in sorted(_CI_CASES)
    ]
    results.extend(
        make_security_result(
            case_id=case_id,
            evidence_kind=SecurityEvidenceKind.ISOLATED_NETWORK,
            evidence=ssrf_evidence,
            passed=passed,
            request_id="ssrf-harness",
        )
        for case_id in sorted(_EGRESS_CASES)
    )
    return tuple(results)


async def collect_host_security_results(root: Path) -> tuple[SecurityResult, ...]:
    return host_security_results_from_reports(
        ci_report=check_ci_attack_paths(root),
        ssrf_report=await run_ssrf_harness(),
    )


def surface_security_results(
    raw: Mapping[SecuritySurface, str | bytes],
    *,
    canaries: tuple[str, ...],
) -> tuple[tuple[SecuritySurfaceEvidence, ...], tuple[SecurityResult, ...]]:
    surfaces = scan_security_surfaces(raw, canaries=canaries)
    results: list[SecurityResult] = []
    for surface in surfaces:
        case_id = f"redaction.{surface.surface.value}"
        case = _CASES_BY_ID.get(case_id)
        if case is None or case.area is not SecurityArea.REDACTION:
            raise ValueError("surface has no redaction security case")
        results.append(
            make_security_result(
                case_id=case_id,
                evidence_kind=case.evidence_kind,
                evidence=raw[surface.surface],
                passed=True,
                request_id=(
                    f"security-surface-{surface.surface.value}"
                    if case.evidence_kind is SecurityEvidenceKind.BLACK_BOX
                    else ""
                ),
                canaries=canaries,
            )
        )
    return surfaces, tuple(results)


__all__ = [
    "black_box_security_results",
    "collect_host_security_results",
    "host_security_results_from_reports",
    "surface_security_results",
]
