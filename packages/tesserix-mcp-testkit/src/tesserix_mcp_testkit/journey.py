from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from itertools import chain
from typing import Any, Final, cast

from tesserix_mcp_runtime import JsonValue

JOURNEY_CONTRACT_VERSION: Final = "1.0"

REQUIRED_JOURNEY_ASSERTIONS: Final = (
    "activation.authenticated_probe",
    "activation.bad_probe_rejected",
    "activation.route_accepted",
    "discovery.exact_fetch",
    "discovery.semantic_match",
    "invocation.approval_required",
    "invocation.deadline",
    "invocation.safe_failure",
    "invocation.structured_result",
    "invocation.write_replay",
    "observability.audit",
    "observability.correlation",
    "outage.backing_visible",
    "outage.gateway_visible",
    "outage.registry_last_known_good",
    "publication.immutable",
    "publication.replay",
    "redaction.canary_absent",
    "rollback.known_good",
    "tenant.invocation_non_disclosure",
    "tenant.search_non_disclosure",
)

_REQUIRED_ASSERTION_SET = frozenset(REQUIRED_JOURNEY_ASSERTIONS)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REVISION = re.compile(r"(?:sha256:[0-9a-f]{64}|[0-9a-f]{40})\Z")
_COMPONENT_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_ARTIFACT_REF = re.compile(r"mcpservers/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[^\s@]{1,255}\Z")
_ASSERTION_CODE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TRACE_ID = re.compile(r"[0-9a-f]{32}\Z")
_TIMESTAMP = re.compile(
    r"(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:(?:api[_-]?key|access[_-]?token|password|credential|secret)"
    r"\s*[:=]\s*[^\s,;\"}\[{]{4,}|authorization\s*[:=]\s*"
    r"(?!(?:action|rules)\s*:)[^\s,;\"}\[{]{4,})"
)
_MAX_EVIDENCE_BYTES = 1024 * 1024
_MAX_SURFACE_BYTES = 1024 * 1024
_MAX_TOTAL_SURFACE_BYTES = 8 * 1024 * 1024
_MAX_SURFACES = 256


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


class JourneyPhase(StrEnum):
    PUBLISHED = "published"
    DISCOVERED = "discovered"
    ROUTE_ACCEPTED = "route_accepted"
    PROBE_AUTHENTICATED = "probe_authenticated"
    INVOKED = "invoked"
    FAILED_CANDIDATE = "failed_candidate"
    OUTAGE = "outage"
    ROLLBACK = "rollback"


class JourneyState(StrEnum):
    HEALTHY = "healthy"
    CONTROL_PLANE_DEGRADED = "control_plane_degraded"
    ACTIVATION_TIMED_OUT = "activation_timed_out"
    PROBE_FAILED = "probe_failed"
    GATEWAY_UNAVAILABLE = "gateway_unavailable"
    BACKING_UNAVAILABLE = "backing_unavailable"
    ROLLED_BACK = "rolled_back"


class JourneyEvidenceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"journey_evidence:{code}")


@dataclass(frozen=True, slots=True, kw_only=True)
class JourneyComponent:
    name: str
    version: str
    revision: str

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.name, str)
            or _COMPONENT_NAME.fullmatch(self.name) is None
            or not _is_runtime_instance(self.version, str)
            or _VERSION.fullmatch(self.version) is None
            or self.version == "latest"
            or not _is_runtime_instance(self.revision, str)
            or _REVISION.fullmatch(self.revision) is None
        ):
            raise ValueError("component identity must be exact bounded text")

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "name": self.name,
            "revision": self.revision,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class JourneyArtifact:
    ref: str
    registry_digest: str
    artifact_digest: str
    version: str

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.ref, str)
            or len(self.ref) > 2_048
            or _ARTIFACT_REF.fullmatch(self.ref) is None
            or not _is_runtime_instance(self.registry_digest, str)
            or _DIGEST.fullmatch(self.registry_digest) is None
            or not _is_runtime_instance(self.artifact_digest, str)
            or _DIGEST.fullmatch(self.artifact_digest) is None
            or not _is_runtime_instance(self.version, str)
            or _VERSION.fullmatch(self.version) is None
            or self.version == "latest"
            or not self.ref.endswith("@" + self.version)
        ):
            raise ValueError("artifact identity must be immutable bounded text")

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "artifact_digest": self.artifact_digest,
            "ref": self.ref,
            "registry_digest": self.registry_digest,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class JourneyAssertion:
    code: str
    phase: JourneyPhase
    state: JourneyState
    passed: bool
    elapsed_ms: int
    request_id: str
    trace_id: str = ""
    ref: str = ""
    digest: str = ""

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.code, str)
            or _ASSERTION_CODE.fullmatch(self.code) is None
            or not _is_runtime_instance(self.phase, JourneyPhase)
            or not _is_runtime_instance(self.state, JourneyState)
            or not _is_runtime_instance(self.passed, bool)
            or _is_runtime_instance(self.elapsed_ms, bool)
            or not _is_runtime_instance(self.elapsed_ms, int)
            or not 0 <= self.elapsed_ms <= 600_000
            or not _is_runtime_instance(self.request_id, str)
            or _REQUEST_ID.fullmatch(self.request_id) is None
            or not _is_runtime_instance(self.trace_id, str)
            or (self.trace_id != "" and _TRACE_ID.fullmatch(self.trace_id) is None)
            or not _is_runtime_instance(self.ref, str)
            or (self.ref != "" and _ARTIFACT_REF.fullmatch(self.ref) is None)
            or not _is_runtime_instance(self.digest, str)
            or (self.digest != "" and _DIGEST.fullmatch(self.digest) is None)
            or (self.ref == "") != (self.digest == "")
        ):
            raise ValueError("assertion must use bounded journey contract values")

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "code": self.code,
            "digest": self.digest,
            "elapsed_ms": self.elapsed_ms,
            "passed": self.passed,
            "phase": self.phase.value,
            "ref": self.ref,
            "request_id": self.request_id,
            "state": self.state.value,
            "trace_id": self.trace_id,
        }


_EXPECTED_PHASES: Final = {
    "publication.immutable": JourneyPhase.PUBLISHED,
    "publication.replay": JourneyPhase.PUBLISHED,
    "discovery.exact_fetch": JourneyPhase.DISCOVERED,
    "discovery.semantic_match": JourneyPhase.DISCOVERED,
    "tenant.search_non_disclosure": JourneyPhase.DISCOVERED,
    "activation.route_accepted": JourneyPhase.ROUTE_ACCEPTED,
    "activation.authenticated_probe": JourneyPhase.PROBE_AUTHENTICATED,
    "activation.bad_probe_rejected": JourneyPhase.FAILED_CANDIDATE,
    "outage.registry_last_known_good": JourneyPhase.OUTAGE,
    "outage.gateway_visible": JourneyPhase.OUTAGE,
    "outage.backing_visible": JourneyPhase.OUTAGE,
    "rollback.known_good": JourneyPhase.ROLLBACK,
}
_EXPECTED_STATES: Final = {
    "activation.bad_probe_rejected": JourneyState.PROBE_FAILED,
    "outage.registry_last_known_good": JourneyState.CONTROL_PLANE_DEGRADED,
    "outage.gateway_visible": JourneyState.GATEWAY_UNAVAILABLE,
    "outage.backing_visible": JourneyState.BACKING_UNAVAILABLE,
    "rollback.known_good": JourneyState.ROLLED_BACK,
}
_IDENTITY_CHECKPOINTS: Final = frozenset(
    {
        "activation.authenticated_probe",
        "activation.route_accepted",
        "discovery.exact_fetch",
        "invocation.structured_result",
        "outage.registry_last_known_good",
        "publication.immutable",
        "publication.replay",
        "rollback.known_good",
    }
)


def make_journey_assertion(
    *,
    code: str,
    passed: bool,
    elapsed_ms: int,
    request_id: str,
    trace_id: str = "",
    known_good: JourneyArtifact | None = None,
) -> JourneyAssertion:
    if code not in _REQUIRED_ASSERTION_SET:
        raise ValueError("code must be a required journey assertion")
    identity_required = code in _IDENTITY_CHECKPOINTS
    if (identity_required and not _is_runtime_instance(known_good, JourneyArtifact)) or (
        known_good is not None and not _is_runtime_instance(known_good, JourneyArtifact)
    ):
        raise ValueError("known_good must match the assertion identity checkpoint")
    return JourneyAssertion(
        code=code,
        phase=_EXPECTED_PHASES.get(code, JourneyPhase.INVOKED),
        state=_EXPECTED_STATES.get(code, JourneyState.HEALTHY),
        passed=passed,
        elapsed_ms=elapsed_ms,
        request_id=request_id,
        trace_id=trace_id,
        ref=known_good.ref if identity_required and known_good is not None else "",
        digest=(known_good.registry_digest if identity_required and known_good is not None else ""),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class JourneyEvidence:
    run_id: str
    created_at: str
    components: tuple[JourneyComponent, ...]
    known_good: JourneyArtifact
    assertions: tuple[JourneyAssertion, ...]

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.run_id, str)
            or _RUN_ID.fullmatch(self.run_id) is None
            or not _is_runtime_instance(self.created_at, str)
            or _TIMESTAMP.fullmatch(self.created_at) is None
            or not _is_runtime_instance(self.components, tuple)
            or not 1 <= len(self.components) <= 32
            or any(not _is_runtime_instance(item, JourneyComponent) for item in self.components)
            or len({item.name for item in self.components}) != len(self.components)
            or not _is_runtime_instance(self.known_good, JourneyArtifact)
            or not _is_runtime_instance(self.assertions, tuple)
            or not 1 <= len(self.assertions) <= 128
            or any(not _is_runtime_instance(item, JourneyAssertion) for item in self.assertions)
        ):
            raise ValueError("evidence must use bounded immutable journey values")
        if len({item.code for item in self.assertions}) != len(self.assertions):
            raise ValueError("assertion codes must be unique")

    def _assert_complete(self) -> None:
        by_code = {item.code: item for item in self.assertions}
        missing = sorted(_REQUIRED_ASSERTION_SET.difference(by_code))
        if missing:
            raise JourneyEvidenceError(f"missing:{missing[0]}")
        for code in REQUIRED_JOURNEY_ASSERTIONS:
            assertion = by_code[code]
            if not assertion.passed:
                raise JourneyEvidenceError(f"failed:{code}")
            expected_phase = _EXPECTED_PHASES.get(code, JourneyPhase.INVOKED)
            if assertion.phase is not expected_phase:
                raise JourneyEvidenceError(f"phase_mismatch:{code}")
            expected_state = _EXPECTED_STATES.get(code, JourneyState.HEALTHY)
            if assertion.state is not expected_state:
                raise JourneyEvidenceError(f"state_mismatch:{code}")
            if code in _IDENTITY_CHECKPOINTS and (
                assertion.ref != self.known_good.ref
                or assertion.digest != self.known_good.registry_digest
            ):
                raise JourneyEvidenceError(f"identity_mismatch:{code}")
            if code.startswith(("invocation.", "observability.")) and not assertion.trace_id:
                raise JourneyEvidenceError(f"trace_missing:{code}")

    def to_document(self) -> dict[str, JsonValue]:
        self._assert_complete()
        return {
            "assertions": [
                item.to_document() for item in sorted(self.assertions, key=lambda item: item.code)
            ],
            "components": [
                item.to_document() for item in sorted(self.components, key=lambda item: item.name)
            ],
            "contract_version": JOURNEY_CONTRACT_VERSION,
            "created_at": self.created_at,
            "known_good": self.known_good.to_document(),
            "run_id": self.run_id,
        }

    def to_json(
        self,
        *,
        surfaces: Iterable[str | bytes] = (),
        canaries: tuple[str, ...] = (),
    ) -> bytes:
        encoded = (
            json.dumps(
                self.to_document(),
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            + b"\n"
        )
        if len(encoded) > _MAX_EVIDENCE_BYTES:
            raise JourneyEvidenceError("evidence_too_large")
        scan_journey_surfaces(chain((encoded,), surfaces), canaries=canaries)
        return encoded


def _canaries(values: tuple[str, ...]) -> tuple[str, ...]:
    if (
        not _is_runtime_instance(values, tuple)
        or len(values) > 32
        or any(
            not _is_runtime_instance(value, str)
            or not 8 <= len(value) <= 256
            or not value.isprintable()
            for value in values
        )
        or len(set(values)) != len(values)
    ):
        raise ValueError("canaries must be unique bounded printable text")
    return values


def scan_journey_surfaces(
    surfaces: Iterable[str | bytes],
    *,
    canaries: tuple[str, ...] = (),
) -> None:
    forbidden = _canaries(canaries)
    total = 0
    for count, surface in enumerate(surfaces, start=1):
        if count > _MAX_SURFACES:
            raise JourneyEvidenceError("surface_bounds")
        if _is_runtime_instance(surface, str):
            text = cast(str, surface)
            raw = text.encode()
        elif _is_runtime_instance(surface, bytes):
            raw = cast(bytes, surface)
            text = raw.decode(errors="replace")
        else:
            raise ValueError("journey surfaces must be text or bytes")
        total += len(raw)
        if len(raw) > _MAX_SURFACE_BYTES or total > _MAX_TOTAL_SURFACE_BYTES:
            raise JourneyEvidenceError("surface_bounds")
        if (
            any(canary in text for canary in forbidden)
            or _BEARER.search(text) is not None
            or _SECRET_ASSIGNMENT.search(text) is not None
        ):
            raise JourneyEvidenceError("forbidden_material")


__all__ = [
    "JOURNEY_CONTRACT_VERSION",
    "REQUIRED_JOURNEY_ASSERTIONS",
    "JourneyArtifact",
    "JourneyAssertion",
    "JourneyComponent",
    "JourneyEvidence",
    "JourneyEvidenceError",
    "JourneyPhase",
    "JourneyState",
    "make_journey_assertion",
    "scan_journey_surfaces",
]
