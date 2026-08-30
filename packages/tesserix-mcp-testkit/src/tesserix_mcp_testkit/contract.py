from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from tesserix_mcp_runtime import ErrorCode, JsonValue, LifecycleState

CONFORMANCE_CONTRACT_VERSION = "1.0"
CONFORMANCE_TOOL_NAME = "conformance_echo"
_CASE_ID = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\Z")
_FAILURE_CODE = re.compile(r"[a-z][a-z0-9_]*(?::[a-z][a-z0-9_]*)?\Z")
_MAX_TELEMETRY_TEXT = 65_536


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


class ConformanceCapability(StrEnum):
    AUTHORIZATION = "authorization"
    CANCELLATION = "cancellation"
    DISCOVERY = "discovery"
    ERROR_MAPPING = "error_mapping"
    INVOCATION = "invocation"
    LIFECYCLE = "lifecycle"
    LIMITS = "limits"
    TELEMETRY = "telemetry"
    TENANCY = "tenancy"


REQUIRED_CAPABILITIES = frozenset(
    {
        ConformanceCapability.DISCOVERY,
        ConformanceCapability.INVOCATION,
    }
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ConformanceObservation:
    state: LifecycleState | None = None
    error_code: ErrorCode | None = None
    tool_names: tuple[str, ...] = ()
    value: JsonValue | None = None
    telemetry_text: str = ""

    def __post_init__(self) -> None:
        if self.state is not None and not _is_runtime_instance(self.state, LifecycleState):
            raise ValueError("state must use the runtime lifecycle vocabulary")
        if self.error_code is not None and not _is_runtime_instance(self.error_code, ErrorCode):
            raise ValueError("error_code must use the runtime error vocabulary")
        if not _is_runtime_instance(self.tool_names, tuple) or any(
            not _is_runtime_instance(name, str) or not 1 <= len(name) <= 128
            for name in self.tool_names
        ):
            raise ValueError("tool_names must contain bounded names")
        if (
            not _is_runtime_instance(self.telemetry_text, str)
            or len(self.telemetry_text) > _MAX_TELEMETRY_TEXT
        ):
            raise ValueError("telemetry_text must be bounded text")


@dataclass(frozen=True, slots=True, kw_only=True)
class ConformanceCase:
    id: str
    capability: ConformanceCapability
    expected_state: LifecycleState | None = None
    expected_error: ErrorCode | None = None
    expected_value: JsonValue | None = None
    check_value: bool = False
    required_tool: bool = False
    forbidden_text: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.id, str) or _CASE_ID.fullmatch(self.id) is None:
            raise ValueError("conformance case id must use stable dotted vocabulary")
        if not _is_runtime_instance(self.capability, ConformanceCapability):
            raise ValueError("capability must use the conformance vocabulary")
        if self.expected_state is not None and not _is_runtime_instance(
            self.expected_state, LifecycleState
        ):
            raise ValueError("expected_state must use the runtime lifecycle vocabulary")
        if self.expected_error is not None and not _is_runtime_instance(
            self.expected_error, ErrorCode
        ):
            raise ValueError("expected_error must use the runtime error vocabulary")
        if not _is_runtime_instance(self.check_value, bool) or not _is_runtime_instance(
            self.required_tool, bool
        ):
            raise ValueError("case switches must be boolean")
        if not _is_runtime_instance(self.forbidden_text, tuple) or any(
            not _is_runtime_instance(value, str) or not 1 <= len(value) <= 256
            for value in self.forbidden_text
        ):
            raise ValueError("forbidden_text must contain bounded canaries")


@runtime_checkable
class ConformanceTarget(Protocol):
    @property
    def capabilities(self) -> frozenset[ConformanceCapability]: ...

    async def observe(self, case: ConformanceCase) -> ConformanceObservation: ...


class ConformanceFailure(AssertionError):
    def __init__(self, *, case_id: str, code: str) -> None:
        if _CASE_ID.fullmatch(case_id) is None or _FAILURE_CODE.fullmatch(code) is None:
            raise ValueError("conformance failures require stable identifiers")
        self.case_id = case_id
        self.code = code
        super().__init__(f"{case_id}:{code}")


class ConformanceNotApplicable(Exception):
    def __init__(self, *, case_id: str, capability: ConformanceCapability) -> None:
        self.case_id = case_id
        self.capability = capability
        super().__init__(f"{case_id}:requires_{capability.value}")


def _case(
    case_id: str,
    capability: ConformanceCapability,
    *,
    expected_state: LifecycleState | None = None,
    expected_error: ErrorCode | None = None,
    expected_value: JsonValue | None = None,
    check_value: bool = False,
    required_tool: bool = False,
    forbidden_text: tuple[str, ...] = (),
) -> ConformanceCase:
    return ConformanceCase(
        id=case_id,
        capability=capability,
        expected_state=expected_state,
        expected_error=expected_error,
        expected_value=expected_value,
        check_value=check_value,
        required_tool=required_tool,
        forbidden_text=forbidden_text,
    )


CONFORMANCE_CASES = (
    _case(
        "discovery.tools",
        ConformanceCapability.DISCOVERY,
        required_tool=True,
    ),
    _case(
        "invocation.success",
        ConformanceCapability.INVOCATION,
        expected_value={"echo": "ok"},
        check_value=True,
    ),
    *(
        _case(
            f"errors.{code.value}",
            ConformanceCapability.ERROR_MAPPING,
            expected_error=code,
        )
        for code in ErrorCode
    ),
    *(
        _case(
            f"lifecycle.{state.value}",
            ConformanceCapability.LIFECYCLE,
            expected_state=state,
        )
        for state in LifecycleState
    ),
    _case(
        "authorization.default_deny",
        ConformanceCapability.AUTHORIZATION,
        expected_error=ErrorCode.INVALID_INPUT,
    ),
    _case(
        "tenancy.cross_tenant",
        ConformanceCapability.TENANCY,
        expected_error=ErrorCode.FORBIDDEN,
    ),
    _case(
        "limits.input",
        ConformanceCapability.LIMITS,
        expected_error=ErrorCode.INVALID_INPUT,
    ),
    _case(
        "limits.result",
        ConformanceCapability.LIMITS,
        expected_error=ErrorCode.RESULT_TOO_LARGE,
    ),
    _case(
        "limits.concurrency",
        ConformanceCapability.LIMITS,
        expected_error=ErrorCode.OVERLOADED,
    ),
    _case(
        "telemetry.payload_free",
        ConformanceCapability.TELEMETRY,
        forbidden_text=("SyntheticPayloadCanary8Kq3", "SyntheticCredentialCanary2Zp7"),
    ),
    _case(
        "cancellation.cancelled",
        ConformanceCapability.CANCELLATION,
        expected_error=ErrorCode.CANCELLED,
    ),
)


def _fail(case_id: str, code: str) -> None:
    raise ConformanceFailure(case_id=case_id, code=code)


async def assert_conformance_case(
    target: ConformanceTarget,
    case: ConformanceCase,
) -> None:
    if not _is_runtime_instance(target, ConformanceTarget):
        _fail("contract.capabilities", "invalid_target")
    capabilities = target.capabilities
    if not _is_runtime_instance(capabilities, frozenset) or any(
        not _is_runtime_instance(capability, ConformanceCapability) for capability in capabilities
    ):
        _fail("contract.capabilities", "invalid_capabilities")
    missing = sorted(REQUIRED_CAPABILITIES - capabilities, key=lambda value: value.value)
    if missing:
        _fail("contract.capabilities", f"missing_required_capability:{missing[0].value}")
    if case.capability not in capabilities:
        raise ConformanceNotApplicable(case_id=case.id, capability=case.capability)

    observation = await target.observe(case)
    if not _is_runtime_instance(observation, ConformanceObservation):
        _fail(case.id, "invalid_observation")
    if case.expected_state is not None and observation.state is not case.expected_state:
        _fail(case.id, "lifecycle_state_mismatch")
    if case.expected_error is not None and observation.error_code is not case.expected_error:
        _fail(case.id, "error_code_mismatch")
    if case.required_tool and observation.tool_names.count(CONFORMANCE_TOOL_NAME) != 1:
        _fail(case.id, "tool_listing_mismatch")
    if case.check_value and observation.value != case.expected_value:
        _fail(case.id, "invocation_value_mismatch")
    if any(value in observation.telemetry_text for value in case.forbidden_text):
        _fail(case.id, "telemetry_contains_forbidden_text")


def run_conformance_case(target: ConformanceTarget, case: ConformanceCase) -> None:
    asyncio.run(assert_conformance_case(target, case))


__all__ = [
    "CONFORMANCE_CASES",
    "CONFORMANCE_CONTRACT_VERSION",
    "CONFORMANCE_TOOL_NAME",
    "REQUIRED_CAPABILITIES",
    "ConformanceCapability",
    "ConformanceCase",
    "ConformanceFailure",
    "ConformanceNotApplicable",
    "ConformanceObservation",
    "ConformanceTarget",
    "assert_conformance_case",
    "run_conformance_case",
]
