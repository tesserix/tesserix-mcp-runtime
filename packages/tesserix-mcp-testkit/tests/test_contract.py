from __future__ import annotations

import asyncio

import pytest
from tesserix_mcp_testkit import (
    CONFORMANCE_CASES,
    CONFORMANCE_CONTRACT_VERSION,
    CONFORMANCE_TOOL_NAME,
    REQUIRED_CAPABILITIES,
    ConformanceCapability,
    ConformanceCase,
    ConformanceFailure,
    ConformanceNotApplicable,
    ConformanceObservation,
    ConformanceTarget,
    assert_conformance_case,
)

from tesserix_mcp_runtime import ErrorCode, LifecycleState


class ContractTarget:
    def __init__(
        self,
        *,
        capabilities: frozenset[ConformanceCapability] | None = None,
        replacement_error: ErrorCode | None = None,
        telemetry_text: str = "event=success",
    ) -> None:
        self.capabilities = (
            frozenset(ConformanceCapability) if capabilities is None else capabilities
        )
        self.replacement_error = replacement_error
        self.telemetry_text = telemetry_text
        self.seen: list[str] = []

    async def observe(self, case: ConformanceCase) -> ConformanceObservation:
        self.seen.append(case.id)
        return ConformanceObservation(
            state=case.expected_state,
            error_code=(
                self.replacement_error
                if case.expected_error is not None and self.replacement_error is not None
                else case.expected_error
            ),
            tool_names=(CONFORMANCE_TOOL_NAME,) if case.required_tool else (),
            value=case.expected_value if case.check_value else None,
            telemetry_text=self.telemetry_text,
        )


class FixedObservationTarget:
    capabilities = frozenset(ConformanceCapability)

    def __init__(self, observation: ConformanceObservation) -> None:
        self._observation = observation

    async def observe(self, case: ConformanceCase) -> ConformanceObservation:
        del case
        return self._observation


def test_contract_v1_covers_every_stable_error_and_lifecycle_state() -> None:
    assert CONFORMANCE_CONTRACT_VERSION == "1.0"
    assert len(CONFORMANCE_CASES) == 24
    assert {case.id for case in CONFORMANCE_CASES} == {
        "authorization.default_deny",
        "cancellation.cancelled",
        "discovery.tools",
        "invocation.success",
        "limits.concurrency",
        "limits.input",
        "limits.result",
        "telemetry.payload_free",
        "tenancy.cross_tenant",
        *(f"errors.{code.value}" for code in ErrorCode),
        *(f"lifecycle.{state.value}" for state in LifecycleState),
    }
    assert {case.expected_error for case in CONFORMANCE_CASES if case.expected_error} == set(
        ErrorCode
    )
    assert {case.expected_state for case in CONFORMANCE_CASES if case.expected_state} == set(
        LifecycleState
    )
    assert (
        frozenset(
            {
                ConformanceCapability.DISCOVERY,
                ConformanceCapability.INVOCATION,
            }
        )
        == REQUIRED_CAPABILITIES
    )


def test_every_contract_case_accepts_a_conforming_target() -> None:
    async def exercise() -> None:
        target = ContractTarget()
        for case in CONFORMANCE_CASES:
            await assert_conformance_case(target, case)
        assert target.seen == [case.id for case in CONFORMANCE_CASES]

    asyncio.run(exercise())


def test_missing_required_capability_fails_before_observing_a_case() -> None:
    async def exercise() -> None:
        target = ContractTarget(capabilities=frozenset({ConformanceCapability.DISCOVERY}))
        with pytest.raises(ConformanceFailure) as captured:
            await assert_conformance_case(target, CONFORMANCE_CASES[0])
        assert captured.value.code == "missing_required_capability:invocation"
        assert captured.value.case_id == "contract.capabilities"
        assert target.seen == []

    asyncio.run(exercise())


def test_optional_capability_is_reported_as_not_applicable() -> None:
    async def exercise() -> None:
        target = ContractTarget(capabilities=REQUIRED_CAPABILITIES)
        lifecycle = next(case for case in CONFORMANCE_CASES if case.id == "lifecycle.ready")
        with pytest.raises(ConformanceNotApplicable) as captured:
            await assert_conformance_case(target, lifecycle)
        assert captured.value.case_id == "lifecycle.ready"
        assert captured.value.capability is ConformanceCapability.LIFECYCLE
        assert target.seen == []

    asyncio.run(exercise())


def test_wrong_error_mapping_is_killed_with_a_stable_failure_code() -> None:
    async def exercise() -> None:
        target = ContractTarget(replacement_error=ErrorCode.INTERNAL_FAILURE)
        timeout = next(case for case in CONFORMANCE_CASES if case.id == "errors.timeout")
        with pytest.raises(ConformanceFailure) as captured:
            await assert_conformance_case(target, timeout)
        assert captured.value.code == "error_code_mismatch"
        assert captured.value.case_id == "errors.timeout"

    asyncio.run(exercise())


def test_payload_canary_in_telemetry_is_rejected_without_echoing_it() -> None:
    async def exercise() -> None:
        target = ContractTarget(telemetry_text="SyntheticPayloadCanary8Kq3")
        telemetry = next(case for case in CONFORMANCE_CASES if case.id == "telemetry.payload_free")
        with pytest.raises(ConformanceFailure) as captured:
            await assert_conformance_case(target, telemetry)
        assert captured.value.code == "telemetry_contains_forbidden_text"
        assert str(captured.value) == "telemetry.payload_free:telemetry_contains_forbidden_text"
        assert "SyntheticPayloadCanary8Kq3" not in str(captured.value)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        ("state", "ready", "state must use the runtime lifecycle vocabulary"),
        ("error_code", "timeout", "error_code must use the runtime error vocabulary"),
        ("tool_names", ("",), "tool_names must contain bounded names"),
        ("telemetry_text", "x" * 65_537, "telemetry_text must be bounded text"),
    ],
)
def test_observations_reject_values_outside_the_bounded_runtime_contract(
    attribute: str,
    value: object,
    message: str,
) -> None:
    observation = ConformanceObservation()
    object.__setattr__(observation, attribute, value)

    with pytest.raises(ValueError, match=message):
        observation.__post_init__()


@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        ("id", "unstable", "conformance case id must use stable dotted vocabulary"),
        ("capability", "discovery", "capability must use the conformance vocabulary"),
        (
            "expected_state",
            "ready",
            "expected_state must use the runtime lifecycle vocabulary",
        ),
        (
            "expected_error",
            "timeout",
            "expected_error must use the runtime error vocabulary",
        ),
        ("check_value", 1, "case switches must be boolean"),
        ("required_tool", 1, "case switches must be boolean"),
        ("forbidden_text", ("",), "forbidden_text must contain bounded canaries"),
    ],
)
def test_cases_reject_values_outside_the_stable_contract(
    attribute: str,
    value: object,
    message: str,
) -> None:
    case = ConformanceCase(
        id="validation.case",
        capability=ConformanceCapability.DISCOVERY,
    )
    object.__setattr__(case, attribute, value)

    with pytest.raises(ValueError, match=message):
        case.__post_init__()


@pytest.mark.parametrize(
    ("case_id", "code"),
    [
        ("unstable", "invalid_target"),
        ("contract.capabilities", "INVALID"),
    ],
)
def test_failures_reject_unstable_identifiers(case_id: str, code: str) -> None:
    with pytest.raises(ValueError, match="stable identifiers"):
        ConformanceFailure(case_id=case_id, code=code)


def test_target_must_implement_the_runtime_checkable_contract() -> None:
    async def exercise() -> None:
        target: ConformanceTarget = ContractTarget()
        object.__delattr__(target, "capabilities")

        with pytest.raises(ConformanceFailure) as captured:
            await assert_conformance_case(target, CONFORMANCE_CASES[0])
        assert captured.value.code == "invalid_target"

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "capabilities",
    [
        (ConformanceCapability.DISCOVERY, ConformanceCapability.INVOCATION),
        frozenset({"discovery", "invocation"}),
    ],
)
def test_target_capabilities_must_use_a_frozen_stable_vocabulary(
    capabilities: object,
) -> None:
    async def exercise() -> None:
        target: ConformanceTarget = ContractTarget()
        object.__setattr__(target, "capabilities", capabilities)

        with pytest.raises(ConformanceFailure) as captured:
            await assert_conformance_case(target, CONFORMANCE_CASES[0])
        assert captured.value.code == "invalid_capabilities"

    asyncio.run(exercise())


def test_target_observation_must_use_the_contract_type() -> None:
    async def exercise() -> None:
        target: ConformanceTarget = ContractTarget()

        async def invalid_observe(case: ConformanceCase) -> object:
            del case
            return object()

        object.__setattr__(target, "observe", invalid_observe)

        with pytest.raises(ConformanceFailure) as captured:
            await assert_conformance_case(target, CONFORMANCE_CASES[0])
        assert captured.value.code == "invalid_observation"

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("case_id", "observation", "failure_code"),
    [
        (
            "lifecycle.ready",
            ConformanceObservation(state=LifecycleState.STARTUP),
            "lifecycle_state_mismatch",
        ),
        (
            "discovery.tools",
            ConformanceObservation(tool_names=()),
            "tool_listing_mismatch",
        ),
        (
            "invocation.success",
            ConformanceObservation(value={"echo": "wrong"}),
            "invocation_value_mismatch",
        ),
    ],
)
def test_observation_mismatches_report_stable_failure_codes(
    case_id: str,
    observation: ConformanceObservation,
    failure_code: str,
) -> None:
    async def exercise() -> None:
        case = next(candidate for candidate in CONFORMANCE_CASES if candidate.id == case_id)

        with pytest.raises(ConformanceFailure) as captured:
            await assert_conformance_case(FixedObservationTarget(observation), case)
        assert captured.value.code == failure_code
        assert captured.value.case_id == case_id

    asyncio.run(exercise())
