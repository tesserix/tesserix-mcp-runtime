from __future__ import annotations

import asyncio

import pytest
from tesserix_mcp_testkit import (
    FaultKind,
    FaultScript,
    FaultScriptExhausted,
    FaultStep,
    InjectedFault,
)


def test_fault_vocabulary_covers_every_required_deterministic_scenario() -> None:
    assert {kind.value for kind in FaultKind} == {
        "cancelled",
        "cross_tenant",
        "duplicate",
        "flapping",
        "malformed",
        "oversized",
        "slow",
        "success",
        "truncated",
        "unavailable",
    }


def test_script_returns_values_and_raises_faults_in_exact_order() -> None:
    script = FaultScript(
        (
            FaultStep.success("first"),
            FaultStep.inject(FaultKind.SLOW),
            FaultStep.success("last"),
        )
    )

    assert script.resolve() == "first"
    with pytest.raises(InjectedFault) as captured:
        script.resolve()
    assert captured.value.kind is FaultKind.SLOW
    assert str(captured.value) == "fault:slow"
    assert script.resolve() == "last"
    assert script.calls == 3
    assert script.remaining == 0
    with pytest.raises(FaultScriptExhausted, match="fault_script_exhausted"):
        script.resolve()


def test_cancelled_fault_uses_asyncio_cancellation() -> None:
    script: FaultScript[str] = FaultScript((FaultStep.inject(FaultKind.CANCELLED),))

    with pytest.raises(asyncio.CancelledError):
        script.resolve()


def test_flapping_helper_is_unavailable_once_then_recovers() -> None:
    script: FaultScript[str] = FaultScript.flapping("healthy")

    with pytest.raises(InjectedFault) as captured:
        script.resolve()
    assert captured.value.kind is FaultKind.FLAPPING
    assert script.resolve() == "healthy"
    assert script.calls == 2


@pytest.mark.parametrize(
    "kind",
    [
        FaultKind.CROSS_TENANT,
        FaultKind.DUPLICATE,
        FaultKind.MALFORMED,
        FaultKind.OVERSIZED,
        FaultKind.TRUNCATED,
        FaultKind.UNAVAILABLE,
    ],
)
def test_each_non_cancellation_fault_raises_the_same_bounded_type(kind: FaultKind) -> None:
    script: FaultScript[str] = FaultScript((FaultStep.inject(kind),))

    with pytest.raises(InjectedFault) as captured:
        script.resolve()
    assert captured.value.kind is kind
    assert str(captured.value) == f"fault:{kind.value}"


def test_scripts_reject_empty_or_unbounded_steps() -> None:
    with pytest.raises(ValueError, match="between 1 and 256"):
        FaultScript(())
    with pytest.raises(ValueError, match="between 1 and 256"):
        FaultScript(tuple(FaultStep.success(index) for index in range(257)))
    with pytest.raises(ValueError, match="cannot inject success"):
        FaultStep.inject(FaultKind.SUCCESS)
