from __future__ import annotations

import asyncio
import threading
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Never


def _is_fault_kind(value: object) -> bool:
    return isinstance(value, FaultKind)


def _is_fault_step(value: object) -> bool:
    return isinstance(value, FaultStep)


class FaultKind(StrEnum):
    CANCELLED = "cancelled"
    CROSS_TENANT = "cross_tenant"
    DUPLICATE = "duplicate"
    FLAPPING = "flapping"
    MALFORMED = "malformed"
    OVERSIZED = "oversized"
    SLOW = "slow"
    SUCCESS = "success"
    TRUNCATED = "truncated"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class FaultStep[ValueT]:
    kind: FaultKind
    value: ValueT | None = None

    def __post_init__(self) -> None:
        if not _is_fault_kind(self.kind):
            raise ValueError("fault kind must use the stable vocabulary")
        if self.kind is FaultKind.SUCCESS and self.value is None:
            raise ValueError("success fault step requires a value")
        if self.kind is not FaultKind.SUCCESS and self.value is not None:
            raise ValueError("injected fault step cannot carry a value")

    @staticmethod
    def success[SuccessT](value: SuccessT) -> FaultStep[SuccessT]:
        return FaultStep(kind=FaultKind.SUCCESS, value=value)

    @staticmethod
    def inject(kind: FaultKind) -> FaultStep[Never]:
        if kind is FaultKind.SUCCESS:
            raise ValueError("cannot inject success as a fault")
        return FaultStep(kind=kind)


class InjectedFault(RuntimeError):
    def __init__(self, kind: FaultKind) -> None:
        if kind in {FaultKind.CANCELLED, FaultKind.SUCCESS}:
            raise ValueError("injected fault requires a non-cancellation fault kind")
        self.kind = kind
        super().__init__(f"fault:{kind.value}")


class FaultScriptExhausted(RuntimeError):
    def __init__(self) -> None:
        super().__init__("fault_script_exhausted")


class FaultScript[ValueT]:
    def __init__(self, steps: Iterable[FaultStep[ValueT]]) -> None:
        resolved = tuple(steps)
        if not 1 <= len(resolved) <= 256:
            raise ValueError("fault scripts must contain between 1 and 256 steps")
        if any(not _is_fault_step(step) for step in resolved):
            raise ValueError("fault scripts must contain FaultStep values")
        self._steps = deque(resolved)
        self._calls = 0
        self._lock = threading.Lock()

    @staticmethod
    def flapping[RecoveredT](recovered: RecoveredT) -> FaultScript[RecoveredT]:
        return FaultScript(
            (
                FaultStep.inject(FaultKind.FLAPPING),
                FaultStep.success(recovered),
            )
        )

    @property
    def calls(self) -> int:
        with self._lock:
            return self._calls

    @property
    def remaining(self) -> int:
        with self._lock:
            return len(self._steps)

    def resolve(self) -> ValueT:
        with self._lock:
            if not self._steps:
                raise FaultScriptExhausted
            step = self._steps.popleft()
            self._calls += 1
        if step.kind is FaultKind.SUCCESS:
            if step.value is None:
                raise RuntimeError("validated success step lost its value")
            return step.value
        if step.kind is FaultKind.CANCELLED:
            raise asyncio.CancelledError
        raise InjectedFault(step.kind)


__all__ = [
    "FaultKind",
    "FaultScript",
    "FaultScriptExhausted",
    "FaultStep",
    "InjectedFault",
]
