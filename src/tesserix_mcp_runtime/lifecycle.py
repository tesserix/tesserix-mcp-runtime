"""Deterministic lifecycle hook ordering for runtime components."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

from tesserix_mcp_runtime.contracts import (
    Lifecycle,
    LifecycleState,
    validate_deadline,
)


class LifecycleFailure(RuntimeError):
    """Report a scrubbed hook failure after deterministic cleanup."""

    def __init__(
        self,
        *,
        phase: LifecycleState,
        component: str,
        failure_count: int,
    ) -> None:
        self.phase = phase
        self.component = component
        self.failure_count = failure_count
        super().__init__(f"lifecycle {phase.value} failed for {component}")


class LifecycleTransitionError(RuntimeError):
    """Report an operation that is invalid in the current lifecycle state."""

    def __init__(self, *, operation: str, state: LifecycleState) -> None:
        self.operation = operation
        self.state = state
        super().__init__(f"cannot {operation} while lifecycle is {state.value}")


class LifecycleController:
    """Serialize transitions and run lifecycle hooks in deterministic order."""

    def __init__(self, components: Iterable[Lifecycle]) -> None:
        self._components = tuple(components)
        self._started: list[Lifecycle] = []
        self._state = LifecycleState.STARTUP
        self._transition_lock = asyncio.Lock()

    @property
    def state(self) -> LifecycleState:
        return self._state

    async def start(self) -> None:
        async with self._transition_lock:
            await self._start()

    async def _start(self) -> None:
        if self._state is not LifecycleState.STARTUP:
            raise LifecycleTransitionError(operation="start", state=self._state)
        for component in self._components:
            try:
                await component.start()
            except Exception as error:
                failure_count = 1
                for started in (component, *reversed(self._started)):
                    try:
                        await started.stop()
                    except Exception:
                        failure_count += 1
                self._state = LifecycleState.STOPPED
                raise LifecycleFailure(
                    phase=LifecycleState.STARTUP,
                    component=component.name,
                    failure_count=failure_count,
                ) from error
            self._started.append(component)
        self._state = LifecycleState.READY

    async def drain(self, *, deadline: float) -> None:
        validate_deadline(deadline)
        async with self._transition_lock:
            await self._drain(deadline=deadline)

    async def _drain(self, *, deadline: float) -> None:
        if self._state in {LifecycleState.DRAINING, LifecycleState.STOPPED}:
            return
        if self._state is not LifecycleState.READY:
            raise LifecycleTransitionError(operation="drain", state=self._state)
        self._state = LifecycleState.DRAINING
        failed_component: str | None = None
        failure_count = 0
        for component in reversed(self._started):
            try:
                await component.drain(deadline=deadline)
            except Exception:
                if failed_component is None:
                    failed_component = component.name
                failure_count += 1
        if failed_component is not None:
            raise LifecycleFailure(
                phase=LifecycleState.DRAINING,
                component=failed_component,
                failure_count=failure_count,
            )

    async def stop(self) -> None:
        async with self._transition_lock:
            await self._stop()

    async def _stop(self) -> None:
        if self._state is LifecycleState.STOPPED:
            return
        failed_component: str | None = None
        failure_count = 0
        for component in reversed(self._started):
            try:
                await component.stop()
            except Exception:
                if failed_component is None:
                    failed_component = component.name
                failure_count += 1
        self._state = LifecycleState.STOPPED
        if failed_component is not None:
            raise LifecycleFailure(
                phase=LifecycleState.STOPPED,
                component=failed_component,
                failure_count=failure_count,
            )


__all__ = [
    "LifecycleController",
    "LifecycleFailure",
    "LifecycleTransitionError",
]
