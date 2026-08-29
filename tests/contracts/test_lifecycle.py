from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass

import pytest
from hypothesis import given, strategies as st

from tesserix_mcp_runtime import (
    LifecycleController,
    LifecycleFailure,
    LifecycleState,
    LifecycleTransitionError,
)


@dataclass(slots=True)
class RecordingLifecycle:
    name: str
    events: list[str]

    async def start(self) -> None:
        self.events.append(f"{self.name}.start")

    async def drain(self, *, deadline: float) -> None:
        self.events.append(f"{self.name}.drain:{deadline}")

    async def stop(self) -> None:
        self.events.append(f"{self.name}.stop")


def test_lifecycle_starts_in_order_and_drains_and_stops_in_reverse() -> None:
    async def exercise() -> None:
        events: list[str] = []
        controller = LifecycleController(
            [
                RecordingLifecycle("dependency", events),
                RecordingLifecycle("listener", events),
            ]
        )

        assert controller.state is LifecycleState.STARTUP
        await controller.start()
        assert controller.state is LifecycleState.READY
        await controller.drain(deadline=42.0)
        assert controller.state is LifecycleState.DRAINING
        await controller.stop()
        assert controller.state is LifecycleState.STOPPED
        assert events == [
            "dependency.start",
            "listener.start",
            "listener.drain:42.0",
            "dependency.drain:42.0",
            "listener.stop",
            "dependency.stop",
        ]

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "invalid_deadline",
    [-1.0, math.inf, math.nan, True],
    ids=["negative", "infinite", "nan", "boolean"],
)
def test_lifecycle_rejects_invalid_deadlines_before_draining(
    invalid_deadline: float,
) -> None:
    async def exercise() -> None:
        events: list[str] = []
        controller = LifecycleController([RecordingLifecycle("runtime", events)])
        await controller.start()

        with pytest.raises(ValueError):
            await controller.drain(deadline=invalid_deadline)

        assert controller.state is LifecycleState.READY
        assert events == ["runtime.start"]

    asyncio.run(exercise())


@dataclass(slots=True)
class FailingStartLifecycle(RecordingLifecycle):
    async def start(self) -> None:
        self.events.append(f"{self.name}.start")
        raise RuntimeError("never-return-example-secret")


def test_start_failure_rolls_back_started_hooks_and_stops() -> None:
    async def exercise() -> None:
        events: list[str] = []
        controller = LifecycleController(
            [
                RecordingLifecycle("dependency", events),
                FailingStartLifecycle("failing", events),
                RecordingLifecycle("unreached", events),
            ]
        )

        with pytest.raises(LifecycleFailure) as captured:
            await controller.start()

        assert controller.state is LifecycleState.STOPPED
        assert captured.value.phase is LifecycleState.STARTUP
        assert captured.value.component == "failing"
        assert "never-return-example-secret" not in str(captured.value)
        assert events == [
            "dependency.start",
            "failing.start",
            "failing.stop",
            "dependency.stop",
        ]

    asyncio.run(exercise())


@dataclass(slots=True)
class FailingDrainLifecycle(RecordingLifecycle):
    async def drain(self, *, deadline: float) -> None:
        self.events.append(f"{self.name}.drain:{deadline}")
        raise RuntimeError("never-return-example-secret")


def test_drain_failure_runs_remaining_hooks_and_stays_draining() -> None:
    async def exercise() -> None:
        events: list[str] = []
        controller = LifecycleController(
            [
                RecordingLifecycle("dependency", events),
                FailingDrainLifecycle("listener", events),
            ]
        )
        await controller.start()

        with pytest.raises(LifecycleFailure) as captured:
            await controller.drain(deadline=42.0)

        assert controller.state is LifecycleState.DRAINING
        assert captured.value.phase is LifecycleState.DRAINING
        assert captured.value.component == "listener"
        assert events[-2:] == ["listener.drain:42.0", "dependency.drain:42.0"]

    asyncio.run(exercise())


@dataclass(slots=True)
class FailingStopLifecycle(RecordingLifecycle):
    async def stop(self) -> None:
        self.events.append(f"{self.name}.stop")
        raise RuntimeError("never-return-example-secret")


def test_stop_failure_runs_remaining_hooks_and_finishes_stopped() -> None:
    async def exercise() -> None:
        events: list[str] = []
        controller = LifecycleController(
            [
                RecordingLifecycle("dependency", events),
                FailingStopLifecycle("listener", events),
            ]
        )
        await controller.start()
        await controller.drain(deadline=42.0)

        with pytest.raises(LifecycleFailure) as captured:
            await controller.stop()

        assert controller.state is LifecycleState.STOPPED
        assert captured.value.phase is LifecycleState.STOPPED
        assert captured.value.component == "listener"
        assert events[-2:] == ["listener.stop", "dependency.stop"]

    asyncio.run(exercise())


def test_lifecycle_rejects_invalid_transitions_and_repeats_shutdown_safely() -> None:
    async def exercise() -> None:
        events: list[str] = []
        controller = LifecycleController([RecordingLifecycle("runtime", events)])

        with pytest.raises(LifecycleTransitionError):
            await controller.drain(deadline=42.0)
        await controller.start()
        with pytest.raises(LifecycleTransitionError):
            await controller.start()
        await controller.drain(deadline=42.0)
        await controller.drain(deadline=42.0)
        await controller.stop()
        await controller.stop()

        assert events == [
            "runtime.start",
            "runtime.drain:42.0",
            "runtime.stop",
        ]

    asyncio.run(exercise())


@given(
    operations=st.lists(
        st.sampled_from(["start", "drain", "stop"]),
        min_size=1,
        max_size=20,
    )
)
def test_generated_lifecycle_transitions_never_repeat_hooks(
    operations: list[str],
) -> None:
    async def exercise() -> None:
        events: list[str] = []
        controller = LifecycleController([RecordingLifecycle("runtime", events)])
        for operation in operations:
            try:
                if operation == "start":
                    await controller.start()
                elif operation == "drain":
                    await controller.drain(deadline=42.0)
                else:
                    await controller.stop()
            except LifecycleTransitionError:
                pass

        assert events.count("runtime.start") <= 1
        assert events.count("runtime.drain:42.0") <= 1
        assert events.count("runtime.stop") <= 1

    asyncio.run(exercise())


@dataclass(slots=True)
class BlockingStartLifecycle(RecordingLifecycle):
    entered: asyncio.Event
    release: asyncio.Event

    async def start(self) -> None:
        self.events.append(f"{self.name}.start")
        self.entered.set()
        await self.release.wait()


def test_concurrent_start_attempts_run_hooks_once() -> None:
    async def exercise() -> None:
        events: list[str] = []
        entered = asyncio.Event()
        release = asyncio.Event()
        second_attempted = asyncio.Event()
        controller = LifecycleController(
            [BlockingStartLifecycle("runtime", events, entered, release)]
        )

        first = asyncio.create_task(controller.start())
        await entered.wait()

        async def start_again() -> None:
            second_attempted.set()
            await controller.start()

        second = asyncio.create_task(start_again())
        await second_attempted.wait()
        release.set()
        results = await asyncio.gather(first, second, return_exceptions=True)

        assert events == ["runtime.start"]
        assert (
            sum(isinstance(result, LifecycleTransitionError) for result in results) == 1
        )
        assert controller.state is LifecycleState.READY

    asyncio.run(exercise())
