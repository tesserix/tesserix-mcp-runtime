from __future__ import annotations

import asyncio
import signal
from collections.abc import Callable

import pytest

from tesserix_mcp_runtime import ShutdownSignal, SystemClock
from tesserix_mcp_runtime.adapters.process_signals import ProcessSignalSource


class FakeSignalLoop:
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        *,
        supported: bool,
    ) -> None:
        self._loop = loop
        self._supported = supported
        self._handlers: dict[
            signal.Signals,
            tuple[Callable[..., None], tuple[object, ...]],
        ] = {}
        self.removed: list[signal.Signals] = []

    def create_future(self) -> asyncio.Future[ShutdownSignal]:
        return self._loop.create_future()

    def add_signal_handler(
        self,
        process_signal: signal.Signals,
        callback: Callable[..., None],
        *args: object,
    ) -> None:
        if not self._supported:
            raise NotImplementedError
        self._handlers[process_signal] = (callback, args)
        if process_signal is signal.SIGTERM:
            interrupt, interrupt_args = self._handlers[signal.SIGINT]
            self._loop.call_soon(interrupt, *interrupt_args)
            self._loop.call_soon(callback, *args)

    def remove_signal_handler(self, process_signal: signal.Signals) -> bool:
        self.removed.append(process_signal)
        return True


def test_process_signal_source_maps_once_and_removes_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        fake = FakeSignalLoop(asyncio.get_running_loop(), supported=True)
        monkeypatch.setattr(asyncio, "get_running_loop", lambda: fake)

        received = await ProcessSignalSource().wait()

        assert received is ShutdownSignal.SIGINT
        assert fake.removed == [signal.SIGINT, signal.SIGTERM]

    asyncio.run(exercise())


def test_process_signal_source_reports_an_unsupported_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        fake = FakeSignalLoop(asyncio.get_running_loop(), supported=False)
        monkeypatch.setattr(asyncio, "get_running_loop", lambda: fake)

        with pytest.raises(RuntimeError, match="process signal handlers are unavailable"):
            await ProcessSignalSource().wait()

        assert fake.removed == []

    asyncio.run(exercise())


def test_system_clock_uses_monotonic_time_and_cancellable_sleep() -> None:
    async def exercise() -> None:
        clock = SystemClock()
        before = clock.now()
        await clock.sleep(0)
        assert clock.now() >= before

    asyncio.run(exercise())
