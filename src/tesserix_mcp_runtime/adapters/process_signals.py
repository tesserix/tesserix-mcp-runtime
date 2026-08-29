"""Scoped SIGINT and SIGTERM adapter for an application runner."""

from __future__ import annotations

import asyncio
import signal

from tesserix_mcp_runtime.application import ShutdownSignal


class ProcessSignalSource:
    """Wait for one process shutdown signal and then remove installed handlers."""

    async def wait(self) -> ShutdownSignal:
        loop = asyncio.get_running_loop()
        received: asyncio.Future[ShutdownSignal] = loop.create_future()

        def receive(value: ShutdownSignal) -> None:
            if not received.done():
                received.set_result(value)

        handlers = (
            (signal.SIGINT, ShutdownSignal.SIGINT),
            (signal.SIGTERM, ShutdownSignal.SIGTERM),
        )
        installed: list[signal.Signals] = []
        try:
            for process_signal, value in handlers:
                loop.add_signal_handler(process_signal, receive, value)
                installed.append(process_signal)
            return await received
        except NotImplementedError as error:
            raise RuntimeError("process signal handlers are unavailable") from error
        finally:
            for process_signal in installed:
                loop.remove_signal_handler(process_signal)


__all__ = ["ProcessSignalSource"]
