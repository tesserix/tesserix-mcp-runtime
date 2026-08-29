"""Standard monotonic clock implementation for production composition."""

from __future__ import annotations

import asyncio
import time


class SystemClock:
    """Use the process monotonic clock and cancellable asyncio timers."""

    def now(self) -> float:
        return time.monotonic()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


__all__ = ["SystemClock"]
