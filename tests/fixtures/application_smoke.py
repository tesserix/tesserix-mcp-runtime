from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Mapping
from typing import Any

from tesserix_mcp_runtime import (
    Application,
    ApplicationLimits,
    CallContext,
    JsonValue,
    ScrubbedError,
    ShutdownSignal,
    SystemClock,
    ToolCatalog,
    ToolDefinition,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport
from tesserix_mcp_runtime.adapters.process_signals import ProcessSignalSource

SECRET_CANARY = "startup-secret-must-not-escape"


class AllowAuthorizer:
    async def authorize(
        self,
        *,
        tool: ToolDefinition[Any, Any],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context


class NullTelemetry:
    def emit(self, event: ScrubbedError) -> None:
        del event


class FailingStartup:
    name = "failing_startup"

    async def start(self) -> None:
        raise RuntimeError(SECRET_CANARY)

    async def drain(self, *, deadline: float) -> None:
        del deadline

    async def stop(self) -> None:
        return None


class ReadySignalSource:
    def __init__(self) -> None:
        self._signals = ProcessSignalSource()

    async def wait(self) -> ShutdownSignal:
        loop = asyncio.get_running_loop()
        ready = loop.call_soon(self._report_ready)
        try:
            return await self._signals.wait()
        except BaseException:
            ready.cancel()
            raise

    @staticmethod
    def _report_ready() -> None:
        print(json.dumps({"state": "ready"}), flush=True)


async def run(mode: str) -> int:
    lifecycle = (FailingStartup(),) if mode == "fail-start" else ()
    application = Application(
        catalog=ToolCatalog([]),
        authorizer=AllowAuthorizer(),
        transport=InProcessTransport(),
        telemetry=NullTelemetry(),
        limits=ApplicationLimits(drain_timeout=2.0),
        clock=SystemClock(),
        lifecycle=lifecycle,
    )
    result = await application.run(ReadySignalSource())
    print(
        json.dumps(
            {
                "diagnostic": (
                    result.diagnostic.to_dict() if result.diagnostic is not None else None
                ),
                "exit_code": result.exit_code,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return result.exit_code


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"success", "fail-start"}:
        return 2
    return asyncio.run(run(sys.argv[1]))


if __name__ == "__main__":
    raise SystemExit(main())
