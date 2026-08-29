"""Deterministic in-process transport for composition and conformance tests."""

from __future__ import annotations

from collections.abc import Mapping

from tesserix_mcp_runtime.application import ApplicationEndpoint
from tesserix_mcp_runtime.contracts import (
    CallContext,
    ErrorCode,
    ErrorResponse,
    InvocationResult,
    JsonValue,
)


class InProcessTransport:
    """Forward calls to one explicitly bound application without network I/O."""

    name = "in_process_transport"

    def __init__(self) -> None:
        self._endpoint: ApplicationEndpoint | None = None
        self._accepting = False

    async def start(self, endpoint: ApplicationEndpoint) -> None:
        self._endpoint = endpoint
        self._accepting = True

    async def drain(self, *, deadline: float) -> None:
        del deadline
        self._accepting = False

    async def stop(self) -> None:
        self._accepting = False
        self._endpoint = None

    async def list_tools(self) -> tuple[str, ...]:
        endpoint = self._endpoint
        if endpoint is None or not self._accepting:
            return ()
        return endpoint.list_tools()

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> InvocationResult:
        endpoint = self._endpoint
        if endpoint is None or not self._accepting:
            return InvocationResult.failure(
                ErrorResponse.from_code(ErrorCode.UNAVAILABLE, request_id=context.request_id)
            )
        return await endpoint.invoke(name, arguments, context=context)


__all__ = ["InProcessTransport"]
