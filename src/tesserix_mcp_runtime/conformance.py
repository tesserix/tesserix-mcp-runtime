"""Reusable adapter-neutral conformance checks for typed tool invocation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from tesserix_mcp_runtime.contracts import (
    ErrorCode,
    InvocationResult,
    InvocationStatus,
    JsonValue,
)


@runtime_checkable
class ConformanceAdapter(Protocol):
    """Minimal adapter surface exercised by the reusable contract suite."""

    async def list_tools(self) -> tuple[str, ...]: ...

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
    ) -> InvocationResult: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class ConformanceCase:
    """One portable happy-path and invalid-input adapter scenario."""

    tool_name: str
    valid_arguments: Mapping[str, JsonValue]
    expected_value: JsonValue
    invalid_arguments: Mapping[str, JsonValue]


class ConformanceFailure(AssertionError):
    """Identify a stable adapter conformance failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


async def assert_adapter_conforms(
    adapter: ConformanceAdapter,
    case: ConformanceCase,
) -> None:
    """Verify listing, valid invocation, invalid input, and unknown tools."""

    names = await adapter.list_tools()
    if names.count(case.tool_name) != 1:
        raise ConformanceFailure("tool_listing_mismatch")

    succeeded = await adapter.invoke(case.tool_name, case.valid_arguments)
    if (
        succeeded.status is not InvocationStatus.SUCCESS
        or succeeded.value != case.expected_value
    ):
        raise ConformanceFailure("valid_invocation_mismatch")

    invalid = await adapter.invoke(case.tool_name, case.invalid_arguments)
    if (
        invalid.status is not InvocationStatus.FAILURE
        or invalid.error is None
        or invalid.error.code is not ErrorCode.INVALID_INPUT
    ):
        raise ConformanceFailure("invalid_input_mismatch")

    unknown = await adapter.invoke(f"{case.tool_name}.missing", {})
    if (
        unknown.status is not InvocationStatus.FAILURE
        or unknown.error is None
        or unknown.error.code is not ErrorCode.INVALID_INPUT
    ):
        raise ConformanceFailure("unknown_tool_mismatch")


__all__ = [
    "ConformanceAdapter",
    "ConformanceCase",
    "ConformanceFailure",
    "assert_adapter_conforms",
]
