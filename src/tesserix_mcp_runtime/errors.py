"""Stable public error mapping with payload-free audit data."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any

from tesserix_mcp_runtime.contracts import (
    ErrorCode,
    ErrorResponse,
    InvocationResult,
    JsonValue,
)

_EXCEPTION_TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}\Z")


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


class RuntimeFailure(Exception):
    """Raise a known public failure without accepting unsafe message text."""

    def __init__(self, code: ErrorCode) -> None:
        if not _is_runtime_instance(code, ErrorCode):
            raise ValueError("code must be a stable ErrorCode")
        self.code = code
        super().__init__(code.value)


class TerminalEmitter:
    """Accept the first completion or cancellation result exactly once."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._ready = asyncio.Event()
        self._result: InvocationResult | None = None

    async def emit(self, result: InvocationResult) -> bool:
        if not _is_runtime_instance(result, InvocationResult):
            raise ValueError("result must satisfy the invocation result contract")
        async with self._lock:
            if self._result is not None:
                return False
            self._result = result
            self._ready.set()
            return True

    async def result(self) -> InvocationResult:
        await self._ready.wait()
        result = self._result
        if result is None:
            raise RuntimeError("terminal result invariant violated")
        return result


@dataclass(frozen=True, slots=True, kw_only=True)
class ScrubbedError:
    """Audit-safe failure identity that never contains exception text."""

    code: ErrorCode
    exception_type: str
    request_id: str

    def __post_init__(self) -> None:
        ErrorResponse.from_code(self.code, request_id=self.request_id)
        if (
            not _is_runtime_instance(self.exception_type, str)
            or _EXCEPTION_TYPE.fullmatch(self.exception_type) is None
        ):
            raise ValueError("exception_type must be a bounded type name")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "code": self.code.value,
            "exception_type": self.exception_type,
            "request_id": self.request_id,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class MappedError:
    """Pair one public failure with its matching audit-safe identity."""

    response: ErrorResponse
    audit: ScrubbedError

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.response, ErrorResponse) or not _is_runtime_instance(
            self.audit, ScrubbedError
        ):
            raise ValueError("mapped errors require response and audit contracts")
        if (
            self.response.code is not self.audit.code
            or self.response.request_id != self.audit.request_id
        ):
            raise ValueError("response and audit identities must match")


def map_exception(error: BaseException, *, request_id: str) -> MappedError:
    """Map any exception to stable public and audit-safe failure data."""

    if isinstance(error, RuntimeFailure):
        code = error.code
    elif isinstance(error, TimeoutError):
        code = ErrorCode.TIMEOUT
    elif isinstance(error, asyncio.CancelledError):
        code = ErrorCode.CANCELLED
    else:
        code = ErrorCode.INTERNAL_FAILURE
    exception_type = type(error).__name__
    if _EXCEPTION_TYPE.fullmatch(exception_type) is None:
        exception_type = "Exception"
    return MappedError(
        response=ErrorResponse.from_code(code, request_id=request_id),
        audit=ScrubbedError(
            code=code,
            exception_type=exception_type,
            request_id=request_id,
        ),
    )


__all__ = [
    "MappedError",
    "RuntimeFailure",
    "ScrubbedError",
    "TerminalEmitter",
    "map_exception",
]
