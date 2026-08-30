"""Bounded no-shell delegated command execution."""

from __future__ import annotations

import asyncio
import os
import re
import signal
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from tesserix_mcp_runtime import RedactionPolicy

from .errors import PublicationError, PublicationErrorCode

_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


@dataclass(frozen=True, slots=True, kw_only=True)
class CommandLimits:
    """Hard-capped child lifetime, arguments, and captured output."""

    timeout_seconds: float = 30.0
    max_arguments: int = 16
    max_argument_bytes: int = 4_096
    max_stdout_bytes: int = 512 * 1024
    max_stderr_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        values = (
            (self.timeout_seconds, 0.01, 120.0),
            (self.max_arguments, 1, 32),
            (self.max_argument_bytes, 1, 8_192),
            (self.max_stdout_bytes, 1, 1024 * 1024),
            (self.max_stderr_bytes, 1, 256 * 1024),
        )
        if any(
            not _is_number(value) or not lower <= value <= upper for value, lower, upper in values
        ):
            raise ValueError("command limits must be within hard bounds")


_DEFAULT_LIMITS = CommandLimits()


@dataclass(frozen=True, slots=True, kw_only=True)
class CommandResult:
    """Bounded raw result handed immediately to a secret-safe adapter."""

    exit_code: int
    stdout: bytes
    stderr: bytes

    def __post_init__(self) -> None:
        if (
            _is_runtime_instance(self.exit_code, bool)
            or not _is_runtime_instance(self.exit_code, int)
            or not 0 <= self.exit_code <= 255
            or not _is_runtime_instance(self.stdout, bytes)
            or not _is_runtime_instance(self.stderr, bytes)
        ):
            raise ValueError("command result must contain typed process output")


@runtime_checkable
class CommandRunner(Protocol):
    """Replaceable bounded argv-only child-process boundary."""

    async def run(
        self,
        arguments: tuple[str, ...],
        *,
        request_id: str,
    ) -> CommandResult: ...


class _OutputLimitError(Exception):
    pass


async def _read_bounded(
    stream: asyncio.StreamReader,
    *,
    maximum: int,
) -> bytes:
    output = bytearray()
    while True:
        chunk = await stream.read(min(64 * 1024, maximum + 1 - len(output)))
        if not chunk:
            return bytes(output)
        output.extend(chunk)
        if len(output) > maximum:
            raise _OutputLimitError


async def _terminate(process: asyncio.subprocess.Process) -> None:
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    await process.wait()


class SubprocessCommandRunner:
    """Execute an explicit argv tuple without a shell and with finite capture."""

    def __init__(
        self,
        *,
        redactor: RedactionPolicy,
        limits: CommandLimits = _DEFAULT_LIMITS,
    ) -> None:
        if not _is_runtime_instance(redactor, RedactionPolicy):
            raise TypeError("redactor must implement RedactionPolicy")
        if not _is_runtime_instance(limits, CommandLimits):
            raise TypeError("limits must be CommandLimits")
        self._redactor = redactor
        self._limits = limits

    async def run(
        self,
        arguments: tuple[str, ...],
        *,
        request_id: str,
    ) -> CommandResult:
        if (
            not _is_runtime_instance(arguments, tuple)
            or not arguments
            or len(arguments) > self._limits.max_arguments
            or not _is_runtime_instance(request_id, str)
            or _REQUEST_ID.fullmatch(request_id) is None
        ):
            raise PublicationError(
                PublicationErrorCode.COMMAND_FAILED,
                request_id="publication-command",
            )
        try:
            for argument in arguments:
                if (
                    not _is_runtime_instance(argument, str)
                    or not argument
                    or len(argument.encode("utf-8")) > self._limits.max_argument_bytes
                    or any(character in argument for character in ("\x00", "\r", "\n"))
                    or self._redactor.redact_text(argument) != argument
                ):
                    raise PublicationError(
                        PublicationErrorCode.SECRET_MATERIAL,
                        request_id=request_id,
                    )
            process = await asyncio.create_subprocess_exec(
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=os.name != "nt",
            )
        except PublicationError:
            raise
        except (OSError, ValueError):
            raise PublicationError(
                PublicationErrorCode.UNAVAILABLE,
                request_id=request_id,
            ) from None
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_task = asyncio.create_task(
            _read_bounded(process.stdout, maximum=self._limits.max_stdout_bytes)
        )
        stderr_task = asyncio.create_task(
            _read_bounded(process.stderr, maximum=self._limits.max_stderr_bytes)
        )
        try:
            async with asyncio.timeout(self._limits.timeout_seconds):
                stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
                exit_code = await process.wait()
        except asyncio.CancelledError:
            await _terminate(process)
            stdout_task.cancel()
            stderr_task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            raise
        except TimeoutError:
            await _terminate(process)
            stdout_task.cancel()
            stderr_task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            raise PublicationError(
                PublicationErrorCode.UNAVAILABLE,
                request_id=request_id,
                retryable=True,
            ) from None
        except _OutputLimitError:
            await _terminate(process)
            stdout_task.cancel()
            stderr_task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            raise PublicationError(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            ) from None
        return CommandResult(exit_code=exit_code, stdout=stdout, stderr=stderr)


__all__ = [
    "CommandLimits",
    "CommandResult",
    "CommandRunner",
    "SubprocessCommandRunner",
]
