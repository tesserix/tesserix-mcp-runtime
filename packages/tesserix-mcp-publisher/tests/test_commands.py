from __future__ import annotations

import asyncio
import os
import signal
import sys
from collections.abc import Callable
from typing import cast

import pytest
from tesserix_mcp_publisher import (
    CommandLimits,
    CommandResult,
    PublicationError,
    PublicationErrorCode,
    SubprocessCommandRunner,
)

from tesserix_mcp_runtime import RedactionPolicy, SecretRedactor, SecretValue


class WaitingProcess:
    def __init__(self) -> None:
        self.pid = 4_242
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._terminated = asyncio.Event()

    async def wait(self) -> int:
        await self._terminated.wait()
        return -signal.SIGKILL

    def kill(self) -> None:
        self._terminated.set()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: CommandLimits(timeout_seconds=True),
        lambda: CommandLimits(max_arguments=0),
        lambda: CommandLimits(max_argument_bytes=8_193),
        lambda: CommandLimits(max_stdout_bytes=1024 * 1024 + 1),
        lambda: CommandLimits(max_stderr_bytes=256 * 1024 + 1),
    ],
)
def test_command_limits_reject_values_outside_hard_bounds(
    factory: Callable[[], CommandLimits],
) -> None:
    with pytest.raises(ValueError):
        factory()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: CommandResult(exit_code=True, stdout=b"", stderr=b""),
        lambda: CommandResult(exit_code=256, stdout=b"", stderr=b""),
        lambda: CommandResult(exit_code=0, stdout=cast(bytes, "text"), stderr=b""),
    ],
)
def test_command_result_rejects_untyped_or_impossible_process_values(
    factory: Callable[[], CommandResult],
) -> None:
    with pytest.raises(ValueError):
        factory()


def test_subprocess_runner_rejects_invalid_construction_and_invocation() -> None:
    with pytest.raises(TypeError):
        SubprocessCommandRunner(redactor=cast(RedactionPolicy, object()))
    with pytest.raises(TypeError):
        SubprocessCommandRunner(
            redactor=SecretRedactor(),
            limits=cast(CommandLimits, object()),
        )

    runner = SubprocessCommandRunner(redactor=SecretRedactor())
    with pytest.raises(PublicationError) as caught:
        asyncio.run(runner.run((), request_id="request-empty"))
    assert caught.value.code is PublicationErrorCode.COMMAND_FAILED

    with pytest.raises(PublicationError) as caught:
        asyncio.run(runner.run(("command",), request_id="invalid request"))
    assert caught.value.code is PublicationErrorCode.COMMAND_FAILED


@pytest.mark.parametrize(
    "argument",
    ["line\nbreak", "x" * 4_097, "SyntheticCommandSecret8Kq3"],
    ids=["line-break", "oversized", "secret"],
)
def test_subprocess_runner_rejects_unsafe_arguments(argument: str) -> None:
    runner = SubprocessCommandRunner(
        redactor=SecretRedactor(
            known_secrets=(SecretValue("SyntheticCommandSecret8Kq3"),),
        )
    )

    with pytest.raises(PublicationError) as caught:
        asyncio.run(runner.run((argument,), request_id="request-unsafe-argument"))

    assert caught.value.code is PublicationErrorCode.SECRET_MATERIAL


def test_subprocess_runner_maps_spawn_and_output_limit_failures() -> None:
    runner = SubprocessCommandRunner(
        redactor=SecretRedactor(),
        limits=CommandLimits(max_stdout_bytes=64),
    )

    with pytest.raises(PublicationError) as caught:
        asyncio.run(
            runner.run(
                ("tesserix-command-that-does-not-exist",),
                request_id="request-missing-command",
            )
        )
    assert caught.value.code is PublicationErrorCode.UNAVAILABLE
    assert caught.value.retryable is False

    with pytest.raises(PublicationError) as caught:
        asyncio.run(
            runner.run(
                (sys.executable, "-c", "import sys; sys.stdout.write('x' * 65)"),
                request_id="request-output-limit",
            )
        )
    assert caught.value.code is PublicationErrorCode.COMMAND_OUTPUT_INVALID


@pytest.mark.skipif(os.name == "nt", reason="POSIX process groups are unavailable")
def test_subprocess_runner_terminates_the_process_group_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> tuple[int, list[tuple[int, int]], PublicationError]:
        process = WaitingProcess()
        killed: list[tuple[int, int]] = []

        async def create_process(
            *arguments: str,
            **options: object,
        ) -> asyncio.subprocess.Process:
            assert arguments == ("agentic", "status")
            assert options["start_new_session"] is True
            return cast(asyncio.subprocess.Process, process)

        def kill_group(process_group: int, signal_number: int) -> None:
            killed.append((process_group, signal_number))
            process.kill()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(os, "killpg", kill_group)
        runner = SubprocessCommandRunner(
            redactor=SecretRedactor(),
            limits=CommandLimits(timeout_seconds=0.01),
        )

        with pytest.raises(PublicationError) as caught:
            await runner.run(("agentic", "status"), request_id="request-timeout-group")
        return process.pid, killed, caught.value

    process_id, killed, error = asyncio.run(exercise())

    assert error.code is PublicationErrorCode.UNAVAILABLE
    assert killed == [(process_id, signal.SIGKILL)]


@pytest.mark.skipif(os.name == "nt", reason="POSIX process groups are unavailable")
def test_subprocess_runner_terminates_the_process_group_when_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> tuple[int, list[tuple[int, int]]]:
        process = WaitingProcess()
        spawned = asyncio.Event()
        killed: list[tuple[int, int]] = []

        async def create_process(
            *arguments: str,
            **options: object,
        ) -> asyncio.subprocess.Process:
            del arguments, options
            spawned.set()
            return cast(asyncio.subprocess.Process, process)

        def kill_group(process_group: int, signal_number: int) -> None:
            killed.append((process_group, signal_number))
            process.kill()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(os, "killpg", kill_group)
        runner = SubprocessCommandRunner(redactor=SecretRedactor())
        running = asyncio.create_task(
            runner.run(("agentic", "status"), request_id="request-cancel-group")
        )
        await spawned.wait()
        running.cancel()

        with pytest.raises(asyncio.CancelledError):
            await running
        return process.pid, killed

    process_id, killed = asyncio.run(exercise())

    assert killed == [(process_id, signal.SIGKILL)]
