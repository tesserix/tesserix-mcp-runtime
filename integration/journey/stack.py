from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Protocol

_PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}\Z")
_PORT = re.compile(r"127\.0\.0\.1:([0-9]{1,5})\Z")
_SERVICES = frozenset(
    {
        "backing",
        "gateway-candidate",
        "gateway-good",
        "identity",
        "registry",
        "runtime-bad",
        "runtime-good",
    }
)
_COMMAND_TIMEOUT_SECONDS = 120.0
_MAX_LOG_BYTES = 1024 * 1024


class JourneyStackError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"journey_stack:{code}")


class CommandExecutor(Protocol):
    def run(
        self,
        arguments: tuple[str, ...],
        *,
        environment: dict[str, str],
        timeout_seconds: float,
    ) -> str: ...


class SubprocessCommandExecutor:
    def run(
        self,
        arguments: tuple[str, ...],
        *,
        environment: dict[str, str],
        timeout_seconds: float,
    ) -> str:
        try:
            completed = subprocess.run(
                arguments,
                capture_output=True,
                check=False,
                env=environment,
                text=True,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise JourneyStackError("command_unavailable") from error
        if completed.returncode != 0:
            raise JourneyStackError("command_failed")
        return completed.stdout


class ComposeStack:
    def __init__(
        self,
        *,
        compose_file: Path,
        project_name: str,
        runtime_image: str,
        registry_image: str,
        output_dir: Path,
        executor: CommandExecutor | None = None,
        executable: tuple[str, ...] = ("docker", "compose"),
        inherited_environment: dict[str, str] | None = None,
    ) -> None:
        if (
            not isinstance(compose_file, Path)
            or not compose_file.is_absolute()
            or not compose_file.is_file()
            or not isinstance(output_dir, Path)
            or not output_dir.is_absolute()
            or not isinstance(project_name, str)
            or _PROJECT.fullmatch(project_name) is None
            or not isinstance(runtime_image, str)
            or _IMAGE.fullmatch(runtime_image) is None
            or not isinstance(registry_image, str)
            or _IMAGE.fullmatch(registry_image) is None
            or not isinstance(executable, tuple)
            or not executable
            or any(not isinstance(item, str) or not item for item in executable)
        ):
            raise ValueError("journey stack configuration is invalid")
        environment = dict(os.environ if inherited_environment is None else inherited_environment)
        environment.update(
            {
                "COMPOSE_PROJECT_NAME": project_name,
                "JOURNEY_OUTPUT_DIR": str(output_dir),
                "JOURNEY_REGISTRY_IMAGE": registry_image,
                "JOURNEY_RUNTIME_IMAGE": runtime_image,
            }
        )
        self._command = (
            *executable,
            "--project-name",
            project_name,
            "--file",
            str(compose_file),
        )
        self._environment = environment
        self._executor = SubprocessCommandExecutor() if executor is None else executor

    def validate(self) -> None:
        self._run("config", "--quiet")

    def up(self, *services: str) -> None:
        selected = self._selected(services)
        self._run("up", "--detach", "--no-build", *selected)

    def stop(self, *services: str) -> None:
        self._run("stop", *self._selected(services))

    def start(self, *services: str) -> None:
        self._run("start", *self._selected(services))

    def start_and_resolve_origin(self, service: str, container_port: int) -> str:
        self.start(service)
        return self.origin(service, container_port)

    def down(self) -> None:
        self._run("down", "--volumes", "--remove-orphans", "--timeout", "10")

    def origin(self, service: str, container_port: int) -> str:
        selected = self._selected((service,))[0]
        if isinstance(container_port, bool) or not isinstance(container_port, int):
            raise ValueError("container port must be an integer")
        output = self._run("port", selected, str(container_port)).strip()
        matched = _PORT.fullmatch(output)
        if matched is None:
            raise JourneyStackError("port_invalid")
        published = int(matched.group(1))
        if not 1 <= published <= 65_535:
            raise JourneyStackError("port_invalid")
        return f"http://127.0.0.1:{published}"

    def logs(self, *services: str) -> bytes:
        output = self._run(
            "logs",
            "--no-color",
            "--timestamps",
            *self._selected(services),
        ).encode()
        if len(output) > _MAX_LOG_BYTES:
            raise JourneyStackError("logs_too_large")
        return output

    @staticmethod
    def _selected(services: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not services
            or len(services) > len(_SERVICES)
            or len(set(services)) != len(services)
            or any(service not in _SERVICES for service in services)
        ):
            raise ValueError("journey services must be unique and allowlisted")
        return services

    def _run(self, *arguments: str) -> str:
        return self._executor.run(
            (*self._command, *arguments),
            environment=dict(self._environment),
            timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        )


__all__ = [
    "CommandExecutor",
    "ComposeStack",
    "JourneyStackError",
    "SubprocessCommandExecutor",
]
