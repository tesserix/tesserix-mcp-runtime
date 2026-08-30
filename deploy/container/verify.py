from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from importlib.metadata import version
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import PaginatedRequestParams, TextContent

_CONTAINER_PORT = 8000
_COMMAND_TIMEOUT_SECONDS = 60.0
_PROBE_TIMEOUT_SECONDS = 30.0


class ContainerVerificationError(RuntimeError):
    pass


def hardened_docker_run_command(image: str) -> tuple[str, ...]:
    return (
        "docker",
        "run",
        "--detach",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=67108864",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--user",
        "10001:10001",
        "--publish",
        "127.0.0.1::8000",
        "--label",
        "tesserix.mcp-runtime.verification=true",
        image,
    )


def _run(arguments: Sequence[str], *, timeout: float = _COMMAND_TIMEOUT_SECONDS) -> str:
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise ContainerVerificationError("bounded command timed out") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip()[-2_000:]
        raise ContainerVerificationError(
            f"command failed with exit code {completed.returncode}: {detail}"
        )
    return completed.stdout


def _run_for_cleanup(arguments: Sequence[str]) -> None:
    subprocess.run(
        arguments,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )


def _docker_document(kind: str, identifier: str) -> dict[str, Any]:
    document = json.loads(_run(("docker", kind, "inspect", identifier)))
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise ContainerVerificationError(f"docker {kind} inspect returned an invalid document")
    return document[0]


def _published_port(container_id: str) -> int:
    lines = _run(("docker", "port", container_id, f"{_CONTAINER_PORT}/tcp")).splitlines()
    loopback = [line for line in lines if line.startswith("127.0.0.1:")]
    if len(loopback) != 1:
        raise ContainerVerificationError("container did not publish exactly one IPv4 loopback port")
    try:
        port = int(loopback[0].rsplit(":", 1)[1])
    except ValueError as error:
        raise ContainerVerificationError("docker returned an invalid published port") from error
    if not 1 <= port <= 65_535:
        raise ContainerVerificationError("docker returned an out-of-range published port")
    return port


def _http_status(url: str) -> int:
    request = Request(
        url,
        method="GET",
        headers={"Host": "127.0.0.1", "User-Agent": "tesserix-container-verifier"},
    )
    try:
        with urlopen(request, timeout=2) as response:
            response.read(4_097)
            return response.status
    except HTTPError as error:
        error.close()
        return error.code
    except (URLError, ConnectionError, TimeoutError):
        return 0


def _wait_for_status(url: str, expected: set[int], *, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    last_status = 0
    while time.monotonic() < deadline:
        last_status = _http_status(url)
        if last_status in expected:
            return last_status
        time.sleep(0.05)
    raise ContainerVerificationError(
        f"endpoint did not reach an expected status; last status was {last_status}"
    )


def _structured_status(result: object) -> dict[str, int]:
    content = getattr(result, "content", None)
    is_error = getattr(result, "is_error", True)
    if is_error or not isinstance(content, list) or not content:
        raise ContainerVerificationError("cancellation probe returned an error")
    first = content[0]
    if not isinstance(first, TextContent):
        raise ContainerVerificationError("cancellation probe returned unexpected content")
    document = json.loads(first.text)
    if (
        not isinstance(document, dict)
        or type(document.get("active")) is not int
        or type(document.get("observed")) is not int
    ):
        raise ContainerVerificationError("cancellation probe returned an invalid status")
    return {"active": document["active"], "observed": document["observed"]}


@asynccontextmanager
async def _mcp_session(endpoint: str) -> AsyncIterator[ClientSession]:
    async with (
        httpx.AsyncClient(headers={"host": "127.0.0.1"}, timeout=10.0) as http_client,
        streamable_http_client(
            endpoint,
            http_client=http_client,
            terminate_on_close=False,
        ) as streams,
        ClientSession(streams[0], streams[1]) as session,
    ):
        yield session


async def _list_all_tools(session: ClientSession) -> tuple[set[str], int]:
    names: set[str] = set()
    cursor: str | None = None
    pages = 0
    while True:
        params = None if cursor is None else PaginatedRequestParams(cursor=cursor)
        listed = await session.list_tools(params=params)
        names.update(tool.name for tool in listed.tools)
        pages += 1
        cursor = listed.next_cursor
        if cursor is None:
            return names, pages
        if pages >= 4:
            raise ContainerVerificationError("tool pagination did not terminate")


async def _exercise_mcp(endpoint: str, expected_sdk: str) -> dict[str, object]:
    actual_sdk = version("mcp")
    if actual_sdk != expected_sdk:
        raise ContainerVerificationError(f"expected MCP SDK {expected_sdk}, resolved {actual_sdk}")
    async with _mcp_session(endpoint) as session:
        initialized = await session.initialize()
        names, pages = await _list_all_tools(session)
        if names != {"always_fails", "cancellation_probe", "echo"} or pages != 2:
            raise ContainerVerificationError("container returned an unexpected tool catalog")
        succeeded = await session.call_tool("echo", {"text": "container-verification"})
        if succeeded.is_error or not succeeded.content:
            raise ContainerVerificationError("container echo tool failed")
        first = succeeded.content[0]
        if not isinstance(first, TextContent) or json.loads(first.text) != {
            "text": "container-verification"
        }:
            raise ContainerVerificationError("container echo tool returned unexpected content")
        failed = await session.call_tool("always_fails")
        if not failed.is_error:
            raise ContainerVerificationError("container failure tool returned success")
        protocol = str(initialized.protocol_version)
    return {
        "sdk": actual_sdk,
        "protocol": protocol,
        "tool_pages": pages,
        "tools": sorted(names),
        "echo": True,
        "tool_error": True,
    }


async def _hold_cancellation_probe(endpoint: str) -> None:
    async with _mcp_session(endpoint) as session:
        await session.initialize()
        await _list_all_tools(session)
        await session.call_tool("cancellation_probe", {"action": "wait"})


async def _signal_and_observe_drain(
    endpoint: str,
    readiness_url: str,
    container_id: str,
) -> dict[str, object]:
    readiness_status = 0
    active_before_signal = 0
    pending: asyncio.Task[None] | None = None
    async with _mcp_session(endpoint) as session:
        await session.initialize()
        await _list_all_tools(session)
        baseline = _structured_status(
            await session.call_tool("cancellation_probe", {"action": "status"})
        )
        pending = asyncio.create_task(_hold_cancellation_probe(endpoint))
        try:
            async with asyncio.timeout(5):
                while True:
                    if pending.done():
                        raise ContainerVerificationError("in-flight MCP call exited before SIGTERM")
                    status = _structured_status(
                        await session.call_tool("cancellation_probe", {"action": "status"})
                    )
                    active_before_signal = status["active"]
                    if active_before_signal > 0:
                        break
                    await asyncio.sleep(0.01)
            await asyncio.to_thread(
                _run,
                ("docker", "kill", "--signal", "TERM", container_id),
            )
            readiness_status = await asyncio.to_thread(
                _wait_for_status,
                readiness_url,
                {503},
                timeout=5.0,
            )
        finally:
            if pending is not None:
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
    return {
        "signal": "SIGTERM",
        "readiness_status": readiness_status,
        "in_flight_before_signal": active_before_signal,
        "cancellations_before_signal": baseline["observed"],
    }


def _assert_no_runtime_shell(image: str) -> None:
    for shell in ("/bin/sh", "/bin/bash", "/usr/bin/bash"):
        completed = subprocess.run(
            ("docker", "run", "--rm", "--entrypoint", shell, image, "-c", "exit 0"),
            capture_output=True,
            check=False,
            text=True,
            timeout=15,
        )
        if completed.returncode == 0:
            raise ContainerVerificationError(f"runtime image exposes a shell at {shell}")


def _assert_no_runtime_pip(image: str) -> None:
    for interpreter in (
        "/usr/local/bin/python",
        "/opt/app/bin/python",
        "/opt/adk-venv/bin/python",
    ):
        completed = subprocess.run(
            (
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                interpreter,
                image,
                "-m",
                "pip",
                "--version",
            ),
            capture_output=True,
            check=False,
            text=True,
            timeout=15,
        )
        if completed.returncode == 0:
            raise ContainerVerificationError(f"runtime image exposes pip through {interpreter}")


def verify(
    *,
    image: str,
    variant: str,
    base_image: str,
    expected_sdk: str,
) -> dict[str, object]:
    image_document = _docker_document("image", image)
    config = image_document.get("Config")
    if not isinstance(config, dict) or config.get("User") != "10001:10001":
        raise ContainerVerificationError("runtime image user is not uid/gid 10001")
    entrypoint = config.get("Entrypoint")
    if not isinstance(entrypoint, list) or entrypoint[:2] != ["/usr/bin/tini", "--"]:
        raise ContainerVerificationError("runtime image entrypoint does not use tini")
    _assert_no_runtime_shell(image)
    _assert_no_runtime_pip(image)

    container_id: str | None = None
    try:
        container_id = _run(hardened_docker_run_command(image)).strip()
        if not container_id:
            raise ContainerVerificationError("docker did not return a container id")
        container_document = _docker_document("container", container_id)
        host_config = container_document.get("HostConfig")
        if not isinstance(host_config, dict):
            raise ContainerVerificationError("docker omitted the container host configuration")
        if host_config.get("ReadonlyRootfs") is not True:
            raise ContainerVerificationError("container root filesystem is writable")
        if host_config.get("CapDrop") != ["ALL"]:
            raise ContainerVerificationError("container capabilities were not dropped")
        if host_config.get("SecurityOpt") != ["no-new-privileges:true"]:
            raise ContainerVerificationError("container allows privilege escalation")
        tmpfs = host_config.get("Tmpfs")
        if not isinstance(tmpfs, dict) or "/tmp" not in tmpfs:
            raise ContainerVerificationError("container has no bounded writable temp filesystem")

        port = _published_port(container_id)
        base_url = f"http://127.0.0.1:{port}"
        probes = {
            path: _wait_for_status(
                f"{base_url}{path}",
                {200},
                timeout=_PROBE_TIMEOUT_SECONDS,
            )
            for path in ("/startupz", "/readyz", "/livez")
        }
        endpoint = f"{base_url}/mcp"
        mcp_report = asyncio.run(_exercise_mcp(endpoint, expected_sdk))
        drain_report = asyncio.run(
            _signal_and_observe_drain(endpoint, f"{base_url}/readyz", container_id)
        )
        exit_code = int(_run(("docker", "wait", container_id), timeout=45.0).strip())
        if exit_code != 0:
            logs = _run(("docker", "logs", container_id), timeout=10.0).strip()[-2_000:]
            raise ContainerVerificationError(
                f"container exited with {exit_code} after SIGTERM: {logs}"
            )
    finally:
        if container_id is not None:
            _run_for_cleanup(("docker", "rm", "--force", container_id))

    return {
        "schema_version": 1,
        "variant": variant,
        "image": image,
        "base_image": base_image,
        "image_id": image_document.get("Id"),
        "image_size_bytes": image_document.get("Size"),
        "user": config["User"],
        "entrypoint": entrypoint,
        "command": config.get("Cmd"),
        "runtime_shell": False,
        "runtime_pip": False,
        "read_only_root": True,
        "tmpfs": "/tmp",
        "capabilities_dropped": ["ALL"],
        "probes": probes,
        "mcp": mcp_report,
        "termination": {**drain_report, "exit_code": exit_code},
        "passed": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-run-command", metavar="IMAGE")
    parser.add_argument("--image")
    parser.add_argument("--variant", choices=("core", "adk"))
    parser.add_argument("--base-image")
    parser.add_argument("--expected-sdk")
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    parser = _parser()
    arguments = parser.parse_args()
    if arguments.print_run_command is not None:
        print(json.dumps(hardened_docker_run_command(arguments.print_run_command)))
        return 0
    required = {
        "--image": arguments.image,
        "--variant": arguments.variant,
        "--base-image": arguments.base_image,
        "--expected-sdk": arguments.expected_sdk,
        "--output": arguments.output,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        parser.error(f"required verification arguments: {', '.join(missing)}")
    try:
        report = verify(
            image=arguments.image,
            variant=arguments.variant,
            base_image=arguments.base_image,
            expected_sdk=arguments.expected_sdk,
        )
    except ContainerVerificationError as error:
        print(str(error), file=sys.stderr)
        return 1
    output: Path = arguments.output
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
