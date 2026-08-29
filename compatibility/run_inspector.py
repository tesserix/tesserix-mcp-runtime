from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from run_matrix import available_port, wait_until_listening

ROOT = Path(__file__).parent
INSPECTOR_VERSION = "2.4.0"


def inspector_command(endpoint: str, *arguments: str) -> list[str]:
    return [
        "npx",
        "--yes",
        f"@modelcontextprotocol/inspector@{INSPECTOR_VERSION}",
        "--cli",
        "--server-url",
        endpoint,
        "--transport",
        "http",
        *arguments,
        "--format",
        "json",
    ]


def inspect(endpoint: str, *arguments: str) -> dict[str, object]:
    completed = subprocess.run(
        inspector_command(endpoint, *arguments),
        cwd=ROOT.parent,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Inspector failed with {completed.returncode}: {completed.stderr}")
    document = json.loads(completed.stdout)
    if not isinstance(document, dict):
        raise RuntimeError("Inspector returned a non-object report")
    return document


def cancellation_status(endpoint: str) -> tuple[int, int]:
    report = inspect(
        endpoint,
        "--method",
        "tools/call",
        "--tool-name",
        "cancellation_probe",
        "--tool-args-json",
        '{"action":"status"}',
    )
    result = report.get("result")
    structured = result.get("structuredContent") if isinstance(result, dict) else None
    if (
        not isinstance(structured, dict)
        or type(structured.get("active")) is not int
        or type(structured.get("observed")) is not int
    ):
        raise RuntimeError("Inspector cancellation probe returned an invalid status")
    return structured["active"], structured["observed"]


def main() -> int:
    port = available_port()
    endpoint = f"http://127.0.0.1:{port}/mcp"
    server = subprocess.Popen(
        [
            "uv",
            "run",
            "--frozen",
            "python",
            str(ROOT / "server.py"),
            "--port",
            str(port),
        ],
        cwd=ROOT.parent,
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        text=True,
    )
    cancelling: subprocess.Popen[str] | None = None
    try:
        wait_until_listening(server, port)
        listed = inspect(
            endpoint,
            "--method",
            "tools/list",
            "--strict",
        )
        called = inspect(
            endpoint,
            "--method",
            "tools/call",
            "--tool-name",
            "echo",
            "--tool-args-json",
            '{"text":"inspector"}',
        )
        active, observed = cancellation_status(endpoint)
        if active != 0:
            raise RuntimeError("Inspector cancellation probe was already active")
        cancelling = subprocess.Popen(
            inspector_command(
                endpoint,
                "--method",
                "tools/call",
                "--tool-name",
                "cancellation_probe",
                "--tool-args-json",
                '{"action":"wait"}',
            ),
            cwd=ROOT.parent,
            stderr=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            text=True,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if cancelling.poll() is not None:
                stderr = cancelling.stderr.read() if cancelling.stderr is not None else ""
                raise RuntimeError(f"Inspector cancellation call exited early: {stderr}")
            current_active, _ = cancellation_status(endpoint)
            if current_active > 0:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("Inspector cancellation call did not become active")
        cancelling.terminate()
        cancelling.wait(timeout=10)
        cancelling = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            current_active, current_observed = cancellation_status(endpoint)
            if current_active == 0 and current_observed > observed:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("Inspector disconnect did not cancel the tool call")
    finally:
        if cancelling is not None:
            cancelling.terminate()
            try:
                cancelling.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cancelling.kill()
                cancelling.wait(timeout=5)
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)

    listed_result = listed.get("result")
    called_result = called.get("result")
    if not isinstance(listed_result, dict) or not isinstance(called_result, dict):
        raise RuntimeError("Inspector results are malformed")
    tools = listed_result.get("tools")
    names = (
        {str(tool.get("name")) for tool in tools if isinstance(tool, dict)}
        if isinstance(tools, list)
        else set()
    )
    if names != {"always_fails", "cancellation_probe", "echo"}:
        raise RuntimeError(f"Inspector returned unexpected tools: {sorted(names)}")
    if called_result.get("structuredContent") != {"text": "inspector"}:
        raise RuntimeError("Inspector returned unexpected tool content")
    if called_result.get("isError") is not False:
        raise RuntimeError("Inspector reported a tool failure")

    print(
        json.dumps(
            {
                "inspector": INSPECTOR_VERSION,
                "operations": [
                    "initialize",
                    "list_tools",
                    "paginate_tools",
                    "call_tool",
                    "cancel_work",
                    "close",
                ],
                "passed": True,
                "transport": "streamable-http",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
