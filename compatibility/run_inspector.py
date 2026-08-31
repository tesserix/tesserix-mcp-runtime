from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).parent
INSPECTOR_VERSION = "2.4.0"
_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "HOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "LANG",
        "LC_ALL",
        "NO_PROXY",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)


def _environment() -> dict[str, str]:
    return {name: value for name, value in os.environ.items() if name in _ENVIRONMENT_ALLOWLIST}


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


def _run_inspector(endpoint: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        inspector_command(endpoint, *arguments),
        cwd=ROOT.parent,
        env=_environment(),
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )


def inspect(endpoint: str, *arguments: str) -> dict[str, object]:
    completed = _run_inspector(endpoint, *arguments)
    if completed.returncode != 0 or len(completed.stdout.encode()) > 262_144:
        raise RuntimeError("Inspector operation failed")
    document = json.loads(completed.stdout)
    if not isinstance(document, dict):
        raise RuntimeError("Inspector returned a non-object report")
    return document


def validate_inspector_tool_error(returncode: int, stdout: str, stderr: str) -> None:
    try:
        first = json.loads(stdout)
        second = json.loads(stderr)
    except json.JSONDecodeError as error:
        raise RuntimeError("Inspector tool-error contract returned invalid JSON") from error
    result = first.get("result") if isinstance(first, dict) else None
    error_document = second.get("error") if isinstance(second, dict) else None
    if (
        returncode != 5
        or len(stdout.encode()) + len(stderr.encode()) > 262_144
        or not isinstance(result, dict)
        or result.get("isError") is not True
        or not isinstance(error_document, dict)
        or error_document.get("code") != "tool_is_error"
    ):
        raise RuntimeError("Inspector tool-error contract is invalid")


def inspect_tool_error(endpoint: str) -> None:
    completed = _run_inspector(
        endpoint,
        "--method",
        "tools/call",
        "--tool-name",
        "always_fails",
        "--tool-args-json",
        "{}",
    )
    validate_inspector_tool_error(completed.returncode, completed.stdout, completed.stderr)


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


def _validate_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Inspector endpoint port is invalid") from error
    route = parsed.path.rstrip("/")
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or route not in {"/mcp", "/gateway/runtime/mcp"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Inspector endpoint must be an expected loopback route")
    return route


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--report", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    endpoint = arguments.endpoint
    route = _validate_endpoint(endpoint)
    cancelling: subprocess.Popen[str] | None = None
    listed = inspect(endpoint, "--method", "tools/list", "--strict")
    called = inspect(
        endpoint,
        "--method",
        "tools/call",
        "--tool-name",
        "echo",
        "--tool-args-json",
        '{"text":"inspector"}',
    )
    if route == "/mcp":
        inspect_tool_error(endpoint)
    try:
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
            env=_environment(),
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            text=True,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if cancelling.poll() is not None:
                raise RuntimeError("Inspector cancellation call exited early")
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
    expected_names = (
        {"cancellation_probe", "echo"}
        if route == "/gateway/runtime/mcp"
        else {"always_fails", "cancellation_probe", "echo", "reliability_probe"}
    )
    if names != expected_names:
        raise RuntimeError("Inspector returned an unexpected tool catalog")
    if called_result.get("structuredContent") != {"text": "inspector"}:
        raise RuntimeError("Inspector returned unexpected tool content")
    if called_result.get("isError") is not False:
        raise RuntimeError("Inspector returned an invalid tool status")

    operations = [
        "initialize",
        "list_tools",
        "paginate_tools",
        "call_tool",
        "cancel_work",
        "close",
        "reconnect",
    ]
    if route == "/mcp":
        operations.insert(-2, "tool_error")
    report = {
        "feature_gaps": (["agentgateway_pagination"] if route == "/gateway/runtime/mcp" else []),
        "inspector": INSPECTOR_VERSION,
        "operations": operations,
        "passed": True,
        "route": route,
        "schema_version": 1,
        "transport": "streamable-http",
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    target = arguments.report.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
