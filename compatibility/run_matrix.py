from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import time


ROOT = Path(__file__).parent
LANES = (
    ROOT / "client_1_28.py",
    ROOT / "client_1_29.py",
    ROOT / "client_2_1.py",
)
EXPECTED_OPERATIONS = {
    "initialize",
    "list_tools",
    "call_tool",
    "tool_error",
    "close",
}


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_until_listening(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr is not None else ""
            raise RuntimeError(f"compatibility server exited early: {stderr}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("compatibility server did not become ready")


def run_lane(script: Path, endpoint: str) -> dict[str, object]:
    environment = os.environ.copy()
    environment["MCP_COMPAT_URL"] = endpoint
    completed = subprocess.run(
        ["uv", "run", "--frozen", "--script", str(script)],
        cwd=ROOT.parent,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{script.name} failed with {completed.returncode}: {completed.stderr}"
        )
    report = json.loads(completed.stdout)
    if not isinstance(report, dict):
        raise RuntimeError(f"{script.name} returned a non-object report")
    operations = report.get("operations")
    if not isinstance(operations, list) or set(operations) != EXPECTED_OPERATIONS:
        raise RuntimeError(f"{script.name} did not exercise every operation")
    if report.get("closed") is not True:
        raise RuntimeError(f"{script.name} did not close cleanly")
    protocols = report.get("protocols")
    if not isinstance(protocols, list):
        raise RuntimeError(f"{script.name} did not report protocols")
    return {
        "closed": True,
        "lane": str(report.get("lane")),
        "operations": [str(operation) for operation in operations],
        "protocols": [str(protocol) for protocol in protocols],
        "sdk": str(report.get("sdk")),
    }


def main() -> int:
    port = available_port()
    endpoint = f"http://127.0.0.1:{port}/mcp"
    server = subprocess.Popen(
        [
            "uv",
            "run",
            "--frozen",
            "--script",
            str(ROOT / "server.py"),
            "--port",
            str(port),
        ],
        cwd=ROOT.parent,
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        text=True,
    )
    try:
        wait_until_listening(server, port)
        reports = [run_lane(script, endpoint) for script in LANES]
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)

    print(json.dumps({"lanes": reports, "passed": True}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
