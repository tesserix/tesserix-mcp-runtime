from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

from reverse_proxy import ReverseProxyServer

ROOT = Path(__file__).parent
LANES = (
    ROOT / "client_1_28.py",
    ROOT / "client_1_29.py",
    ROOT / "client_2_1.py",
)
EXPECTED_OPERATIONS = {
    "initialize",
    "list_tools",
    "paginate_tools",
    "call_tool",
    "cancel_work",
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
        raise RuntimeError(f"{script.name} failed with {completed.returncode}: {completed.stderr}")
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
    proxy: ReverseProxyServer | None = None
    try:
        wait_until_listening(server, port)
        proxy = ReverseProxyServer(port)
        proxy_thread = threading.Thread(
            target=proxy.serve_forever,
            name="mcp-compatibility-reverse-proxy",
            daemon=True,
        )
        proxy_thread.start()
        reports = [run_lane(script, endpoint) for script in LANES]
        proxy_port = int(proxy.server_address[1])
        proxy_report = run_lane(
            ROOT / "client_2_1.py",
            f"http://127.0.0.1:{proxy_port}/gateway/runtime/mcp",
        )
    finally:
        if proxy is not None:
            proxy.shutdown()
            proxy.server_close()
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)

    print(
        json.dumps(
            {
                "lanes": reports,
                "passed": True,
                "proxy": {
                    **proxy_report,
                    "path": "/gateway/runtime/mcp",
                    "rewritten_path": "/mcp",
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
