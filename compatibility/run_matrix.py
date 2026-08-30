from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

ROOT = Path(__file__).parent
REPOSITORY_ROOT = ROOT.parent
EXPECTED_OPERATIONS = frozenset(
    {
        "initialize",
        "capabilities",
        "list_tools",
        "paginate_tools",
        "call_tool",
        "cancel_work",
        "tool_error",
        "close",
        "reconnect",
    }
)
DEVAI_OPERATIONS = frozenset(
    {"initialize", "capabilities", "list_tools", "call_tool", "close", "reconnect"}
)
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
        "UV_CACHE_DIR",
        "UV_PYTHON_INSTALL_DIR",
        "XDG_CACHE_HOME",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)


class MatrixContractError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class LaneResult:
    client: str
    lane: str
    sdk: str
    artifact: Literal["wheel", "image"]
    transport: Literal["direct", "agentgateway"]
    route: str
    protocols: tuple[str, ...]
    operations: tuple[str, ...]
    supported_features: tuple[str, ...]
    negotiated_out: tuple[str, ...]
    feature_gaps: tuple[str, ...]
    passed: bool
    failure: dict[str, str] | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ClientSpec:
    client: str
    lane: str
    sdk: str
    command: tuple[str, ...]
    cwd: Path
    expected_protocols: tuple[str, ...]
    required_operations: frozenset[str] = EXPECTED_OPERATIONS


def _strings(
    document: dict[str, object],
    name: str,
    *,
    maximum: int,
    minimum: int = 1,
) -> tuple[str, ...]:
    value = document.get(name)
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
        or any(not isinstance(item, str) or not item or len(item) > 64 for item in value)
        or len(set(value)) != len(value)
    ):
        raise MatrixContractError(f"client report has invalid {name}")
    return tuple(value)


def parse_client_report(
    output: str,
    *,
    expected_client: str,
    expected_lane: str,
    expected_sdk: str,
    artifact: Literal["wheel", "image"],
    transport: Literal["direct", "agentgateway"],
    route: str,
    required_operations: frozenset[str] = EXPECTED_OPERATIONS,
    protocols_required: bool = True,
) -> LaneResult:
    if not isinstance(output, str) or not output or len(output.encode()) > 65_536:
        raise MatrixContractError("client report is empty or too large")
    try:
        document = json.loads(output)
    except json.JSONDecodeError as error:
        raise MatrixContractError("client report is not JSON") from error
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise MatrixContractError("client report schema is invalid")
    if (
        document.get("client") != expected_client
        or document.get("lane") != expected_lane
        or document.get("sdk") != expected_sdk
    ):
        raise MatrixContractError("client report identity is invalid")
    passed = document.get("passed")
    if not isinstance(passed, bool):
        raise MatrixContractError("client report status is invalid")
    minimum_protocols = int(passed and protocols_required)
    protocols = _strings(document, "protocols", maximum=4, minimum=minimum_protocols)
    operations = _strings(document, "operations", maximum=16, minimum=0)
    if passed and not required_operations <= set(operations):
        raise MatrixContractError("client report omitted required operations")
    supported_features = _strings(document, "supported_features", maximum=16)
    negotiated_out = _strings(document, "negotiated_out", maximum=16)
    feature_gaps = _strings(document, "feature_gaps", maximum=16, minimum=0)
    failure_value = document.get("failure")
    failure: dict[str, str] | None = None
    if passed:
        if failure_value is not None:
            raise MatrixContractError("successful client report has a failure")
    else:
        if not isinstance(failure_value, dict) or set(failure_value) != {
            "code",
            "error_type",
            "operation",
            "protocol",
        }:
            raise MatrixContractError("failed client report has an invalid failure")
        if any(
            not isinstance(value, str)
            or not value
            or len(value) > 64
            or not all(character.isalnum() or character in "_.-" for character in value)
            for value in failure_value.values()
        ):
            raise MatrixContractError("failed client report has unsafe failure fields")
        failure = {name: str(value) for name, value in failure_value.items()}
    return LaneResult(
        client=expected_client,
        lane=expected_lane,
        sdk=expected_sdk,
        artifact=artifact,
        transport=transport,
        route=route,
        protocols=protocols,
        operations=operations,
        supported_features=supported_features,
        negotiated_out=negotiated_out,
        feature_gaps=feature_gaps,
        passed=passed,
        failure=failure,
    )


def write_junit(results: tuple[LaneResult, ...], target: Path) -> None:
    failures = sum(not result.passed for result in results)
    suite = ET.Element(
        "testsuite",
        {
            "failures": str(failures),
            "name": "tesserix-mcp-compatibility",
            "tests": str(len(results)),
        },
    )
    for result in results:
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": f"compatibility.{result.artifact}.{result.transport}",
                "name": f"{result.lane}[mcp-{result.sdk}]",
            },
        )
        properties = ET.SubElement(case, "properties")
        values = {
            "artifact": result.artifact,
            "client": result.client,
            "feature_gaps": ",".join(result.feature_gaps) or "none",
            "operations": ",".join(result.operations) or "not-completed",
            "protocols": ",".join(result.protocols) or "not-negotiated",
            "route": result.route,
            "sdk": result.sdk,
            "transport": result.transport,
        }
        for name, value in values.items():
            ET.SubElement(properties, "property", {"name": name, "value": value})
        if result.failure is not None:
            code = result.failure.get("code", "compatibility_failure")
            operation = result.failure.get("operation", "unknown")
            protocol = result.failure.get("protocol", "not-negotiated")
            error_type = result.failure.get("error_type", "CompatibilityFailure")
            ET.SubElement(
                case,
                "failure",
                {
                    "message": f"{code} at {operation} ({protocol})",
                    "type": error_type,
                },
            )
    ET.indent(suite)
    target.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(target, encoding="utf-8", xml_declaration=True)


def validate_unsupported_initialization(status: int, body: bytes) -> None:
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixContractError("unsupported initialization returned invalid JSON") from error
    error_document = document.get("error") if isinstance(document, dict) else None
    if (
        status != 400
        or not isinstance(document, dict)
        or len(body) > 1_024
        or document.get("jsonrpc") != "2.0"
        or document.get("id") != "compatibility-unsupported"
        or not isinstance(error_document, dict)
        or error_document.get("code") != -32022
        or "result" in document
        or b"2.1.1" in body
    ):
        raise MatrixContractError("unsupported initialization was not rejected explicitly")


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_until_listening(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise MatrixContractError("compatibility server exited before accepting connections")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise MatrixContractError("compatibility server did not become ready")


def _base_environment() -> dict[str, str]:
    environment = {
        name: value for name, value in os.environ.items() if name in _ENVIRONMENT_ALLOWLIST
    }
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _client_environment(
    endpoint: str,
    *,
    pagination_mode: Literal["complete", "agentgateway-first-page-only"],
) -> dict[str, str]:
    environment = _base_environment()
    environment["DEVAI_MCP_HUB_SSRF_ENFORCE"] = "false"
    environment["MCP_COMPAT_URL"] = endpoint
    environment["MCP_COMPAT_PAGINATION_MODE"] = pagination_mode
    return environment


def _sdk_specs() -> tuple[ClientSpec, ...]:
    return (
        ClientSpec(
            client="python-sdk",
            lane="devai-sdk",
            sdk="1.28.1",
            command=("uv", "run", "--frozen", "--script", str(ROOT / "client_1_28.py")),
            cwd=REPOSITORY_ROOT,
            expected_protocols=("2025-11-25",),
        ),
        ClientSpec(
            client="python-sdk",
            lane="maintained-v1",
            sdk="1.29.1",
            command=("uv", "run", "--frozen", "--script", str(ROOT / "client_1_29.py")),
            cwd=REPOSITORY_ROOT,
            expected_protocols=("2025-11-25",),
        ),
        ClientSpec(
            client="python-sdk",
            lane="current-v2",
            sdk="2.1.1",
            command=("uv", "run", "--frozen", "--script", str(ROOT / "client_2_1.py")),
            cwd=REPOSITORY_ROOT,
            expected_protocols=("2026-07-28", "2025-11-25"),
        ),
    )


def _devai_spec(python: Path) -> ClientSpec:
    return ClientSpec(
        client="devai-downstream",
        lane="devai-adapter",
        sdk="1.28.1",
        command=(str(python), "-m", "compatibility.devai_smoke"),
        cwd=REPOSITORY_ROOT,
        expected_protocols=(),
        required_operations=DEVAI_OPERATIONS,
    )


def _failed_result(
    spec: ClientSpec,
    *,
    artifact: Literal["wheel", "image"],
    transport: Literal["direct", "agentgateway"],
    route: str,
    code: str,
    error_type: str,
    operation: str = "client_process",
    protocol: str = "not-negotiated",
) -> LaneResult:
    return LaneResult(
        client=spec.client,
        lane=spec.lane,
        sdk=spec.sdk,
        artifact=artifact,
        transport=transport,
        route=route,
        protocols=(),
        operations=(),
        supported_features=(),
        negotiated_out=(),
        feature_gaps=(),
        passed=False,
        failure={
            "code": code,
            "error_type": error_type,
            "operation": operation,
            "protocol": protocol,
        },
    )


def run_client(
    spec: ClientSpec,
    endpoint: str,
    *,
    artifact: Literal["wheel", "image"],
    transport: Literal["direct", "agentgateway"],
    route: str,
) -> LaneResult:
    try:
        completed = subprocess.run(
            spec.command,
            cwd=spec.cwd,
            env=_client_environment(
                endpoint,
                pagination_mode=(
                    "agentgateway-first-page-only" if transport == "agentgateway" else "complete"
                ),
            ),
            capture_output=True,
            check=False,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return _failed_result(
            spec,
            artifact=artifact,
            transport=transport,
            route=route,
            code="client_timeout",
            error_type="TimeoutExpired",
        )
    lines = completed.stdout.splitlines()
    candidate = lines[-1] if lines else ""
    try:
        result = parse_client_report(
            candidate,
            expected_client=spec.client,
            expected_lane=spec.lane,
            expected_sdk=spec.sdk,
            artifact=artifact,
            transport=transport,
            route=route,
            required_operations=spec.required_operations,
            protocols_required=bool(spec.expected_protocols),
        )
    except MatrixContractError:
        return _failed_result(
            spec,
            artifact=artifact,
            transport=transport,
            route=route,
            code="client_report_invalid",
            error_type="MatrixContractError",
        )
    if completed.returncode != 0 and result.passed:
        return _failed_result(
            spec,
            artifact=artifact,
            transport=transport,
            route=route,
            code="client_exit_status",
            error_type="SubprocessError",
            protocol=result.protocols[-1] if result.protocols else "not-negotiated",
        )
    if completed.returncode == 0 and not result.passed:
        return _failed_result(
            spec,
            artifact=artifact,
            transport=transport,
            route=route,
            code="client_status_invalid",
            error_type="MatrixContractError",
            protocol=result.protocols[-1] if result.protocols else "not-negotiated",
        )
    if result.passed and result.protocols != spec.expected_protocols:
        return _failed_result(
            spec,
            artifact=artifact,
            transport=transport,
            route=route,
            code="protocol_mismatch",
            error_type="MatrixContractError",
            operation="initialize",
            protocol=result.protocols[-1] if result.protocols else "not-negotiated",
        )
    return result


def _run_sdk_surface(
    endpoint: str,
    *,
    artifact: Literal["wheel", "image"],
    transport: Literal["direct", "agentgateway"],
    route: str,
) -> list[LaneResult]:
    return [
        run_client(
            spec,
            endpoint,
            artifact=artifact,
            transport=transport,
            route=route,
        )
        for spec in _sdk_specs()
    ]


def probe_unsupported_initialization(
    endpoint: str,
    *,
    artifact: Literal["wheel", "image"],
    transport: Literal["direct", "agentgateway"],
    route: str,
) -> LaneResult:
    parsed = urlsplit(endpoint)
    connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=10)
    body = json.dumps(
        {
            "id": "compatibility-unsupported",
            "jsonrpc": "2.0",
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/protocolVersion": "1900-01-01",
                }
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    try:
        connection.request(
            "POST",
            parsed.path,
            body=body,
            headers={
                "accept": "application/json, text/event-stream",
                "content-type": "application/json",
                "mcp-method": "server/discover",
                "mcp-protocol-version": "1900-01-01",
            },
        )
        response = connection.getresponse()
        response_body = response.read(1_025)
        validate_unsupported_initialization(response.status, response_body)
    except Exception as error:
        return LaneResult(
            client="raw-protocol-probe",
            lane="unsupported-initialize",
            sdk="not-applicable",
            artifact=artifact,
            transport=transport,
            route=route,
            protocols=(),
            operations=(),
            supported_features=(),
            negotiated_out=(),
            feature_gaps=(),
            passed=False,
            failure={
                "code": "unsupported_initialization_failed",
                "error_type": type(error).__name__[:64],
                "operation": "initialize",
                "protocol": "1900-01-01",
            },
        )
    finally:
        connection.close()
    return LaneResult(
        client="raw-protocol-probe",
        lane="unsupported-initialize",
        sdk="not-applicable",
        artifact=artifact,
        transport=transport,
        route=route,
        protocols=("1900-01-01-rejected",),
        operations=("initialize_rejected",),
        supported_features=("explicit_initialization_rejection",),
        negotiated_out=("unsupported_protocol",),
        feature_gaps=(),
        passed=True,
        failure=None,
    )


def _endpoint_path(endpoint: str, expected: str) -> None:
    parsed = urlsplit(endpoint)
    try:
        port = parsed.port
    except ValueError as error:
        raise MatrixContractError("compatibility endpoint port is invalid") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path.rstrip("/") != expected.rstrip("/")
        or parsed.query
        or parsed.fragment
    ):
        raise MatrixContractError("compatibility endpoint is not an expected loopback route")


@contextmanager
def _wheel_server(python: Path) -> Iterator[str]:
    port = available_port()
    endpoint = f"http://127.0.0.1:{port}/mcp"
    server = subprocess.Popen(
        [
            str(python),
            str(ROOT / "server.py"),
            "--port",
            str(port),
        ],
        cwd=REPOSITORY_ROOT,
        env=_base_environment(),
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        text=True,
    )
    try:
        wait_until_listening(server, port)
        yield endpoint
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


def _matrix_document(results: tuple[LaneResult, ...]) -> dict[str, object]:
    return {
        "lanes": [asdict(result) for result in results],
        "passed": all(result.passed for result in results),
        "schema_version": 1,
        "server_sdk": "2.1.1",
    }


def _write_matrix(results: tuple[LaneResult, ...], target: Path) -> str:
    encoded = json.dumps(_matrix_document(results), indent=2, sort_keys=True) + "\n"
    if len(encoded.encode()) > 262_144:
        raise MatrixContractError("compatibility evidence is too large")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(encoded, encoding="utf-8")
    return encoded


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-python", type=Path, required=True)
    parser.add_argument("--image-endpoint", required=True)
    parser.add_argument("--gateway-endpoint", required=True)
    parser.add_argument("--devai-python", type=Path, required=True)
    parser.add_argument("--devai-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    wheel_python = arguments.wheel_python.absolute()
    devai_python = arguments.devai_python.absolute()
    devai_root = arguments.devai_root.resolve()
    if not wheel_python.is_file() or not devai_python.is_file() or not devai_root.is_dir():
        raise MatrixContractError("compatibility environments are missing")
    _endpoint_path(arguments.image_endpoint, "/mcp")
    _endpoint_path(arguments.gateway_endpoint, "/gateway/runtime/mcp")

    results: list[LaneResult] = []
    with _wheel_server(wheel_python) as wheel_endpoint:
        results.extend(
            _run_sdk_surface(
                wheel_endpoint,
                artifact="wheel",
                transport="direct",
                route="/mcp",
            )
        )
        results.append(
            probe_unsupported_initialization(
                wheel_endpoint,
                artifact="wheel",
                transport="direct",
                route="/mcp",
            )
        )
    results.extend(
        _run_sdk_surface(
            arguments.image_endpoint,
            artifact="image",
            transport="direct",
            route="/mcp",
        )
    )
    results.append(
        probe_unsupported_initialization(
            arguments.image_endpoint,
            artifact="image",
            transport="direct",
            route="/mcp",
        )
    )
    results.extend(
        _run_sdk_surface(
            arguments.gateway_endpoint,
            artifact="image",
            transport="agentgateway",
            route="/gateway/runtime/mcp",
        )
    )
    results.append(
        probe_unsupported_initialization(
            arguments.gateway_endpoint,
            artifact="image",
            transport="agentgateway",
            route="/gateway/runtime/mcp",
        )
    )
    results.append(
        run_client(
            _devai_spec(devai_python),
            arguments.gateway_endpoint,
            artifact="image",
            transport="agentgateway",
            route="/gateway/runtime/mcp",
        )
    )
    final = tuple(results)
    report = _write_matrix(final, arguments.report.resolve())
    write_junit(final, arguments.junit.resolve())
    print(report, end="")
    return 0 if all(result.passed for result in final) else 1


if __name__ == "__main__":
    raise SystemExit(main())
