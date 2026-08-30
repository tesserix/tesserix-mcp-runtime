from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from compatibility.run_matrix import (
    LaneResult,
    MatrixContractError,
    parse_client_report,
    validate_unsupported_initialization,
    write_junit,
)


def _report(*, operations: list[str]) -> str:
    return json.dumps(
        {
            "client": "python-sdk",
            "failure": None,
            "feature_gaps": [],
            "lane": "maintained-v1",
            "negotiated_out": ["prompts", "resources"],
            "operations": operations,
            "passed": True,
            "protocols": ["2025-11-25"],
            "schema_version": 1,
            "sdk": "1.29.1",
            "supported_features": [
                "cancellation",
                "pagination",
                "structured_content",
            ],
        }
    )


def test_client_report_requires_exact_identity_protocol_and_operations() -> None:
    operations = [
        "initialize",
        "capabilities",
        "list_tools",
        "paginate_tools",
        "call_tool",
        "cancel_work",
        "tool_error",
        "close",
        "reconnect",
    ]

    result = parse_client_report(
        _report(operations=operations),
        expected_client="python-sdk",
        expected_lane="maintained-v1",
        expected_sdk="1.29.1",
        artifact="wheel",
        transport="direct",
        route="/mcp",
    )

    assert result.passed is True
    assert result.protocols == ("2025-11-25",)
    assert result.operations == tuple(operations)
    assert result.supported_features == (
        "cancellation",
        "pagination",
        "structured_content",
    )
    assert result.negotiated_out == ("prompts", "resources")
    assert result.failure is None
    assert result.feature_gaps == ()

    with pytest.raises(MatrixContractError, match="required operations"):
        parse_client_report(
            _report(operations=operations[:-1]),
            expected_client="python-sdk",
            expected_lane="maintained-v1",
            expected_sdk="1.29.1",
            artifact="wheel",
            transport="direct",
            route="/mcp",
        )


def test_junit_identifies_the_client_protocol_lane_and_failed_operation(
    tmp_path: Path,
) -> None:
    result = LaneResult(
        client="python-sdk",
        lane="devai-sdk",
        sdk="1.28.1",
        artifact="image",
        transport="agentgateway",
        route="/gateway/runtime/mcp",
        protocols=(),
        operations=(),
        supported_features=(),
        negotiated_out=(),
        passed=False,
        failure={
            "code": "client_operation_failed",
            "error_type": "RuntimeError",
            "operation": "initialize",
            "protocol": "not-negotiated",
        },
        feature_gaps=(),
    )
    target = tmp_path / "compatibility.xml"

    write_junit((result,), target)

    suite = ET.parse(target).getroot()
    assert suite.attrib == {
        "failures": "1",
        "name": "tesserix-mcp-compatibility",
        "tests": "1",
    }
    case = suite.find("testcase")
    assert case is not None
    assert case.attrib == {
        "classname": "compatibility.image.agentgateway",
        "name": "devai-sdk[mcp-1.28.1]",
    }
    properties = {
        property_element.attrib["name"]: property_element.attrib["value"]
        for property_element in case.findall("./properties/property")
    }
    assert properties == {
        "artifact": "image",
        "client": "python-sdk",
        "feature_gaps": "none",
        "operations": "not-completed",
        "protocols": "not-negotiated",
        "route": "/gateway/runtime/mcp",
        "sdk": "1.28.1",
        "transport": "agentgateway",
    }
    failure = case.find("failure")
    assert failure is not None
    assert failure.attrib == {
        "message": "client_operation_failed at initialize (not-negotiated)",
        "type": "RuntimeError",
    }
    assert failure.text is None


def test_failed_client_report_preserves_only_the_bounded_failure_envelope() -> None:
    output = json.dumps(
        {
            "client": "python-sdk",
            "failure": {
                "code": "client_operation_failed",
                "error_type": "RuntimeError",
                "operation": "initialize",
                "protocol": "not-negotiated",
            },
            "feature_gaps": [],
            "lane": "devai-sdk",
            "negotiated_out": ["prompts", "resources"],
            "operations": ["sdk_version"],
            "passed": False,
            "protocols": [],
            "schema_version": 1,
            "sdk": "1.28.1",
            "supported_features": ["pagination"],
        }
    )

    result = parse_client_report(
        output,
        expected_client="python-sdk",
        expected_lane="devai-sdk",
        expected_sdk="1.28.1",
        artifact="image",
        transport="agentgateway",
        route="/gateway/runtime/mcp",
    )

    assert result.passed is False
    assert result.protocols == ()
    assert result.operations == ("sdk_version",)
    assert result.failure == {
        "code": "client_operation_failed",
        "error_type": "RuntimeError",
        "operation": "initialize",
        "protocol": "not-negotiated",
    }


def test_unsupported_protocol_must_fail_during_initialization() -> None:
    body = json.dumps(
        {
            "error": {
                "code": -32022,
                "message": "Unsupported protocol version",
            },
            "id": "compatibility-unsupported",
            "jsonrpc": "2.0",
        }
    ).encode()

    validate_unsupported_initialization(400, body)

    with pytest.raises(MatrixContractError, match="unsupported initialization"):
        validate_unsupported_initialization(
            200,
            json.dumps(
                {
                    "id": "compatibility-unsupported",
                    "jsonrpc": "2.0",
                    "result": {"protocolVersion": "1900-01-01"},
                }
            ).encode(),
        )
