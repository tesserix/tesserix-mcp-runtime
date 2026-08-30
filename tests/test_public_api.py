from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import tesserix_mcp_runtime

ROOT = Path(__file__).parents[1]
CHECKER = ROOT / "architecture" / "check_public_api.py"
SNAPSHOT = ROOT / "architecture" / "public-api.txt"


def run_snapshot_check(snapshot: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), str(snapshot)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )


def test_public_api_exports_only_the_stable_contract_surface() -> None:
    assert set(tesserix_mcp_runtime.__all__) == {
        "Application",
        "ApplicationConfigurationError",
        "ApplicationDeadlineExceeded",
        "ApplicationDiagnostic",
        "ApplicationDiagnosticCode",
        "ApplicationEndpoint",
        "ApplicationLimits",
        "ApplicationRunResult",
        "ApplicationTransport",
        "ApprovalRecord",
        "ApprovalRequirement",
        "ApprovalStore",
        "ApprovalUse",
        "AuthenticatedIdentity",
        "Authorizer",
        "CallContext",
        "Cancellation",
        "Clock",
        "ContractViolation",
        "CredentialProvider",
        "DuplicateToolName",
        "ErrorCode",
        "ErrorResponse",
        "ExecutionLimits",
        "IdempotencyRequirement",
        "InvocationResult",
        "InvocationStatus",
        "JsonValue",
        "Lifecycle",
        "LifecycleController",
        "LifecycleFailure",
        "LifecycleState",
        "LifecycleTransitionError",
        "MappedError",
        "MetadataPolicy",
        "Retryability",
        "RuntimeFailure",
        "SchemaPolicy",
        "SchemaChange",
        "SchemaDirection",
        "ScrubbedError",
        "ShutdownSignal",
        "ShutdownSignalSource",
        "SystemClock",
        "Telemetry",
        "TerminalEmitter",
        "ToolCatalog",
        "ToolDefinition",
        "ToolDiscoveryMetadata",
        "ToolEffect",
        "ToolHandler",
        "ToolMetadata",
        "ToolManifest",
        "ToolPolicy",
        "ToolPolicyAuditEvent",
        "ToolPolicyAuditSink",
        "ToolPolicyConfigurationError",
        "ToolPolicyDecision",
        "ToolPolicyRule",
        "ToolPolicyState",
        "ToolReview",
        "TraceContext",
        "__version__",
        "classify_schema_change",
        "map_exception",
        "normalize_tool_name",
        "schema_fingerprint",
        "tool_policy_fingerprint",
    }
    for name in tesserix_mcp_runtime.__all__:
        assert getattr(tesserix_mcp_runtime, name) is not None


def test_checked_in_public_api_snapshot_matches_exports() -> None:
    completed = run_snapshot_check(SNAPSHOT)

    assert completed.returncode == 0
    assert completed.stdout == "Public API snapshot matches (68 exports).\n"
    assert completed.stderr == ""


def test_public_api_snapshot_reports_owner_drift(tmp_path: Path) -> None:
    drifted_snapshot = tmp_path / "public-api.txt"
    drifted_snapshot.write_text(
        SNAPSHOT.read_text(encoding="utf-8").replace(
            "ToolDefinition = tesserix_mcp_runtime.contracts.ToolDefinition",
            "ToolDefinition = tesserix_mcp_runtime.adapters.ToolDefinition",
        ),
        encoding="utf-8",
    )

    completed = run_snapshot_check(drifted_snapshot)

    assert completed.returncode == 1
    assert "-ToolDefinition = tesserix_mcp_runtime.adapters.ToolDefinition" in completed.stderr
    assert "+ToolDefinition = tesserix_mcp_runtime.contracts.ToolDefinition" in completed.stderr
