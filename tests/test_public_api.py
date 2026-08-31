from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import tesserix_mcp_manifest
import tesserix_mcp_publisher
import tesserix_mcp_testkit

import tesserix_mcp_runtime

ROOT = Path(__file__).parents[1]
CHECKER = ROOT / "architecture" / "check_public_api.py"
SNAPSHOT = ROOT / "architecture" / "public-api.txt"
MANIFEST_SNAPSHOT = ROOT / "architecture" / "manifest-public-api.txt"
PUBLISHER_SNAPSHOT = ROOT / "architecture" / "publisher-public-api.txt"
TESTKIT_SNAPSHOT = ROOT / "architecture" / "testkit-public-api.txt"


def run_snapshot_check(
    snapshot: Path,
    *,
    package: str = "tesserix_mcp_runtime",
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(CHECKER), str(snapshot)]
    if package != "tesserix_mcp_runtime":
        command.extend(["--package", package])
    return subprocess.run(
        command,
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
        "DeclaredEgressPolicy",
        "DuplicateToolName",
        "EgressDestination",
        "EgressManifest",
        "EgressPolicy",
        "EgressPolicyViolation",
        "ErrorCode",
        "ErrorResponse",
        "ExecutionLimits",
        "IdempotencyRequirement",
        "InMemoryRegistryCache",
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
        "RedactionError",
        "RedactionLimits",
        "RedactionPolicy",
        "ReadinessCheck",
        "Retryability",
        "RegistryADKServer",
        "RegistryArtifact",
        "RegistryArtifactCacheKey",
        "RegistryArtifactRaceError",
        "RegistryAuthenticationError",
        "RegistryAuthorizationError",
        "RegistryCachePolicy",
        "RegistryCacheUnavailableError",
        "RegistryCandidateDecision",
        "RegistryCandidateExplanation",
        "RegistryCandidateReason",
        "RegistryContractError",
        "RegistryDiscovery",
        "RegistryDiscoveryCache",
        "RegistryDiscoveryError",
        "RegistryDigestMismatchError",
        "RegistryResolution",
        "RegistryResolutionPolicy",
        "RegistryResolutionSource",
        "RegistryResolver",
        "RegistrySearchQuery",
        "RegistrySearchCacheKey",
        "RegistrySearchStub",
        "RegistryToolRequirement",
        "RegistryToolPin",
        "RegistryUnavailableError",
        "RuntimeExporter",
        "RuntimeFailure",
        "RuntimeLimit",
        "RuntimeLogEvent",
        "RuntimeLogName",
        "RuntimeObservability",
        "RuntimeOperation",
        "RuntimeOperationsEndpoint",
        "RuntimeOutcome",
        "RuntimeReason",
        "RuntimeSpan",
        "RuntimeSpanName",
        "RuntimeSpanSpec",
        "SchemaPolicy",
        "SchemaChange",
        "SchemaDirection",
        "ScrubbedError",
        "SecretRedactor",
        "SecretValue",
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
        "registry_artifact_digest",
        "schema_fingerprint",
        "tool_policy_fingerprint",
    }
    for name in tesserix_mcp_runtime.__all__:
        assert getattr(tesserix_mcp_runtime, name) is not None


def test_checked_in_public_api_snapshot_matches_exports() -> None:
    completed = run_snapshot_check(SNAPSHOT)

    assert completed.returncode == 0
    assert completed.stdout == "Public API snapshot matches (119 exports).\n"
    assert completed.stderr == ""


def test_testkit_public_api_snapshot_matches_exports() -> None:
    assert len(tesserix_mcp_testkit.__all__) == 104
    for name in tesserix_mcp_testkit.__all__:
        assert getattr(tesserix_mcp_testkit, name) is not None

    completed = run_snapshot_check(
        TESTKIT_SNAPSHOT,
        package="tesserix_mcp_testkit",
    )

    assert completed.returncode == 0
    assert completed.stdout == "Public API snapshot matches (104 exports).\n"
    assert completed.stderr == ""


def test_manifest_public_api_snapshot_matches_exports() -> None:
    assert set(tesserix_mcp_manifest.__all__) == {
        "AUTHORING_MANIFEST_MAX_BYTES",
        "AUTHORING_MANIFEST_MAX_DEPTH",
        "AUTHORING_MANIFEST_MAX_NODES",
        "AUTHORING_MANIFEST_VERSION",
        "CompiledManifests",
        "CredentialReference",
        "DISCOVERY_CAPABILITIES_ANNOTATION",
        "DISCOVERY_REQUIRES_ANNOTATION",
        "DISCOVERY_SUMMARY_ANNOTATION",
        "DISCOVERY_WHEN_TO_USE_ANNOTATION",
        "DiscoveryEvaluationDataset",
        "DiscoveryEvaluationMetrics",
        "DiscoveryIntentCase",
        "DiscoveryIntentResult",
        "DiscoveryRisk",
        "DiscoveryScenario",
        "GatewayApprovalState",
        "GatewayEligibilityCandidate",
        "GatewayEligibilityDecision",
        "GatewayEligibilityPolicy",
        "GatewayEligibilityReason",
        "GatewayReconciliationContractError",
        "GatewayReconciliationPage",
        "GatewayReconciliationSnapshot",
        "GatewayRouteIdentity",
        "GatewayRouteRecord",
        "GatewayTenantSnapshot",
        "GatewayTenantState",
        "ManifestError",
        "ManifestLifecycle",
        "ManifestValidationCode",
        "ManifestValidationError",
        "ManifestVersionMismatchError",
        "ManifestVisibility",
        "OFFICIAL_REGISTRY_COMMIT",
        "OFFICIAL_REGISTRY_RELEASE",
        "OFFICIAL_SCHEMA_SHA256",
        "OFFICIAL_SCHEMA_URL",
        "OFFICIAL_SCHEMA_VERSION",
        "Ownership",
        "PackageIdentity",
        "PackageRegistry",
        "PackageTransport",
        "REGISTRY_API_VERSION",
        "REGISTRY_EXTENSION_KEY",
        "RemoteEndpoint",
        "Repository",
        "RoutePolicy",
        "RuntimeAdapter",
        "SEMANTIC_MANIFEST_TOKEN_BUDGET",
        "SemanticLintCode",
        "SemanticLintFinding",
        "SemanticMetadata",
        "ServerAuthoringManifest",
        "ToolInputField",
        "ToolSummary",
        "assemble_gateway_reconciliation_pages",
        "compile_manifests",
        "derive_gateway_route_identity",
        "evaluate_discovery",
        "evaluate_gateway_eligibility",
        "extract_server_json",
        "lint_semantic_manifest",
        "load_authoring_manifest",
    }
    for name in tesserix_mcp_manifest.__all__:
        assert getattr(tesserix_mcp_manifest, name) is not None

    completed = run_snapshot_check(
        MANIFEST_SNAPSHOT,
        package="tesserix_mcp_manifest",
    )

    assert completed.returncode == 0
    assert completed.stdout == "Public API snapshot matches (64 exports).\n"
    assert completed.stderr == ""


def test_publisher_public_api_snapshot_matches_exports() -> None:
    assert len(tesserix_mcp_publisher.__all__) == 37
    for name in tesserix_mcp_publisher.__all__:
        assert getattr(tesserix_mcp_publisher, name) is not None

    completed = run_snapshot_check(
        PUBLISHER_SNAPSHOT,
        package="tesserix_mcp_publisher",
    )

    assert completed.returncode == 0
    assert completed.stdout == "Public API snapshot matches (37 exports).\n"
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
