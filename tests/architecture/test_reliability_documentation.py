from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tesserix_mcp_testkit import ReliabilityCorrelationEvidence, ReliabilityLoadKind

ROOT = Path(__file__).parents[2]
ADR = ROOT / "docs" / "adr" / "0027-stateless-reliability-qualification.md"
GUIDE = ROOT / "docs" / "reliability.md"
ADR_INDEX = ROOT / "docs" / "adr" / "README.md"
REFERENCE = ROOT / "deploy" / "kubernetes" / "reference" / "README.md"
AGENTGATEWAY_EVIDENCE = ROOT / "benchmarks" / "agentgateway-reliability-correlation.json"


def test_reliability_adr_records_stateless_boundaries_numbers_and_failure_behavior() -> None:
    text = ADR.read_text(encoding="utf-8")

    for required in (
        "Status: Accepted",
        "Tracking: [tesserix-mcp-runtime#29]",
        "99.9%",
        "60,000-byte request",
        "500,000-byte response",
        "50 calls/second",
        "200 calls/second",
        "stateless",
        "session affinity",
        "PostgreSQL",
        "Valkey",
        "object storage",
        "Temporal",
        "Registry outage",
        "identity",
        "telemetry",
        "DNS",
        "SIGTERM",
        "canary",
        "rollback",
        "mcp_server_saturation_ratio",
        "ceil(52.5 / 32) = 2",
        "Agent runtime or short-lived job",
        "MCP Gateway",
        "Tool Registry",
        "Stateless MCP runtime",
        "Product APIs",
        "Temporal workflow",
        "External state",
        "AI agent",
        "Simple tool / Product API",
        "Immediate result",
        "Workflow ID",
        "later status, signal, cancel, or result",
        "same or a different pod",
        "Authenticated identity and tenant",
        "Tool and schema version",
        "Idempotency key for writes",
        "Correlation and trace IDs",
        "Workflow or resource reference",
        "Timeout and retry policy",
        "Authorisation context",
        "Qdrant",
        "transactional outbox",
        "same key with a different request digest",
        "PostgreSQL is the source of truth",
        "Temporal Run ID",
    ):
        assert required in text


def test_reliability_guide_is_an_executable_sanitized_evidence_runbook() -> None:
    text = GUIDE.read_text(encoding="utf-8")

    for required in (
        "uv run --frozen python benchmarks/measure_reliability.py",
        "uv run --frozen python compatibility/measure_reliability.py",
        "uv run --frozen python compatibility/correlate_reliability.py",
        "--lane direct_http",
        "--lane agentgateway",
        "--kind sustained",
        "http://127.0.0.1:33000/gateway/runtime/mcp",
        "http://127.0.0.1:31520/metrics",
        "http://127.0.0.1:38080/metrics",
        "agentgateway-reliability-correlation.json",
        "TESSERIX_RELIABILITY_SPAN",
        "docker stats --no-stream",
        "reliability-observations.json",
        "capacity-plan.json",
        "horizontal-pod-autoscaler.json",
        "Mcp-Session-Id",
        "request-owned memory",
        "request-owned filesystem",
        "one external effect",
        "--compatibility-smoke",
        "Never retain or promote smoke output",
        "No raw payload",
        "Argo CD",
    ):
        assert required in text


def test_reliability_decision_and_reference_resources_are_indexed() -> None:
    index = ADR_INDEX.read_text(encoding="utf-8")
    reference = REFERENCE.read_text(encoding="utf-8")

    assert "0026-digest-bound-evaluation-promotion.md" in index
    assert "0027-stateless-reliability-qualification.md" in index
    assert "HorizontalPodAutoscaler" in reference
    assert "session affinity" in reference
    assert "capacity-plan.json" in reference


def test_checked_in_agentgateway_windows_are_correlated_and_sanitized() -> None:
    retained_keys: set[str] = set()

    def retain_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            retained_keys.add(key)
            document[key] = value
        return document

    document: dict[str, Any] = json.loads(
        AGENTGATEWAY_EVIDENCE.read_text(encoding="utf-8"),
        object_pairs_hook=retain_keys,
    )

    assert document["schema_version"] == 1
    assert document["case"] == "agentgateway_reliability_correlation"
    assert document["evidence_scope"] == "isolated_local_containers"
    assert document["runtime"]["stateless_http"] is True
    assert document["gateway"] == {
        "name": "AgentGateway",
        "version": "v1.4.1",
        "image_digest": ("sha256:efd79355b89094a8225a9db465d9a01dc656b377f0bab458761b935a13231d29"),
        "retries": 0,
    }
    assert document["passed"] is True
    correlations = tuple(
        ReliabilityCorrelationEvidence.model_validate_json(json.dumps(item))
        for item in document["correlations"]
    )
    assert {item.kind for item in correlations} == set(ReliabilityLoadKind)
    loads = {item["kind"]: item for item in document["loads"]}
    assert set(loads) == {item.value for item in ReliabilityLoadKind}
    for correlation in correlations:
        load = loads[correlation.kind.value]
        assert correlation.requests == load["completed"] == load["successful"]
        assert correlation.client_p99_milliseconds == load["latency"]["p99_milliseconds"]

    assert retained_keys.isdisjoint(
        {
            "authorization",
            "arguments",
            "container",
            "request_id",
            "tenant",
            "tenant_id",
            "trace_id",
            "workflow_id",
        }
    )
