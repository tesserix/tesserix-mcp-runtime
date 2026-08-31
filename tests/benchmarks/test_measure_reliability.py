from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
MEASURE = ROOT / "benchmarks" / "measure_reliability.py"
OBSERVATION = ROOT / "benchmarks" / "reliability-observations.json"
QUALITY = ROOT / ".github" / "workflows" / "quality.yml"


def test_reliability_measurement_exercises_every_offline_evidence_boundary() -> None:
    completed = subprocess.run(
        [sys.executable, str(MEASURE), "--requests", "32", "--cycles", "2"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert "reliability-tenant" not in completed.stdout
    assert "payload" not in completed.stdout
    report = json.loads(completed.stdout)
    assert report["schema_version"] == 1
    assert report["case"] == "offline_reliability_harness"
    assert report["evidence_scope"] == "local_process_without_network"
    assert report["requests_per_load"] == 32
    assert report["soak_cycles"] == 2
    assert report["profile_digest"].startswith("sha256:")
    assert {(item["lane"], item["kind"]) for item in report["loads"]} == {
        ("in_process", "sustained"),
        ("in_process", "burst"),
        ("in_process", "boundary"),
    }
    assert all(item["completed"] == 32 for item in report["loads"])
    assert all(item["successful"] == 32 for item in report["loads"])
    assert len(report["soak"]["resources"]) == 6
    assert report["statelessness"]["replicas"] == 2
    assert report["statelessness"]["replica_switches"] == 7
    assert report["statelessness"]["external_effects"] == 1
    assert report["statelessness"]["request_memory_entries"] == 0
    assert report["statelessness"]["request_filesystem_entries"] == 0
    assert report["statelessness"]["session_affinity_required"] is False
    assert report["fault_injection"]["dependency_scenarios"] == 6
    assert report["fairness_injection"]["mode"] == "tenant_saturation"
    assert report["retry_injection"]["observed_effects"] == 1
    assert report["rollout_injection"]["scenarios"] == 5
    assert report["soak"]["completed_calls"] == 64
    assert all(item["samples"] == 3 for item in report["soak"]["resources"])
    assert report["fairness"]["global_limit"] == 64
    assert report["fairness"]["tool_limit"] == 32
    assert report["fairness"]["tenant_limit"] == 16
    assert report["fairness_injection"] == {
        "mode": "tenant_saturation",
        "noisy_started": 32,
        "reserved_started": 8,
    }
    assert report["stateless_injection"] == {
        "deliveries": 8,
        "mode": "cross_replica",
        "replicas": 2,
    }
    assert report["statelessness"] == {
        "deliveries": 8,
        "external_effects": 1,
        "replica_switches": 7,
        "replicas": 2,
        "request_filesystem_entries": 0,
        "request_memory_entries": 0,
        "session_affinity_required": False,
        "successful_calls": 8,
    }
    assert report["retry_injection"] == {
        "duplicate_deliveries": 10,
        "mode": "deterministic",
        "observed_effects": 1,
        "owning_layer": "runtime",
    }
    assert report["retry"]["effects"] == 1
    assert {item["layer"]: item["count"] for item in report["retry"]["retries"]} == {
        "client": 0,
        "agentgateway": 0,
        "mesh": 0,
        "runtime": 2,
    }
    assert len(report["dependencies"]) == 6
    dependencies = {item["dependency"]: item for item in report["dependencies"]}
    assert report["fault_injection"] == {
        "dependency_calls": 120,
        "dependency_scenarios": 6,
        "mode": "deterministic",
    }
    assert all(item["affected_calls"] == 10 for item in dependencies.values())
    assert all(item["unaffected_successes"] == 10 for item in dependencies.values())
    assert dependencies["registry"]["affected_outcome"] == "success"
    assert dependencies["agentgateway"]["affected_outcome"] == "unavailable"
    assert dependencies["identity"]["stale_cache_successes"] == 5
    assert dependencies["identity"]["fail_closed_count"] == 5
    assert dependencies["telemetry"]["telemetry_drop_count"] == 10
    assert dependencies["dns"]["circuit_open_count"] == 1
    assert dependencies["backing_api"]["circuit_open_count"] == 1
    assert len(report["rollouts"]) == 5
    rollouts = {item["scenario"]: item for item in report["rollouts"]}
    assert report["rollout_injection"] == {
        "accepted_calls": 40,
        "mode": "deterministic",
        "scenarios": 5,
    }
    assert all(item["completed_calls"] == 8 for item in rollouts.values())
    assert all(item["rejected_new_calls"] == 2 for item in rollouts.values())
    assert rollouts["rolling_update"]["interruption_seconds"] == 0
    assert rollouts["canary_abort"]["interruption_seconds"] == 0
    assert all(item["drain_seconds"] == 4 for item in rollouts.values())
    assert all(item["previous_capacity_preserved"] for item in rollouts.values())
    assert all(item["rollback_restored"] for item in rollouts.values())
    assert report["capacity"]["minimum_replicas"] == 2
    assert report["capacity"]["scaling_metric"] == "mcp_server_saturation_ratio"
    assert report["network_lanes"] == {
        "agentgateway": "deferred_to_container_lane",
        "direct_http": "deferred_to_container_lane",
    }
    assert report["passed"] is True


def test_checked_in_reliability_observation_passes_the_offline_gate() -> None:
    report = json.loads(OBSERVATION.read_text(encoding="utf-8"))

    assert report["schema_version"] == 1
    assert report["requests_per_load"] >= 200
    assert report["soak_cycles"] >= 3
    assert len(report["soak"]["resources"]) == 6
    assert report["statelessness"]["replicas"] == 2
    assert report["statelessness"]["replica_switches"] == 7
    assert report["statelessness"]["external_effects"] == 1
    assert report["statelessness"]["request_memory_entries"] == 0
    assert report["statelessness"]["request_filesystem_entries"] == 0
    assert report["statelessness"]["session_affinity_required"] is False
    assert report["fault_injection"]["dependency_scenarios"] == 6
    assert report["fairness_injection"]["mode"] == "tenant_saturation"
    assert report["retry_injection"]["observed_effects"] == 1
    assert report["rollout_injection"]["scenarios"] == 5
    assert report["network_lanes"]["direct_http"] == "deferred_to_container_lane"
    assert report["network_lanes"]["agentgateway"] == "deferred_to_container_lane"
    assert report["passed"] is True


def test_quality_workflow_runs_the_offline_reliability_gate() -> None:
    workflow = QUALITY.read_text(encoding="utf-8")

    assert "uv run --frozen python benchmarks/measure_reliability.py" in workflow
