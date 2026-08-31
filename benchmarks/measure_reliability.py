from __future__ import annotations

import argparse
import asyncio
import json
import platform
import sys

from tesserix_mcp_testkit import (
    ReliabilityCapacityPlan,
    ReliabilityDependency,
    ReliabilityDependencyEvidence,
    ReliabilityDependencyPlan,
    ReliabilityDependencySnapshot,
    ReliabilityFairnessEvidence,
    ReliabilityFairnessPlan,
    ReliabilityLane,
    ReliabilityLoadEvidence,
    ReliabilityLoadKind,
    ReliabilityLoadPlan,
    ReliabilityOutcome,
    ReliabilityRequest,
    ReliabilityResource,
    ReliabilityResourceBudget,
    ReliabilityResourceSnapshot,
    ReliabilityRetryCount,
    ReliabilityRetryEvidence,
    ReliabilityRetryLayer,
    ReliabilityRetryPlan,
    ReliabilityRetrySnapshot,
    ReliabilityRolloutEvidence,
    ReliabilityRolloutPlan,
    ReliabilityRolloutScenario,
    ReliabilityRolloutSnapshot,
    ReliabilitySoakPlan,
    ReliabilityStatelessEvidence,
    ReliabilityStatelessPlan,
    ReliabilityStatelessRequest,
    ReliabilityStatelessSnapshot,
    ReliabilityTargetResult,
    reliability_profile_digest,
    run_reliability_dependency_failure,
    run_reliability_fairness_scenario,
    run_reliability_load,
    run_reliability_retry_scenario,
    run_reliability_rollout_scenario,
    run_reliability_soak,
    run_reliability_stateless_scenario,
    standard_reliability_profile,
)


class _Target:
    lane = ReliabilityLane.IN_PROCESS

    async def invoke(self, request: ReliabilityRequest) -> ReliabilityTargetResult:
        await asyncio.sleep(0)
        return ReliabilityTargetResult(
            outcome=ReliabilityOutcome.SUCCESS,
            response_bytes=request.response_bytes,
        )


class _Probe:
    def __init__(self, snapshots: tuple[ReliabilityResourceSnapshot, ...]) -> None:
        self._snapshots = iter(snapshots)

    async def snapshot(self) -> ReliabilityResourceSnapshot:
        return next(self._snapshots)


class _DependencyFaultTarget:
    lane = ReliabilityLane.IN_PROCESS

    def __init__(self, dependency: ReliabilityDependency) -> None:
        self.dependency = dependency
        self.runtime_retries = 0
        self.circuit_open_count = 0
        self.telemetry_drop_count = 0
        self.stale_cache_successes = 0
        self.fail_closed_count = 0

    async def snapshot(self) -> ReliabilityDependencySnapshot:
        return ReliabilityDependencySnapshot(
            runtime_retries=self.runtime_retries,
            circuit_open_count=self.circuit_open_count,
            telemetry_drop_count=self.telemetry_drop_count,
            stale_cache_successes=self.stale_cache_successes,
            fail_closed_count=self.fail_closed_count,
        )

    async def invoke_affected(self, request: ReliabilityRequest) -> ReliabilityTargetResult:
        await asyncio.sleep(0)
        match self.dependency:
            case ReliabilityDependency.REGISTRY:
                return self._success(request)
            case ReliabilityDependency.AGENTGATEWAY:
                return ReliabilityTargetResult(outcome=ReliabilityOutcome.UNAVAILABLE)
            case ReliabilityDependency.IDENTITY:
                if request.sequence < 5:
                    self.stale_cache_successes += 1
                else:
                    self.fail_closed_count += 1
                return ReliabilityTargetResult(outcome=ReliabilityOutcome.AUTHENTICATION_DENIED)
            case ReliabilityDependency.TELEMETRY:
                self.telemetry_drop_count += 1
                return self._success(request)
            case ReliabilityDependency.DNS:
                if request.sequence == 2:
                    self.circuit_open_count += 1
                return ReliabilityTargetResult(outcome=ReliabilityOutcome.TIMEOUT)
            case ReliabilityDependency.BACKING_API:
                if request.sequence < 2:
                    self.runtime_retries += 1
                if request.sequence == 2:
                    self.circuit_open_count += 1
                return ReliabilityTargetResult(outcome=ReliabilityOutcome.UNAVAILABLE)

    async def invoke_unaffected(self, request: ReliabilityRequest) -> ReliabilityTargetResult:
        await asyncio.sleep(0)
        return self._success(request)

    @staticmethod
    def _success(request: ReliabilityRequest) -> ReliabilityTargetResult:
        return ReliabilityTargetResult(
            outcome=ReliabilityOutcome.SUCCESS,
            response_bytes=request.response_bytes,
        )


class _RetryFaultTarget:
    lane = ReliabilityLane.IN_PROCESS
    owning_layer = ReliabilityRetryLayer.RUNTIME
    maximum_attempts = 3

    def __init__(self) -> None:
        self.effects = 0
        self.retry_counts = dict.fromkeys(ReliabilityRetryLayer, 0)

    async def snapshot(self) -> ReliabilityRetrySnapshot:
        return ReliabilityRetrySnapshot(
            effects=self.effects,
            retries=tuple(
                ReliabilityRetryCount(layer=layer, count=self.retry_counts[layer])
                for layer in ReliabilityRetryLayer
            ),
        )

    async def invoke_duplicate(self, delivery: int) -> ReliabilityTargetResult:
        await asyncio.sleep(0)
        if delivery == 0:
            self.effects += 1
        if delivery < 2:
            self.retry_counts[ReliabilityRetryLayer.RUNTIME] += 1
        return ReliabilityTargetResult(outcome=ReliabilityOutcome.SUCCESS)


class _RolloutFaultTarget:
    def __init__(self, scenario: ReliabilityRolloutScenario) -> None:
        self.scenario = scenario
        self.accepted_calls = 0
        self.completed_calls = 0
        self.rejected_new_calls = 0
        self.interruption_seconds = 0.0
        self.drain_seconds = 0.0
        self.previous_capacity_preserved = False
        self.rollback_restored = False

    async def snapshot(self) -> ReliabilityRolloutSnapshot:
        return ReliabilityRolloutSnapshot(
            accepted_calls=self.accepted_calls,
            completed_calls=self.completed_calls,
            rejected_new_calls=self.rejected_new_calls,
            interruption_seconds=self.interruption_seconds,
            drain_seconds=self.drain_seconds,
            previous_capacity_preserved=self.previous_capacity_preserved,
            rollback_restored=self.rollback_restored,
        )

    async def accept(self, calls: int) -> None:
        self.accepted_calls += calls

    async def begin_transition(self) -> None:
        self.previous_capacity_preserved = True

    async def reject_new(self, calls: int) -> None:
        self.rejected_new_calls += calls

    async def drain(self) -> None:
        self.completed_calls = self.accepted_calls
        self.drain_seconds += 4

    async def restore(self) -> None:
        if self.scenario not in {
            ReliabilityRolloutScenario.ROLLING_UPDATE,
            ReliabilityRolloutScenario.CANARY_ABORT,
        }:
            self.interruption_seconds += 2
        self.rollback_restored = True


class _StatelessFaultTarget:
    replica_count = 2

    def __init__(self) -> None:
        self.external_effects = 0
        self.idempotency_keys: set[str] = set()

    async def snapshot(self) -> ReliabilityStatelessSnapshot:
        return ReliabilityStatelessSnapshot(
            external_effects=self.external_effects,
            request_memory_entries=(0, 0),
            request_filesystem_entries=(0, 0),
            session_affinity_required=False,
        )

    async def invoke(
        self,
        replica: int,
        request: ReliabilityStatelessRequest,
    ) -> ReliabilityTargetResult:
        del replica
        await asyncio.sleep(0)
        if request.idempotency_key not in self.idempotency_keys:
            self.idempotency_keys.add(request.idempotency_key)
            self.external_effects += 1
        return ReliabilityTargetResult(outcome=ReliabilityOutcome.SUCCESS)


class _FairnessFaultTarget:
    lane = ReliabilityLane.IN_PROCESS
    global_limit = 64
    tool_limit = 32
    tenant_limit = 16

    def __init__(self, noisy_started: int) -> None:
        self.noisy_started = noisy_started
        self.noisy_seen = 0
        self.noisy_admitted = 0
        self.noisy_classified = asyncio.Event()
        self.release = asyncio.Event()

    async def invoke_noisy(self, sequence: int) -> ReliabilityTargetResult:
        del sequence
        self.noisy_seen += 1
        admitted = self.noisy_admitted < self.tenant_limit
        if admitted:
            self.noisy_admitted += 1
        if self.noisy_seen == self.noisy_started:
            self.noisy_classified.set()
        if not admitted:
            return ReliabilityTargetResult(outcome=ReliabilityOutcome.OVERLOADED)
        await self.release.wait()
        return ReliabilityTargetResult(outcome=ReliabilityOutcome.SUCCESS)

    async def wait_until_noisy_classified(self) -> None:
        await self.noisy_classified.wait()

    async def invoke_reserved(self, sequence: int) -> ReliabilityTargetResult:
        del sequence
        await asyncio.sleep(0)
        return ReliabilityTargetResult(outcome=ReliabilityOutcome.SUCCESS)

    async def release_noisy(self) -> None:
        self.release.set()


def _bounded_requests(value: str) -> int:
    requests = int(value)
    if not 1 <= requests <= 10_000:
        raise argparse.ArgumentTypeError("requests must be between 1 and 10000")
    return requests


def _bounded_cycles(value: str) -> int:
    cycles = int(value)
    if not 2 <= cycles <= 100:
        raise argparse.ArgumentTypeError("cycles must be between 2 and 100")
    return cycles


def _load_plans(requests: int) -> tuple[ReliabilityLoadPlan, ...]:
    return (
        ReliabilityLoadPlan(
            name="offline-sustained",
            lane=ReliabilityLane.IN_PROCESS,
            kind=ReliabilityLoadKind.SUSTAINED,
            requests=requests,
            concurrency=min(16, requests),
            tenants=min(4, requests),
            request_bytes=1_024,
            response_bytes=4_096,
        ),
        ReliabilityLoadPlan(
            name="offline-burst",
            lane=ReliabilityLane.IN_PROCESS,
            kind=ReliabilityLoadKind.BURST,
            requests=requests,
            concurrency=min(64, requests),
            tenants=min(16, requests),
            request_bytes=1_024,
            response_bytes=4_096,
        ),
        ReliabilityLoadPlan(
            name="offline-boundary",
            lane=ReliabilityLane.IN_PROCESS,
            kind=ReliabilityLoadKind.BOUNDARY,
            requests=requests,
            concurrency=min(8, requests),
            tenants=min(4, requests),
            request_bytes=65_536,
            response_bytes=524_288,
        ),
    )


def _resource_budgets() -> tuple[ReliabilityResourceBudget, ...]:
    maxima = {
        ReliabilityResource.RSS_MEBIBYTES: 128,
        ReliabilityResource.TASKS: 256,
        ReliabilityResource.CONNECTIONS: 64,
        ReliabilityResource.SESSIONS: 128,
        ReliabilityResource.TELEMETRY_BUFFER: 2_048,
        ReliabilityResource.CREDENTIAL_CACHE: 32,
    }
    return tuple(
        ReliabilityResourceBudget(
            resource=resource,
            maximum=maxima[resource],
            permitted_growth=(4 if resource is ReliabilityResource.RSS_MEBIBYTES else 0),
        )
        for resource in ReliabilityResource
    )


def _resource_snapshots(cycles: int) -> tuple[ReliabilityResourceSnapshot, ...]:
    snapshots = [
        ReliabilityResourceSnapshot(
            rss_mebibytes=80,
            tasks=0,
            connections=0,
            sessions=0,
            telemetry_buffer=0,
            credential_cache=0,
        )
    ]
    for cycle in range(1, cycles + 1):
        active = 0 if cycle == cycles else 2
        snapshots.append(
            ReliabilityResourceSnapshot(
                rss_mebibytes=(82 if cycle == cycles else 84),
                tasks=active,
                connections=active,
                sessions=active,
                telemetry_buffer=active,
                credential_cache=active,
            )
        )
    return tuple(snapshots)


async def _fairness() -> ReliabilityFairnessEvidence:
    plan = ReliabilityFairnessPlan(
        lane=ReliabilityLane.IN_PROCESS,
        global_limit=64,
        tool_limit=32,
        tenant_limit=16,
        noisy_started=32,
        reserved_started=8,
    )
    return await run_reliability_fairness_scenario(
        plan,
        _FairnessFaultTarget(noisy_started=plan.noisy_started),
    )


async def _retry() -> ReliabilityRetryEvidence:
    return await run_reliability_retry_scenario(
        ReliabilityRetryPlan(
            lane=ReliabilityLane.IN_PROCESS,
            owning_layer=ReliabilityRetryLayer.RUNTIME,
            maximum_attempts=3,
            calls=10,
        ),
        _RetryFaultTarget(),
    )


async def _statelessness() -> ReliabilityStatelessEvidence:
    return await run_reliability_stateless_scenario(
        ReliabilityStatelessPlan(deliveries=8, replicas=2),
        _StatelessFaultTarget(),
    )


async def _dependencies() -> tuple[ReliabilityDependencyEvidence, ...]:
    evidence: list[ReliabilityDependencyEvidence] = []
    for dependency in ReliabilityDependency:
        evidence.append(
            await run_reliability_dependency_failure(
                ReliabilityDependencyPlan(
                    dependency=dependency,
                    lane=ReliabilityLane.IN_PROCESS,
                    affected_calls=10,
                    unaffected_calls=10,
                    request_bytes=1_024,
                    response_bytes=4_096,
                ),
                _DependencyFaultTarget(dependency),
            )
        )
    return tuple(evidence)


async def _rollouts() -> tuple[ReliabilityRolloutEvidence, ...]:
    evidence: list[ReliabilityRolloutEvidence] = []
    for scenario in ReliabilityRolloutScenario:
        evidence.append(
            await run_reliability_rollout_scenario(
                ReliabilityRolloutPlan(
                    scenario=scenario,
                    accepted_calls=8,
                    new_calls=2,
                ),
                _RolloutFaultTarget(scenario),
            )
        )
    return tuple(evidence)


def _capacity() -> ReliabilityCapacityPlan:
    return ReliabilityCapacityPlan(
        observed_sustained_requests_per_second=55,
        observed_burst_requests_per_second=210,
        handler_p99_milliseconds=250,
        maximum_concurrency=64,
        normal_occupancy_ratio=0.5,
        minimum_replicas=2,
        maximum_replicas=10,
        observed_peak_rss_mebibytes=112,
        memory_request_mebibytes=128,
        memory_limit_mebibytes=256,
        termination_grace_seconds=45,
        scaling_metric="mcp_server_saturation_ratio",
        scaling_target=0.5,
    )


def _loads_pass(loads: tuple[ReliabilityLoadEvidence, ...]) -> bool:
    by_kind = {load.kind: load for load in loads}
    return (
        len(by_kind) == len(ReliabilityLoadKind)
        and all(load.successful == load.completed for load in loads)
        and all(load.maximum_queue_depth == 0 for load in loads)
        and all(load.latency.p99_milliseconds <= 15 for load in loads)
        and by_kind[ReliabilityLoadKind.SUSTAINED].throughput_requests_per_second >= 50
        and by_kind[ReliabilityLoadKind.BURST].throughput_requests_per_second >= 200
        and by_kind[ReliabilityLoadKind.BOUNDARY].request_bytes == 65_536
        and by_kind[ReliabilityLoadKind.BOUNDARY].response_bytes == 524_288
    )


async def _measure(requests: int, cycles: int) -> dict[str, object]:
    target = _Target()
    loads = tuple([await run_reliability_load(plan, target) for plan in _load_plans(requests)])
    soak = await run_reliability_soak(
        ReliabilitySoakPlan(
            load=ReliabilityLoadPlan(
                name="offline-soak",
                lane=ReliabilityLane.IN_PROCESS,
                requests=requests,
                concurrency=min(16, requests),
                tenants=min(4, requests),
                request_bytes=1_024,
                response_bytes=4_096,
            ),
            cycles=cycles,
            budgets=_resource_budgets(),
        ),
        target,
        _Probe(_resource_snapshots(cycles)),
    )
    fairness = await _fairness()
    statelessness = await _statelessness()
    retry = await _retry()
    dependencies = await _dependencies()
    rollouts = await _rollouts()
    capacity = _capacity()
    resources_pass = all(
        item.growth <= item.permitted_growth and item.peak <= item.maximum
        for item in soak.resources
    )
    passed = (
        _loads_pass(loads)
        and resources_pass
        and fairness.reserved_successful == fairness.reserved_started
        and statelessness.successful_calls == statelessness.deliveries
        and statelessness.external_effects == 1
        and not statelessness.session_affinity_required
        and retry.effects == 1
        and all(item.unaffected_successes > 0 for item in dependencies)
        and all(item.completed_calls == item.accepted_calls for item in rollouts)
        and capacity.minimum_replicas >= 2
    )
    profile = standard_reliability_profile()
    return {
        "schema_version": 1,
        "case": "offline_reliability_harness",
        "evidence_scope": "local_process_without_network",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "profile_digest": reliability_profile_digest(profile),
        "requests_per_load": requests,
        "soak_cycles": cycles,
        "loads": [item.model_dump(mode="json") for item in loads],
        "soak": {
            "completed_calls": soak.completed_calls,
            "resources": [item.model_dump(mode="json") for item in soak.resources],
        },
        "fairness": fairness.model_dump(mode="json"),
        "fairness_injection": {
            "mode": "tenant_saturation",
            "noisy_started": fairness.noisy_started,
            "reserved_started": fairness.reserved_started,
        },
        "statelessness": statelessness.model_dump(mode="json"),
        "stateless_injection": {
            "mode": "cross_replica",
            "deliveries": statelessness.deliveries,
            "replicas": statelessness.replicas,
        },
        "retry": retry.model_dump(mode="json"),
        "retry_injection": {
            "mode": "deterministic",
            "duplicate_deliveries": retry.calls,
            "observed_effects": retry.effects,
            "owning_layer": retry.owning_layer.value,
        },
        "dependencies": [item.model_dump(mode="json") for item in dependencies],
        "fault_injection": {
            "mode": "deterministic",
            "dependency_scenarios": len(dependencies),
            "dependency_calls": sum(
                item.affected_calls + item.unaffected_successes for item in dependencies
            ),
        },
        "rollouts": [item.model_dump(mode="json") for item in rollouts],
        "rollout_injection": {
            "mode": "deterministic",
            "scenarios": len(rollouts),
            "accepted_calls": sum(item.accepted_calls for item in rollouts),
        },
        "capacity": capacity.model_dump(mode="json"),
        "network_lanes": {
            "direct_http": "deferred_to_container_lane",
            "agentgateway": "deferred_to_container_lane",
        },
        "passed": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=_bounded_requests, default=200)
    parser.add_argument("--cycles", type=_bounded_cycles, default=3)
    arguments = parser.parse_args()
    try:
        report = asyncio.run(_measure(arguments.requests, arguments.cycles))
    except (RuntimeError, TypeError, ValueError):
        json.dump({"code": "reliability_measurement_failed"}, sys.stderr)
        sys.stderr.write("\n")
        return 2
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
