from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest
import tesserix_mcp_testkit
import tesserix_mcp_testkit.reliability as reliability_module
from tesserix_mcp_testkit.reliability import (
    ReliabilityCapacityPlan,
    ReliabilityCorrelationEvidence,
    ReliabilityDependency,
    ReliabilityDependencyEvidence,
    ReliabilityDependencyPlan,
    ReliabilityDependencySnapshot,
    ReliabilityFairnessEvidence,
    ReliabilityFairnessPlan,
    ReliabilityLane,
    ReliabilityLatency,
    ReliabilityLoadEvidence,
    ReliabilityLoadKind,
    ReliabilityLoadPlan,
    ReliabilityOutcome,
    ReliabilityOutcomeCount,
    ReliabilityReport,
    ReliabilityReportBinding,
    ReliabilityRequest,
    ReliabilityResource,
    ReliabilityResourceBudget,
    ReliabilityResourceEvidence,
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
    assess_reliability_report,
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


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _correlation_values(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "lane": ReliabilityLane.AGENTGATEWAY,
        "kind": ReliabilityLoadKind.SUSTAINED,
        "window_digest": _digest("d"),
        "requests": 100,
        "client_samples": 100,
        "gateway_tool_calls": 100,
        "gateway_metric_samples": 200,
        "runtime_span_samples": 100,
        "runtime_metric_samples": 100,
        "pod_resource_samples": 20,
        "client_p99_milliseconds": 25.0,
        "gateway_p99_milliseconds": 20.0,
        "runtime_span_p99_milliseconds": 8.0,
        "runtime_metric_p99_milliseconds": 8.0,
        "pod_cpu_millicores_peak": 180.0,
        "pod_rss_mebibytes_peak": 112.0,
    }
    values.update(updates)
    return values


def _correlation_evidence(**updates: object) -> ReliabilityCorrelationEvidence:
    return ReliabilityCorrelationEvidence.model_validate(_correlation_values(**updates))


def _reliability_mutant(
    mutate: Callable[[ReliabilityReport], ReliabilityReport],
    reason: str,
    *,
    case_id: str,
) -> object:
    return pytest.param(mutate, reason, id=case_id)


def test_reliability_contract_is_a_stable_public_testkit_surface() -> None:
    expected = {
        "ReliabilityCapacityPlan",
        "ReliabilityCorrelationEvidence",
        "ReliabilityDecision",
        "ReliabilityDependency",
        "ReliabilityDependencyEvidence",
        "ReliabilityDependencyPlan",
        "ReliabilityDependencySnapshot",
        "ReliabilityDependencyTarget",
        "ReliabilityFairnessEvidence",
        "ReliabilityFairnessPlan",
        "ReliabilityFairnessTarget",
        "ReliabilityLane",
        "ReliabilityLatency",
        "ReliabilityLoadEvidence",
        "ReliabilityLoadKind",
        "ReliabilityLoadPlan",
        "ReliabilityOutcome",
        "ReliabilityOutcomeCount",
        "ReliabilityProfile",
        "ReliabilityReport",
        "ReliabilityReportBinding",
        "ReliabilityRequest",
        "ReliabilityResource",
        "ReliabilityResourceBudget",
        "ReliabilityResourceEvidence",
        "ReliabilityResourceProbe",
        "ReliabilityResourceSnapshot",
        "ReliabilityRetryCount",
        "ReliabilityRetryEvidence",
        "ReliabilityRetryLayer",
        "ReliabilityRetryPlan",
        "ReliabilityRetrySnapshot",
        "ReliabilityRetryTarget",
        "ReliabilityRolloutEvidence",
        "ReliabilityRolloutPlan",
        "ReliabilityRolloutScenario",
        "ReliabilityRolloutSnapshot",
        "ReliabilityRolloutTarget",
        "ReliabilitySoakPlan",
        "ReliabilitySoakResult",
        "ReliabilityStatelessEvidence",
        "ReliabilityStatelessPlan",
        "ReliabilityStatelessRequest",
        "ReliabilityStatelessSnapshot",
        "ReliabilityStatelessTarget",
        "ReliabilityTarget",
        "ReliabilityTargetResult",
        "assess_reliability_report",
        "reliability_profile_digest",
        "run_reliability_dependency_failure",
        "run_reliability_fairness_scenario",
        "run_reliability_load",
        "run_reliability_retry_scenario",
        "run_reliability_rollout_scenario",
        "run_reliability_soak",
        "run_reliability_stateless_scenario",
        "standard_reliability_profile",
    }

    assert expected <= set(tesserix_mcp_testkit.__all__)
    for name in expected:
        assert getattr(tesserix_mcp_testkit, name) is getattr(reliability_module, name)


def _load(
    lane: ReliabilityLane,
    kind: ReliabilityLoadKind,
    *,
    throughput: float,
    p99: float,
) -> ReliabilityLoadEvidence:
    return ReliabilityLoadEvidence(
        name=f"{lane.value.replace('_', '-')}-{kind.value}",
        lane=lane,
        kind=kind,
        request_bytes=65_536,
        response_bytes=524_288,
        completed=200,
        successful=200,
        outcomes=(ReliabilityOutcomeCount(outcome=ReliabilityOutcome.SUCCESS, count=200),),
        duration_seconds=1,
        throughput_requests_per_second=throughput,
        latency=ReliabilityLatency(
            p50_milliseconds=p99 / 2,
            p95_milliseconds=p99,
            p99_milliseconds=p99,
            maximum_milliseconds=p99,
        ),
        peak_client_concurrency=32,
        maximum_queue_depth=0,
        sample_digest=_digest("1"),
    )


def _complete_report() -> ReliabilityReport:
    loads = tuple(
        _load(
            lane,
            kind,
            throughput=(210 if kind is ReliabilityLoadKind.BURST else 55),
            p99=(8 if lane is ReliabilityLane.IN_PROCESS else 25),
        )
        for lane in ReliabilityLane
        for kind in ReliabilityLoadKind
    )
    resources = tuple(
        ReliabilityResourceEvidence(
            resource=resource,
            baseline=(80 if resource is ReliabilityResource.RSS_MEBIBYTES else 0),
            peak=(112 if resource is ReliabilityResource.RSS_MEBIBYTES else 16),
            final=(82 if resource is ReliabilityResource.RSS_MEBIBYTES else 0),
            maximum=(128 if resource is ReliabilityResource.RSS_MEBIBYTES else 2_048),
            permitted_growth=(4 if resource is ReliabilityResource.RSS_MEBIBYTES else 0),
            samples=20,
        )
        for resource in ReliabilityResource
    )
    correlation_digests = {
        ReliabilityLoadKind.SUSTAINED: "d",
        ReliabilityLoadKind.BURST: "e",
        ReliabilityLoadKind.BOUNDARY: "f",
    }
    correlations = tuple(
        _correlation_evidence(
            kind=load.kind,
            window_digest=_digest(correlation_digests[load.kind]),
            requests=load.completed,
            client_samples=load.completed,
            gateway_tool_calls=load.completed,
            gateway_metric_samples=load.completed,
            runtime_span_samples=load.completed,
            runtime_metric_samples=load.completed,
            client_p99_milliseconds=load.latency.p99_milliseconds,
        )
        for load in loads
        if load.lane is ReliabilityLane.AGENTGATEWAY
    )
    dependencies = tuple(
        ReliabilityDependencyEvidence(
            dependency=dependency,
            affected_calls=10,
            affected_outcome=(
                ReliabilityOutcome.SUCCESS
                if dependency in {ReliabilityDependency.REGISTRY, ReliabilityDependency.TELEMETRY}
                else ReliabilityOutcome.AUTHENTICATION_DENIED
                if dependency is ReliabilityDependency.IDENTITY
                else ReliabilityOutcome.UNAVAILABLE
            ),
            unaffected_successes=10,
            maximum_queue_depth=0,
            runtime_retries=(2 if dependency is ReliabilityDependency.BACKING_API else 0),
            circuit_open_count=(
                1
                if dependency in {ReliabilityDependency.DNS, ReliabilityDependency.BACKING_API}
                else 0
            ),
            telemetry_drop_count=(10 if dependency is ReliabilityDependency.TELEMETRY else 0),
            stale_cache_successes=(5 if dependency is ReliabilityDependency.IDENTITY else 0),
            fail_closed_count=(5 if dependency is ReliabilityDependency.IDENTITY else 0),
        )
        for dependency in ReliabilityDependency
    )
    rollouts = tuple(
        ReliabilityRolloutEvidence(
            scenario=scenario,
            accepted_calls=8,
            completed_calls=8,
            rejected_new_calls=2,
            interruption_seconds=(0 if scenario is ReliabilityRolloutScenario.CANARY_ABORT else 2),
            drain_seconds=4,
            previous_capacity_preserved=True,
            rollback_restored=True,
        )
        for scenario in ReliabilityRolloutScenario
    )
    return ReliabilityReport(
        schema_version=1,
        binding=ReliabilityReportBinding(
            source_digest=_digest("a"),
            runtime_digest=_digest("b"),
            image_digest=_digest("c"),
            profile_digest=reliability_profile_digest(standard_reliability_profile()),
        ),
        complete=True,
        startup_seconds=0.8,
        idle_rss_mebibytes=80,
        loads=loads,
        correlations=correlations,
        resources=resources,
        fairness=ReliabilityFairnessEvidence(
            global_limit=64,
            tool_limit=32,
            tenant_limit=16,
            noisy_started=32,
            noisy_admitted=16,
            noisy_overloaded=16,
            reserved_started=8,
            reserved_successful=8,
        ),
        statelessness=ReliabilityStatelessEvidence(
            deliveries=8,
            replicas=2,
            successful_calls=8,
            replica_switches=7,
            external_effects=1,
            request_memory_entries=0,
            request_filesystem_entries=0,
            session_affinity_required=False,
        ),
        retry=ReliabilityRetryEvidence(
            owning_layer=ReliabilityRetryLayer.RUNTIME,
            maximum_attempts=3,
            calls=10,
            effects=1,
            retries=tuple(
                ReliabilityRetryCount(
                    layer=layer,
                    count=(2 if layer is ReliabilityRetryLayer.RUNTIME else 0),
                )
                for layer in ReliabilityRetryLayer
            ),
        ),
        dependencies=dependencies,
        rollouts=rollouts,
        capacity=ReliabilityCapacityPlan(
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
        ),
    )


def _mutate_load(
    report: ReliabilityReport,
    lane: ReliabilityLane,
    kind: ReliabilityLoadKind,
    **updates: object,
) -> ReliabilityReport:
    loads = tuple(
        item.model_copy(update=updates) if (item.lane, item.kind) == (lane, kind) else item
        for item in report.loads
    )
    return report.model_copy(update={"loads": loads})


def _mutate_correlation(
    report: ReliabilityReport,
    kind: ReliabilityLoadKind,
    **updates: object,
) -> ReliabilityReport:
    correlations = tuple(
        item.model_copy(update=updates) if item.kind is kind else item
        for item in report.correlations
    )
    return report.model_copy(update={"correlations": correlations})


def _mutate_resource(
    report: ReliabilityReport,
    resource: ReliabilityResource,
    **updates: object,
) -> ReliabilityReport:
    resources = tuple(
        item.model_copy(update=updates) if item.resource is resource else item
        for item in report.resources
    )
    return report.model_copy(update={"resources": resources})


def _mutate_dependency(
    report: ReliabilityReport,
    dependency: ReliabilityDependency,
    **updates: object,
) -> ReliabilityReport:
    dependencies = tuple(
        item.model_copy(update=updates) if item.dependency is dependency else item
        for item in report.dependencies
    )
    return report.model_copy(update={"dependencies": dependencies})


def _mutate_rollout(
    report: ReliabilityReport,
    scenario: ReliabilityRolloutScenario,
    **updates: object,
) -> ReliabilityReport:
    rollouts = tuple(
        item.model_copy(update=updates) if item.scenario is scenario else item
        for item in report.rollouts
    )
    return report.model_copy(update={"rollouts": rollouts})


def _mutate_retry_count(
    report: ReliabilityReport,
    layer: ReliabilityRetryLayer,
    count: int,
) -> ReliabilityReport:
    retries = tuple(
        item.model_copy(update={"count": count}) if item.layer is layer else item
        for item in report.retry.retries
    )
    return report.model_copy(update={"retry": report.retry.model_copy(update={"retries": retries})})


def _move_retry_owner(report: ReliabilityReport) -> ReliabilityReport:
    retries = tuple(
        item.model_copy(update={"count": 2 if item.layer is ReliabilityRetryLayer.CLIENT else 0})
        for item in report.retry.retries
    )
    return report.model_copy(
        update={
            "retry": report.retry.model_copy(
                update={"owning_layer": ReliabilityRetryLayer.CLIENT, "retries": retries}
            )
        }
    )


def _mutate_statelessness(
    report: ReliabilityReport,
    **updates: object,
) -> ReliabilityReport:
    return report.model_copy(
        update={"statelessness": report.statelessness.model_copy(update=updates)}
    )


def test_standard_profile_preserves_the_reviewed_runtime_envelope() -> None:
    profile = standard_reliability_profile()

    assert profile.schema_version == 1
    assert profile.sustained_requests_per_second == 50
    assert profile.burst_requests_per_second == 200
    assert profile.request_bytes == 65_536
    assert profile.response_bytes == 524_288
    assert profile.runtime_added_p99_milliseconds == 15
    assert profile.startup_seconds == 2
    assert profile.idle_rss_mebibytes == 128
    assert profile.maximum_interruption_seconds == 5
    assert profile.termination_grace_seconds == 45
    assert profile.maximum_queue_depth == 0
    assert profile.maximum_global_concurrency == 64
    assert profile.maximum_tool_concurrency == 32
    assert profile.maximum_tenant_concurrency == 16
    assert profile.minimum_replicas == 2
    assert profile.normal_occupancy_ratio == 0.5
    assert profile.required_lanes == (
        ReliabilityLane.IN_PROCESS,
        ReliabilityLane.DIRECT_HTTP,
        ReliabilityLane.AGENTGATEWAY,
    )

    load = ReliabilityLoadPlan(
        name="direct-sustained",
        lane=ReliabilityLane.DIRECT_HTTP,
        requests=500,
        concurrency=16,
        tenants=4,
        request_bytes=1_024,
        response_bytes=4_096,
    )
    assert load.model_dump(mode="json")["lane"] == "direct_http"


def test_fairness_evidence_records_every_reviewed_concurrency_limit() -> None:
    fairness = _complete_report().fairness

    assert fairness.global_limit == 64
    assert fairness.tool_limit == 32
    assert fairness.tenant_limit == 16


def test_correlation_evidence_joins_every_source_without_raw_identifiers() -> None:
    evidence_type = reliability_module.ReliabilityCorrelationEvidence
    values = _correlation_values()

    evidence = evidence_type.model_validate(values)

    assert evidence.window_digest == _digest("d")
    assert evidence.client_samples == evidence.gateway_tool_calls == evidence.requests
    assert evidence.gateway_metric_samples == 200
    assert evidence.runtime_span_samples == evidence.runtime_metric_samples == evidence.requests
    with pytest.raises(ValueError):
        evidence_type.model_validate(values | {"request_id": "raw-request-id"})


@pytest.mark.parametrize(
    "updates",
    [
        {"lane": ReliabilityLane.DIRECT_HTTP},
        {"client_samples": 99},
        {"gateway_tool_calls": 99},
        {"gateway_metric_samples": 99},
        {"runtime_span_samples": 99},
        {"runtime_metric_samples": 99},
    ],
)
def test_correlation_evidence_rejects_an_unjoined_telemetry_window(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="AgentGateway window with complete source samples"):
        _correlation_evidence(**updates)


def test_complete_report_correlates_every_agentgateway_load_window() -> None:
    report = _complete_report()
    loads: dict[tuple[ReliabilityLane, ReliabilityLoadKind], ReliabilityLoadEvidence] = {
        (load.lane, load.kind): load
        for load in report.loads
        if load.lane is ReliabilityLane.AGENTGATEWAY
    }

    assert {(item.lane, item.kind) for item in report.correlations} == set(loads)
    for correlation in report.correlations:
        load = loads[(correlation.lane, correlation.kind)]
        assert correlation.requests == load.completed
        assert correlation.client_p99_milliseconds == load.latency.p99_milliseconds


class _LoadTarget:
    lane = ReliabilityLane.IN_PROCESS

    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self.requests: list[ReliabilityRequest] = []

    async def invoke(self, request: ReliabilityRequest) -> ReliabilityTargetResult:
        self.requests.append(request)
        self.active += 1
        self.peak = max(self.peak, self.active)
        await asyncio.sleep(0)
        self.active -= 1
        if request.sequence == 7:
            return ReliabilityTargetResult(outcome=ReliabilityOutcome.OVERLOADED)
        return ReliabilityTargetResult(
            outcome=ReliabilityOutcome.SUCCESS,
            response_bytes=request.response_bytes,
        )


class _CancellingTarget:
    lane = ReliabilityLane.IN_PROCESS

    async def invoke(self, request: ReliabilityRequest) -> ReliabilityTargetResult:
        del request
        raise asyncio.CancelledError


class _ScriptedResourceProbe:
    def __init__(self, snapshots: tuple[ReliabilityResourceSnapshot, ...]) -> None:
        self._snapshots = iter(snapshots)

    async def snapshot(self) -> ReliabilityResourceSnapshot:
        return next(self._snapshots)


class _DependencyTarget:
    lane = ReliabilityLane.IN_PROCESS
    dependency = ReliabilityDependency.BACKING_API

    def __init__(self) -> None:
        self.runtime_retries = 5
        self.circuit_open_count = 7
        self.telemetry_drop_count = 11
        self.stale_cache_successes = 13
        self.fail_closed_count = 17
        self.affected_requests: list[ReliabilityRequest] = []
        self.unaffected_requests: list[ReliabilityRequest] = []

    async def snapshot(self) -> ReliabilityDependencySnapshot:
        return ReliabilityDependencySnapshot(
            runtime_retries=self.runtime_retries,
            circuit_open_count=self.circuit_open_count,
            telemetry_drop_count=self.telemetry_drop_count,
            stale_cache_successes=self.stale_cache_successes,
            fail_closed_count=self.fail_closed_count,
        )

    async def invoke_affected(self, request: ReliabilityRequest) -> ReliabilityTargetResult:
        self.affected_requests.append(request)
        self.runtime_retries += 1
        if request.sequence == 2:
            self.circuit_open_count += 1
        await asyncio.sleep(0)
        return ReliabilityTargetResult(
            outcome=ReliabilityOutcome.UNAVAILABLE,
            queue_depth=2,
        )

    async def invoke_unaffected(self, request: ReliabilityRequest) -> ReliabilityTargetResult:
        self.unaffected_requests.append(request)
        await asyncio.sleep(0)
        return ReliabilityTargetResult(
            outcome=ReliabilityOutcome.SUCCESS,
            response_bytes=request.response_bytes,
        )


class _RetryTarget:
    lane = ReliabilityLane.IN_PROCESS
    owning_layer = ReliabilityRetryLayer.RUNTIME
    maximum_attempts = 3

    def __init__(self) -> None:
        self.effects = 19
        self.retry_counts = dict.fromkeys(ReliabilityRetryLayer, 23)
        self.deliveries: list[int] = []

    async def snapshot(self) -> ReliabilityRetrySnapshot:
        return ReliabilityRetrySnapshot(
            effects=self.effects,
            retries=tuple(
                ReliabilityRetryCount(layer=layer, count=self.retry_counts[layer])
                for layer in ReliabilityRetryLayer
            ),
        )

    async def invoke_duplicate(self, delivery: int) -> ReliabilityTargetResult:
        self.deliveries.append(delivery)
        if delivery == 0:
            self.effects += 1
        if delivery < 2:
            self.retry_counts[ReliabilityRetryLayer.RUNTIME] += 1
        await asyncio.sleep(0)
        return ReliabilityTargetResult(outcome=ReliabilityOutcome.SUCCESS)


class _RolloutTarget:
    scenario = ReliabilityRolloutScenario.SIGTERM

    def __init__(self) -> None:
        self.accepted_calls = 3
        self.completed_calls = 3
        self.rejected_new_calls = 5
        self.interruption_seconds = 11.0
        self.drain_seconds = 13.0
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
        self.rollback_restored = True
        self.interruption_seconds += 2


class _StatelessTarget:
    replica_count = 2

    def __init__(self) -> None:
        self.external_effects = 7
        self.seen_idempotency_keys: set[str] = set()
        self.calls: list[tuple[int, ReliabilityStatelessRequest]] = []

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
        self.calls.append((replica, request))
        if request.idempotency_key not in self.seen_idempotency_keys:
            self.seen_idempotency_keys.add(request.idempotency_key)
            self.external_effects += 1
        await asyncio.sleep(0)
        return ReliabilityTargetResult(outcome=ReliabilityOutcome.SUCCESS)


class _FairnessTarget:
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


def test_load_runner_bounds_client_concurrency_and_sanitizes_evidence() -> None:
    async def exercise() -> None:
        plan = ReliabilityLoadPlan(
            name="fair-load",
            lane=ReliabilityLane.IN_PROCESS,
            requests=8,
            concurrency=3,
            tenants=2,
            request_bytes=1_024,
            response_bytes=4_096,
        )
        target = _LoadTarget()

        evidence = await run_reliability_load(plan, target)

        assert evidence.completed == 8
        assert evidence.successful == 7
        assert evidence.outcome_count(ReliabilityOutcome.OVERLOADED) == 1
        assert evidence.peak_client_concurrency == 3
        assert target.peak == 3
        assert {request.tenant for request in target.requests} == {
            "reliability-tenant-0",
            "reliability-tenant-1",
        }
        assert all(request.request_bytes == 1_024 for request in target.requests)
        assert all(request.response_bytes == 4_096 for request in target.requests)
        assert evidence.latency.p99_milliseconds >= 0
        assert evidence.throughput_requests_per_second > 0
        rendered = evidence.model_dump_json()
        assert "reliability-tenant" not in rendered
        assert "payload" not in rendered

    asyncio.run(exercise())


def test_load_runner_rejects_evidence_from_a_different_transport_lane() -> None:
    target = _LoadTarget()
    target.lane = ReliabilityLane.DIRECT_HTTP
    plan = ReliabilityLoadPlan(
        name="mislabeled-load",
        lane=ReliabilityLane.IN_PROCESS,
        requests=1,
        concurrency=1,
        tenants=1,
        request_bytes=0,
        response_bytes=0,
    )

    with pytest.raises(ValueError, match="lane"):
        asyncio.run(run_reliability_load(plan, target))


def test_external_runner_cancellation_propagates_without_a_partial_report() -> None:
    plan = ReliabilityLoadPlan(
        name="cancelled-load",
        lane=ReliabilityLane.IN_PROCESS,
        requests=4,
        concurrency=2,
        tenants=1,
        request_bytes=0,
        response_bytes=0,
    )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run_reliability_load(plan, _CancellingTarget()))


def test_soak_runner_samples_every_bounded_resource_without_retaining_payloads() -> None:
    def snapshot(rss: float, active: int) -> ReliabilityResourceSnapshot:
        return ReliabilityResourceSnapshot(
            rss_mebibytes=rss,
            tasks=active,
            connections=active,
            sessions=active,
            telemetry_buffer=active,
            credential_cache=active,
        )

    budgets = tuple(
        ReliabilityResourceBudget(
            resource=resource,
            maximum=(128 if resource is ReliabilityResource.RSS_MEBIBYTES else 32),
            permitted_growth=(4 if resource is ReliabilityResource.RSS_MEBIBYTES else 0),
        )
        for resource in ReliabilityResource
    )
    plan = ReliabilitySoakPlan(
        load=ReliabilityLoadPlan(
            name="soak-cycle",
            lane=ReliabilityLane.IN_PROCESS,
            requests=4,
            concurrency=2,
            tenants=2,
            request_bytes=64,
            response_bytes=128,
        ),
        cycles=3,
        budgets=budgets,
    )
    probe = _ScriptedResourceProbe(
        (
            snapshot(80, 0),
            snapshot(84, 2),
            snapshot(83, 1),
            snapshot(82, 0),
        )
    )

    result = asyncio.run(run_reliability_soak(plan, _LoadTarget(), probe))

    assert result.completed_calls == 12
    assert len(result.loads) == 3
    assert len(result.resources) == len(ReliabilityResource)
    rss = next(
        item for item in result.resources if item.resource is ReliabilityResource.RSS_MEBIBYTES
    )
    assert rss.baseline == 80
    assert rss.peak == 84
    assert rss.final == 82
    assert rss.growth == 2
    assert all(item.final == 0 for item in result.resources if item is not rss)
    assert "payload" not in result.model_dump_json()


def test_dependency_runner_measures_fault_and_unaffected_counter_deltas() -> None:
    target = _DependencyTarget()
    plan = ReliabilityDependencyPlan(
        dependency=ReliabilityDependency.BACKING_API,
        lane=ReliabilityLane.IN_PROCESS,
        affected_calls=3,
        unaffected_calls=2,
        request_bytes=1_024,
        response_bytes=4_096,
    )

    evidence = asyncio.run(run_reliability_dependency_failure(plan, target))

    assert evidence == ReliabilityDependencyEvidence(
        dependency=ReliabilityDependency.BACKING_API,
        affected_calls=3,
        affected_outcome=ReliabilityOutcome.UNAVAILABLE,
        unaffected_successes=2,
        maximum_queue_depth=2,
        runtime_retries=3,
        circuit_open_count=1,
        telemetry_drop_count=0,
        stale_cache_successes=0,
        fail_closed_count=0,
    )
    assert len(target.affected_requests) == 3
    assert len(target.unaffected_requests) == 2
    assert {request.tenant for request in target.affected_requests} == {
        "reliability-tenant-affected"
    }
    assert {request.tenant for request in target.unaffected_requests} == {
        "reliability-tenant-unaffected"
    }
    assert "tenant" not in evidence.model_dump_json()


def test_retry_runner_measures_one_effect_and_retry_ownership_across_duplicates() -> None:
    target = _RetryTarget()
    plan = ReliabilityRetryPlan(
        lane=ReliabilityLane.IN_PROCESS,
        owning_layer=ReliabilityRetryLayer.RUNTIME,
        maximum_attempts=3,
        calls=10,
    )

    evidence = asyncio.run(run_reliability_retry_scenario(plan, target))

    assert evidence == ReliabilityRetryEvidence(
        owning_layer=ReliabilityRetryLayer.RUNTIME,
        maximum_attempts=3,
        calls=10,
        effects=1,
        retries=tuple(
            ReliabilityRetryCount(
                layer=layer,
                count=(2 if layer is ReliabilityRetryLayer.RUNTIME else 0),
            )
            for layer in ReliabilityRetryLayer
        ),
    )
    assert set(target.deliveries) == set(range(10))


def test_rollout_runner_measures_drain_interruption_and_capacity_restoration() -> None:
    target = _RolloutTarget()
    plan = ReliabilityRolloutPlan(
        scenario=ReliabilityRolloutScenario.SIGTERM,
        accepted_calls=8,
        new_calls=2,
    )

    evidence = asyncio.run(run_reliability_rollout_scenario(plan, target))

    assert evidence == ReliabilityRolloutEvidence(
        scenario=ReliabilityRolloutScenario.SIGTERM,
        accepted_calls=8,
        completed_calls=8,
        rejected_new_calls=2,
        interruption_seconds=2,
        drain_seconds=4,
        previous_capacity_preserved=True,
        rollback_restored=True,
    )


def test_stateless_runner_switches_replicas_without_local_state_or_duplicate_effects() -> None:
    target = _StatelessTarget()
    plan = ReliabilityStatelessPlan(deliveries=6, replicas=2)

    evidence = asyncio.run(run_reliability_stateless_scenario(plan, target))

    assert evidence == ReliabilityStatelessEvidence(
        deliveries=6,
        replicas=2,
        successful_calls=6,
        replica_switches=5,
        external_effects=1,
        request_memory_entries=0,
        request_filesystem_entries=0,
        session_affinity_required=False,
    )
    assert [replica for replica, _ in target.calls] == [0, 1, 0, 1, 0, 1]
    requests = [request for _, request in target.calls]
    assert len({request.request_id for request in requests}) == 6
    assert {request.idempotency_key for request in requests} == {"reliability-idempotency-shared"}
    assert all(request.workload_identity == "reliability-workload-0" for request in requests)
    assert all(request.tenant == "reliability-tenant-0" for request in requests)
    assert all(request.tool_name == "reliability_tool" for request in requests)
    assert all(request.capability_ref == "cap/reliability" for request in requests)
    assert all(request.tool_version == "1.0.0" for request in requests)
    assert all(request.schema_fingerprint == _digest("a") for request in requests)
    assert all(request.arguments == (("value", "synthetic"),) for request in requests)
    assert all(request.authorization_token == "reliability-token-synthetic" for request in requests)
    assert all(request.authorization_scopes == ("reliability:invoke",) for request in requests)
    assert all(request.approval_reference == "reliability-approval-shared" for request in requests)
    assert all(request.correlation_id == "reliability-correlation-shared" for request in requests)
    assert all(request.trace_id == "1" * 32 for request in requests)
    assert all(request.run_id == "reliability-run-shared" for request in requests)
    assert all(request.workflow_reference == "reliability-workflow-shared" for request in requests)
    assert all(request.resource_reference == "reliability-resource-shared" for request in requests)
    assert all(request.timeout_milliseconds == 5_000 for request in requests)
    assert all(request.retry_owner is ReliabilityRetryLayer.RUNTIME for request in requests)
    assert all(request.maximum_attempts == 3 for request in requests)
    assert all(request.idempotency_request_digest == _digest("b") for request in requests)
    assert all(
        request.conversation_reference == "reliability-conversation-shared" for request in requests
    )
    rendered = evidence.model_dump_json()
    assert "token" not in rendered
    assert "tenant" not in rendered
    assert "conversation" not in rendered


def test_fairness_runner_saturates_one_tenant_without_starving_reserved_calls() -> None:
    plan = ReliabilityFairnessPlan(
        lane=ReliabilityLane.IN_PROCESS,
        global_limit=64,
        tool_limit=32,
        tenant_limit=16,
        noisy_started=32,
        reserved_started=8,
    )
    target = _FairnessTarget(noisy_started=plan.noisy_started)

    evidence = asyncio.run(run_reliability_fairness_scenario(plan, target))

    assert evidence == ReliabilityFairnessEvidence(
        global_limit=64,
        tool_limit=32,
        tenant_limit=16,
        noisy_started=32,
        noisy_admitted=16,
        noisy_overloaded=16,
        reserved_started=8,
        reserved_successful=8,
    )


def test_complete_reliability_report_satisfies_every_blocking_gate() -> None:
    report = _complete_report()

    decision = assess_reliability_report(
        report,
        profile=standard_reliability_profile(),
        binding=report.binding,
    )

    assert decision.approved is True
    assert decision.reasons == ()
    assert report.statelessness.session_affinity_required is False
    assert decision.evidence_digest.startswith("sha256:")
    rendered = report.to_json()
    markdown = report.to_markdown()
    assert "reliability-tenant" not in rendered
    assert "payload" not in rendered
    assert "approved: true" in markdown
    assert "correlated gateway windows: 3" in markdown


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("global_limit", 63, "global_limit_mismatch"),
        ("tool_limit", 31, "tool_limit_mismatch"),
        ("tenant_limit", 17, "tenant_limit_mismatch"),
    ),
)
def test_assessment_rejects_each_concurrency_limit_mismatch(
    field: str,
    value: int,
    reason: str,
) -> None:
    report = _complete_report()
    mutant = report.model_copy(
        update={"fairness": report.fairness.model_copy(update={field: value})}
    )

    decision = assess_reliability_report(
        mutant,
        profile=standard_reliability_profile(),
        binding=mutant.binding,
    )

    assert decision.approved is False
    assert decision.reasons == (reason,)


def test_assessment_rejects_a_missing_agentgateway_correlation_window() -> None:
    report = _complete_report()
    mutant = report.model_copy(
        update={
            "correlations": tuple(
                item
                for item in report.correlations
                if item.kind is not ReliabilityLoadKind.SUSTAINED
            )
        }
    )

    decision = assess_reliability_report(
        mutant,
        profile=standard_reliability_profile(),
        binding=mutant.binding,
    )

    assert decision.approved is False
    assert decision.reasons == ("correlation_missing:sustained",)


@pytest.mark.parametrize(
    ("updates", "reason"),
    (
        (
            {
                "requests": 99,
                "client_samples": 99,
                "gateway_metric_samples": 99,
                "runtime_span_samples": 99,
                "runtime_metric_samples": 99,
            },
            "correlation_request_count:sustained",
        ),
        (
            {"client_p99_milliseconds": 24.0},
            "correlation_client_p99:sustained",
        ),
    ),
)
def test_assessment_rejects_correlation_not_bound_to_the_client_load(
    updates: dict[str, object],
    reason: str,
) -> None:
    report = _mutate_correlation(
        _complete_report(),
        ReliabilityLoadKind.SUSTAINED,
        **updates,
    )

    decision = assess_reliability_report(
        report,
        profile=standard_reliability_profile(),
        binding=report.binding,
    )

    assert decision.approved is False
    assert decision.reasons == (reason,)


@pytest.mark.parametrize(
    ("updates", "reason"),
    (
        ({"replicas": 1}, "stateless_replica_floor"),
        ({"successful_calls": 7}, "stateless_call_failed"),
        ({"replica_switches": 6}, "stateless_replica_affinity"),
        ({"external_effects": 2}, "stateless_duplicate_effect"),
        ({"request_memory_entries": 1}, "stateless_request_memory"),
        ({"request_filesystem_entries": 1}, "stateless_request_filesystem"),
        ({"session_affinity_required": True}, "stateless_session_affinity"),
    ),
)
def test_assessment_rejects_each_stateless_runtime_violation(
    updates: dict[str, object],
    reason: str,
) -> None:
    report = _mutate_statelessness(_complete_report(), **updates)

    decision = assess_reliability_report(
        report,
        profile=standard_reliability_profile(),
        binding=report.binding,
    )

    assert decision.approved is False
    assert reason in decision.reasons


@pytest.mark.parametrize(
    ("mutate", "reason"),
    (
        _reliability_mutant(
            lambda report: report.model_copy(update={"complete": False}),
            "report_incomplete",
            case_id="incomplete-report",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(update={"startup_seconds": 2.1}),
            "startup_target_missed",
            case_id="startup",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(update={"idle_rss_mebibytes": 129}),
            "idle_rss_target_missed",
            case_id="idle-rss",
        ),
        _reliability_mutant(
            lambda report: _mutate_load(
                report,
                ReliabilityLane.DIRECT_HTTP,
                ReliabilityLoadKind.SUSTAINED,
                throughput_requests_per_second=49,
            ),
            "sustained_throughput:direct_http",
            case_id="sustained-throughput",
        ),
        _reliability_mutant(
            lambda report: _mutate_load(
                report,
                ReliabilityLane.AGENTGATEWAY,
                ReliabilityLoadKind.BURST,
                throughput_requests_per_second=199,
            ),
            "burst_throughput:agentgateway",
            case_id="burst-throughput",
        ),
        _reliability_mutant(
            lambda report: _mutate_load(
                report,
                ReliabilityLane.IN_PROCESS,
                ReliabilityLoadKind.SUSTAINED,
                latency=ReliabilityLatency(
                    p50_milliseconds=8,
                    p95_milliseconds=15,
                    p99_milliseconds=16,
                    maximum_milliseconds=16,
                ),
            ),
            "runtime_p99:sustained",
            case_id="runtime-p99",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={
                    "loads": tuple(
                        item
                        for item in report.loads
                        if (item.lane, item.kind)
                        != (ReliabilityLane.DIRECT_HTTP, ReliabilityLoadKind.BOUNDARY)
                    )
                }
            ),
            "load_missing:direct_http:boundary",
            case_id="missing-lane-load",
        ),
        _reliability_mutant(
            lambda report: _mutate_load(
                report,
                ReliabilityLane.DIRECT_HTTP,
                ReliabilityLoadKind.SUSTAINED,
                successful=199,
            ),
            "load_errors:direct_http:sustained",
            case_id="load-errors",
        ),
        _reliability_mutant(
            lambda report: _mutate_load(
                report,
                ReliabilityLane.DIRECT_HTTP,
                ReliabilityLoadKind.SUSTAINED,
                maximum_queue_depth=1,
            ),
            "queue_depth:direct_http:sustained",
            case_id="load-queue",
        ),
        _reliability_mutant(
            lambda report: _mutate_load(
                report,
                ReliabilityLane.DIRECT_HTTP,
                ReliabilityLoadKind.BOUNDARY,
                request_bytes=65_535,
            ),
            "payload_boundary:direct_http",
            case_id="request-boundary",
        ),
        _reliability_mutant(
            lambda report: _mutate_load(
                report,
                ReliabilityLane.DIRECT_HTTP,
                ReliabilityLoadKind.BOUNDARY,
                response_bytes=524_287,
            ),
            "payload_boundary:direct_http",
            case_id="response-boundary",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={
                    "resources": tuple(
                        item
                        for item in report.resources
                        if item.resource is not ReliabilityResource.CONNECTIONS
                    )
                }
            ),
            "resource_missing:connections",
            case_id="missing-resource",
        ),
        _reliability_mutant(
            lambda report: _mutate_resource(
                report,
                ReliabilityResource.SESSIONS,
                final=1,
            ),
            "resource_growth:sessions",
            case_id="resource-growth",
        ),
        _reliability_mutant(
            lambda report: _mutate_resource(
                report,
                ReliabilityResource.TELEMETRY_BUFFER,
                final=1,
            ),
            "resource_growth:telemetry_buffer",
            case_id="telemetry-buffer-growth",
        ),
        _reliability_mutant(
            lambda report: _mutate_resource(
                report,
                ReliabilityResource.TASKS,
                peak=257,
            ),
            "resource_peak:tasks",
            case_id="resource-peak",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={
                    "fairness": report.fairness.model_copy(
                        update={"noisy_admitted": 17, "noisy_overloaded": 15}
                    )
                }
            ),
            "noisy_tenant_exceeded_limit",
            case_id="noisy-tenant",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={"fairness": report.fairness.model_copy(update={"reserved_successful": 7})}
            ),
            "reserved_tenant_starved",
            case_id="tenant-starvation",
        ),
        _reliability_mutant(
            _move_retry_owner,
            "retry_owner",
            case_id="retry-owner",
        ),
        _reliability_mutant(
            lambda report: _mutate_retry_count(report, ReliabilityRetryLayer.AGENTGATEWAY, 1),
            "retry_amplification:agentgateway",
            case_id="retry-amplification",
        ),
        _reliability_mutant(
            lambda report: _mutate_retry_count(report, ReliabilityRetryLayer.RUNTIME, 21),
            "runtime_retry_cap",
            case_id="retry-cap",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={"retry": report.retry.model_copy(update={"effects": 2})}
            ),
            "duplicate_effect",
            case_id="duplicate-write",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={
                    "dependencies": tuple(
                        item
                        for item in report.dependencies
                        if item.dependency is not ReliabilityDependency.AGENTGATEWAY
                    )
                }
            ),
            "dependency_missing:agentgateway",
            case_id="missing-dependency",
        ),
        _reliability_mutant(
            lambda report: _mutate_dependency(
                report,
                ReliabilityDependency.REGISTRY,
                maximum_queue_depth=1,
            ),
            "dependency_queue:registry",
            case_id="dependency-queue",
        ),
        _reliability_mutant(
            lambda report: _mutate_dependency(
                report,
                ReliabilityDependency.REGISTRY,
                unaffected_successes=0,
            ),
            "dependency_blast_radius:registry",
            case_id="dependency-blast-radius",
        ),
        _reliability_mutant(
            lambda report: _mutate_dependency(
                report,
                ReliabilityDependency.REGISTRY,
                affected_outcome=ReliabilityOutcome.UNAVAILABLE,
            ),
            "dependency_degraded:registry",
            case_id="registry-degradation",
        ),
        _reliability_mutant(
            lambda report: _mutate_dependency(
                report,
                ReliabilityDependency.AGENTGATEWAY,
                affected_outcome=ReliabilityOutcome.SUCCESS,
            ),
            "dependency_outcome:agentgateway",
            case_id="gateway-outage",
        ),
        _reliability_mutant(
            lambda report: _mutate_dependency(
                report,
                ReliabilityDependency.TELEMETRY,
                telemetry_drop_count=0,
            ),
            "telemetry_drop_unmeasured",
            case_id="telemetry-drops",
        ),
        _reliability_mutant(
            lambda report: _mutate_dependency(
                report,
                ReliabilityDependency.IDENTITY,
                stale_cache_successes=0,
            ),
            "identity_cache_policy",
            case_id="identity-stale-window",
        ),
        _reliability_mutant(
            lambda report: _mutate_dependency(
                report,
                ReliabilityDependency.IDENTITY,
                fail_closed_count=0,
            ),
            "identity_cache_policy",
            case_id="identity-fail-closed",
        ),
        _reliability_mutant(
            lambda report: _mutate_dependency(
                report,
                ReliabilityDependency.IDENTITY,
                affected_outcome=ReliabilityOutcome.SUCCESS,
            ),
            "identity_cache_policy",
            case_id="identity-outcome",
        ),
        _reliability_mutant(
            lambda report: _mutate_dependency(
                report,
                ReliabilityDependency.DNS,
                circuit_open_count=0,
            ),
            "circuit_not_opened:dns",
            case_id="circuit-opening",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={
                    "rollouts": tuple(
                        item
                        for item in report.rollouts
                        if item.scenario is not ReliabilityRolloutScenario.CANARY_ABORT
                    )
                }
            ),
            "rollout_missing:canary_abort",
            case_id="missing-rollout",
        ),
        _reliability_mutant(
            lambda report: _mutate_rollout(
                report,
                ReliabilityRolloutScenario.SIGTERM,
                completed_calls=7,
            ),
            "drain_incomplete:sigterm",
            case_id="drain-incomplete",
        ),
        _reliability_mutant(
            lambda report: _mutate_rollout(
                report,
                ReliabilityRolloutScenario.SIGTERM,
                rejected_new_calls=0,
            ),
            "drain_admission_open:sigterm",
            case_id="drain-admission",
        ),
        _reliability_mutant(
            lambda report: _mutate_rollout(
                report,
                ReliabilityRolloutScenario.ROLLBACK,
                interruption_seconds=6,
            ),
            "interruption_target:rollback",
            case_id="rollout-interruption",
        ),
        _reliability_mutant(
            lambda report: _mutate_rollout(
                report,
                ReliabilityRolloutScenario.SIGTERM,
                drain_seconds=46,
            ),
            "drain_target:sigterm",
            case_id="drain-deadline",
        ),
        _reliability_mutant(
            lambda report: _mutate_rollout(
                report,
                ReliabilityRolloutScenario.ROLLING_UPDATE,
                previous_capacity_preserved=False,
            ),
            "previous_capacity_lost:rolling_update",
            case_id="previous-capacity",
        ),
        _reliability_mutant(
            lambda report: _mutate_rollout(
                report,
                ReliabilityRolloutScenario.ROLLBACK,
                rollback_restored=False,
            ),
            "rollback_failed:rollback",
            case_id="rollback",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={
                    "capacity": report.capacity.model_copy(
                        update={"observed_sustained_requests_per_second": 49}
                    )
                }
            ),
            "capacity_sustained",
            case_id="capacity-sustained",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={
                    "capacity": report.capacity.model_copy(
                        update={"observed_burst_requests_per_second": 199}
                    )
                }
            ),
            "capacity_burst",
            case_id="capacity-burst",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={"capacity": report.capacity.model_copy(update={"minimum_replicas": 1})}
            ),
            "capacity_replica_floor",
            case_id="capacity-replicas",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={
                    "capacity": report.capacity.model_copy(update={"termination_grace_seconds": 44})
                }
            ),
            "capacity_termination_grace",
            case_id="capacity-termination",
        ),
        _reliability_mutant(
            lambda report: report.model_copy(
                update={"capacity": report.capacity.model_copy(update={"scaling_target": 0.4})}
            ),
            "capacity_scaling_target",
            case_id="capacity-scaling",
        ),
    ),
)
def test_assessment_rejects_each_blocking_evidence_mutant(
    mutate: Callable[[ReliabilityReport], ReliabilityReport],
    reason: str,
) -> None:
    report = _complete_report()
    mutant = mutate(report)

    decision = assess_reliability_report(
        mutant,
        profile=standard_reliability_profile(),
        binding=mutant.binding,
    )

    assert decision.approved is False
    assert decision.reasons == (reason,)


def test_changed_reliability_profile_invalidates_stale_evidence() -> None:
    report = _complete_report()
    changed = standard_reliability_profile().model_copy(
        update={"sustained_requests_per_second": 60}
    )

    decision = assess_reliability_report(report, profile=changed, binding=report.binding)

    assert decision.approved is False
    assert "profile_digest_mismatch" in decision.reasons


def test_changed_artifact_binding_invalidates_reliability_evidence() -> None:
    report = _complete_report()
    expected = report.binding
    tampered = report.model_copy(
        update={"binding": report.binding.model_copy(update={"image_digest": _digest("e")})}
    )

    decision = assess_reliability_report(
        tampered,
        profile=standard_reliability_profile(),
        binding=expected,
    )

    assert decision.approved is False
    assert "binding_mismatch" in decision.reasons
