from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import pairwise
from typing import Any, Protocol, Self, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


class ReliabilityLane(StrEnum):
    IN_PROCESS = "in_process"
    DIRECT_HTTP = "direct_http"
    AGENTGATEWAY = "agentgateway"


class ReliabilityLoadKind(StrEnum):
    SUSTAINED = "sustained"
    BURST = "burst"
    BOUNDARY = "boundary"


class ReliabilityOutcome(StrEnum):
    SUCCESS = "success"
    OVERLOADED = "overloaded"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    AUTHENTICATION_DENIED = "authentication_denied"


class ReliabilityResource(StrEnum):
    RSS_MEBIBYTES = "rss_mebibytes"
    TASKS = "tasks"
    CONNECTIONS = "connections"
    SESSIONS = "sessions"
    TELEMETRY_BUFFER = "telemetry_buffer"
    CREDENTIAL_CACHE = "credential_cache"


class ReliabilityDependency(StrEnum):
    REGISTRY = "registry"
    AGENTGATEWAY = "agentgateway"
    IDENTITY = "identity"
    TELEMETRY = "telemetry"
    DNS = "dns"
    BACKING_API = "backing_api"


class ReliabilityRetryLayer(StrEnum):
    CLIENT = "client"
    AGENTGATEWAY = "agentgateway"
    MESH = "mesh"
    RUNTIME = "runtime"


class ReliabilityRolloutScenario(StrEnum):
    SIGTERM = "sigterm"
    POD_EVICTION = "pod_eviction"
    ROLLING_UPDATE = "rolling_update"
    CANARY_ABORT = "canary_abort"
    ROLLBACK = "rollback"


@dataclass(frozen=True, slots=True)
class ReliabilityRequest:
    sequence: int
    lane: ReliabilityLane
    tenant: str
    request_bytes: int
    response_bytes: int

    def __post_init__(self) -> None:
        if not 0 <= self.sequence < 100_000:
            raise ValueError("sequence is outside the reliability profile")
        if not _is_runtime_instance(self.lane, ReliabilityLane):
            raise ValueError("lane must use the stable reliability vocabulary")
        if not self.tenant.startswith("reliability-tenant-") or len(self.tenant) > 64:
            raise ValueError("tenant must be a synthetic reliability identity")
        if not 0 <= self.request_bytes <= 65_536:
            raise ValueError("request bytes exceed the runtime envelope")
        if not 0 <= self.response_bytes <= 524_288:
            raise ValueError("response bytes exceed the runtime envelope")


@dataclass(frozen=True, slots=True)
class ReliabilityStatelessRequest:
    sequence: int
    workload_identity: str
    tenant: str
    tool_name: str
    capability_ref: str
    tool_version: str
    schema_fingerprint: str
    arguments: tuple[tuple[str, str], ...]
    authorization_token: str = field(repr=False)
    authorization_scopes: tuple[str, ...]
    approval_reference: str | None
    request_id: str
    correlation_id: str
    trace_id: str
    run_id: str
    conversation_reference: str | None
    workflow_reference: str | None
    resource_reference: str | None
    timeout_milliseconds: int
    retry_owner: ReliabilityRetryLayer
    maximum_attempts: int
    idempotency_key: str
    idempotency_request_digest: str

    def __post_init__(self) -> None:
        if not 0 <= self.sequence < 100_000:
            raise ValueError("sequence is outside the reliability profile")
        if not self.workload_identity.startswith("reliability-workload-"):
            raise ValueError("workload identity must be synthetic")
        if not self.tenant.startswith("reliability-tenant-"):
            raise ValueError("tenant must be synthetic")
        if self.tool_name != "reliability_tool":
            raise ValueError("tool name must use the synthetic reliability tool")
        if self.capability_ref != "cap/reliability" or self.tool_version != "1.0.0":
            raise ValueError("capability and tool version must use synthetic immutable pins")
        if self.schema_fingerprint != "sha256:" + "a" * 64:
            raise ValueError("schema fingerprint must use the synthetic immutable pin")
        if (
            not 1 <= len(self.arguments) <= 32
            or len({name for name, _ in self.arguments}) != len(self.arguments)
            or any(
                not name or len(name) > 64 or len(value) > 1_024 for name, value in self.arguments
            )
        ):
            raise ValueError("arguments must be bounded synthetic values")
        if not self.authorization_token.startswith("reliability-token-"):
            raise ValueError("authorization token must be synthetic")
        if self.authorization_scopes != ("reliability:invoke",):
            raise ValueError("authorization scopes must use the synthetic policy context")
        if self.approval_reference != "reliability-approval-shared":
            raise ValueError("approval reference must use the shared synthetic approval")
        if not self.request_id.startswith("reliability-request-"):
            raise ValueError("request id must be synthetic")
        if self.correlation_id != "reliability-correlation-shared":
            raise ValueError("correlation id must use the shared synthetic operation")
        if self.trace_id != "1" * 32:
            raise ValueError("trace id must use the synthetic W3C trace")
        if self.run_id != "reliability-run-shared":
            raise ValueError("run id must use the shared synthetic run")
        if self.conversation_reference is not None and not self.conversation_reference.startswith(
            "reliability-conversation-"
        ):
            raise ValueError("conversation reference must be synthetic")
        if self.workflow_reference != "reliability-workflow-shared":
            raise ValueError("workflow reference must use the shared synthetic workflow")
        if self.resource_reference != "reliability-resource-shared":
            raise ValueError("resource reference must use the shared synthetic resource")
        if not 1 <= self.timeout_milliseconds <= 300_000:
            raise ValueError("timeout must be finite and bounded")
        if self.retry_owner is not ReliabilityRetryLayer.RUNTIME or self.maximum_attempts != 3:
            raise ValueError("retry policy must have one bounded synthetic owner")
        if self.idempotency_key != "reliability-idempotency-shared":
            raise ValueError("idempotency key must use the shared reliability key")
        if self.idempotency_request_digest != "sha256:" + "b" * 64:
            raise ValueError("idempotency request digest must bind the logical mutation")


@dataclass(frozen=True, slots=True)
class ReliabilityTargetResult:
    outcome: ReliabilityOutcome
    response_bytes: int = 0
    queue_depth: int = 0

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.outcome, ReliabilityOutcome):
            raise ValueError("outcome must use the stable reliability vocabulary")
        if not 0 <= self.response_bytes <= 524_288:
            raise ValueError("response bytes exceed the runtime envelope")
        if not 0 <= self.queue_depth <= 10_000:
            raise ValueError("queue depth must be bounded")
        if self.outcome is not ReliabilityOutcome.SUCCESS and self.response_bytes != 0:
            raise ValueError("failed reliability calls cannot retain response bytes")


@runtime_checkable
class ReliabilityTarget(Protocol):
    lane: ReliabilityLane

    async def invoke(self, request: ReliabilityRequest) -> ReliabilityTargetResult: ...


@runtime_checkable
class ReliabilityResourceProbe(Protocol):
    async def snapshot(self) -> ReliabilityResourceSnapshot: ...


class _ReliabilityModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class ReliabilityDependencyPlan(_ReliabilityModel):
    dependency: ReliabilityDependency
    lane: ReliabilityLane
    affected_calls: int = Field(ge=1, le=100_000)
    unaffected_calls: int = Field(ge=1, le=100_000)
    request_bytes: int = Field(ge=0, le=65_536)
    response_bytes: int = Field(ge=0, le=524_288)

    @model_validator(mode="after")
    def bounded_calls(self) -> Self:
        if self.affected_calls + self.unaffected_calls > 100_000:
            raise ValueError("dependency plan exceeds the bounded invocation count")
        return self


class ReliabilityDependencySnapshot(_ReliabilityModel):
    runtime_retries: int = Field(ge=0, le=1_000_000)
    circuit_open_count: int = Field(ge=0, le=1_000_000)
    telemetry_drop_count: int = Field(ge=0, le=1_000_000)
    stale_cache_successes: int = Field(ge=0, le=100_000)
    fail_closed_count: int = Field(ge=0, le=100_000)


@runtime_checkable
class ReliabilityDependencyTarget(Protocol):
    lane: ReliabilityLane
    dependency: ReliabilityDependency

    async def snapshot(self) -> ReliabilityDependencySnapshot: ...

    async def invoke_affected(
        self,
        request: ReliabilityRequest,
    ) -> ReliabilityTargetResult: ...

    async def invoke_unaffected(
        self,
        request: ReliabilityRequest,
    ) -> ReliabilityTargetResult: ...


class ReliabilityStatelessPlan(_ReliabilityModel):
    deliveries: int = Field(ge=2, le=100_000)
    replicas: int = Field(ge=2, le=100)

    @model_validator(mode="after")
    def every_replica_receives_a_delivery(self) -> Self:
        if self.deliveries < self.replicas:
            raise ValueError("stateless plan must exercise every replica")
        return self


class ReliabilityStatelessSnapshot(_ReliabilityModel):
    external_effects: int = Field(ge=0, le=100_000)
    request_memory_entries: tuple[int, ...] = Field(min_length=2, max_length=100)
    request_filesystem_entries: tuple[int, ...] = Field(min_length=2, max_length=100)
    session_affinity_required: bool

    @model_validator(mode="after")
    def replica_snapshots_align(self) -> Self:
        if len(self.request_memory_entries) != len(self.request_filesystem_entries):
            raise ValueError("stateless replica snapshots must align")
        if any(value < 0 for value in self.request_memory_entries):
            raise ValueError("request memory entries cannot be negative")
        if any(value < 0 for value in self.request_filesystem_entries):
            raise ValueError("request filesystem entries cannot be negative")
        return self


@runtime_checkable
class ReliabilityStatelessTarget(Protocol):
    replica_count: int

    async def snapshot(self) -> ReliabilityStatelessSnapshot: ...

    async def invoke(
        self,
        replica: int,
        request: ReliabilityStatelessRequest,
    ) -> ReliabilityTargetResult: ...


class ReliabilityLoadPlan(_ReliabilityModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9-]*$")
    lane: ReliabilityLane
    kind: ReliabilityLoadKind = ReliabilityLoadKind.SUSTAINED
    requests: int = Field(ge=1, le=100_000)
    concurrency: int = Field(ge=1, le=256)
    tenants: int = Field(ge=1, le=256)
    request_bytes: int = Field(ge=0, le=65_536)
    response_bytes: int = Field(ge=0, le=524_288)

    @model_validator(mode="after")
    def bounded_work(self) -> Self:
        if self.concurrency > self.requests:
            raise ValueError("concurrency cannot exceed requests")
        if self.tenants > self.requests:
            raise ValueError("tenants cannot exceed requests")
        return self


class ReliabilityResourceSnapshot(_ReliabilityModel):
    rss_mebibytes: float = Field(ge=0, le=4_096)
    tasks: int = Field(ge=0, le=1_000_000)
    connections: int = Field(ge=0, le=1_000_000)
    sessions: int = Field(ge=0, le=1_000_000)
    telemetry_buffer: int = Field(ge=0, le=1_000_000)
    credential_cache: int = Field(ge=0, le=1_000_000)


class ReliabilityResourceBudget(_ReliabilityModel):
    resource: ReliabilityResource
    maximum: float = Field(gt=0, le=1_000_000)
    permitted_growth: float = Field(ge=0, le=1_000_000)

    @model_validator(mode="after")
    def growth_fits_within_maximum(self) -> Self:
        if self.permitted_growth > self.maximum:
            raise ValueError("permitted resource growth cannot exceed its maximum")
        return self


class ReliabilitySoakPlan(_ReliabilityModel):
    load: ReliabilityLoadPlan
    cycles: int = Field(ge=1, le=100_000)
    budgets: tuple[ReliabilityResourceBudget, ...] = Field(
        min_length=len(ReliabilityResource),
        max_length=len(ReliabilityResource),
    )

    @model_validator(mode="after")
    def covers_bounded_resources(self) -> Self:
        resources = {budget.resource for budget in self.budgets}
        if resources != set(ReliabilityResource):
            raise ValueError("soak budgets must cover every bounded resource once")
        if self.cycles * self.load.requests > 100_000:
            raise ValueError("soak plan exceeds the bounded invocation count")
        return self


class ReliabilityLatency(_ReliabilityModel):
    p50_milliseconds: float = Field(ge=0, le=300_000)
    p95_milliseconds: float = Field(ge=0, le=300_000)
    p99_milliseconds: float = Field(ge=0, le=300_000)
    maximum_milliseconds: float = Field(ge=0, le=300_000)

    @model_validator(mode="after")
    def ordered_percentiles(self) -> Self:
        if not (
            self.p50_milliseconds
            <= self.p95_milliseconds
            <= self.p99_milliseconds
            <= self.maximum_milliseconds
        ):
            raise ValueError("latency percentiles must be ordered")
        return self


class ReliabilityOutcomeCount(_ReliabilityModel):
    outcome: ReliabilityOutcome
    count: int = Field(ge=1, le=100_000)


class ReliabilityLoadEvidence(_ReliabilityModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9-]*$")
    lane: ReliabilityLane
    kind: ReliabilityLoadKind = ReliabilityLoadKind.SUSTAINED
    request_bytes: int = Field(ge=0, le=65_536)
    response_bytes: int = Field(ge=0, le=524_288)
    completed: int = Field(ge=1, le=100_000)
    successful: int = Field(ge=0, le=100_000)
    outcomes: tuple[ReliabilityOutcomeCount, ...]
    duration_seconds: float = Field(gt=0, le=86_400)
    throughput_requests_per_second: float = Field(gt=0, le=1_000_000)
    latency: ReliabilityLatency
    peak_client_concurrency: int = Field(ge=1, le=256)
    maximum_queue_depth: int = Field(ge=0, le=10_000)
    sample_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def consistent_counts(self) -> Self:
        if len({item.outcome for item in self.outcomes}) != len(self.outcomes):
            raise ValueError("outcome counts must be unique")
        if sum(item.count for item in self.outcomes) != self.completed:
            raise ValueError("outcome counts must cover every completed request")
        if self.outcome_count(ReliabilityOutcome.SUCCESS) != self.successful:
            raise ValueError("successful count must match success outcomes")
        return self

    def outcome_count(self, outcome: ReliabilityOutcome) -> int:
        return next((item.count for item in self.outcomes if item.outcome is outcome), 0)


class ReliabilityCorrelationEvidence(_ReliabilityModel):
    lane: ReliabilityLane
    kind: ReliabilityLoadKind
    window_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    requests: int = Field(ge=1, le=100_000)
    client_samples: int = Field(ge=1, le=100_000)
    gateway_tool_calls: int = Field(ge=1, le=100_000)
    gateway_metric_samples: int = Field(ge=1, le=100_000)
    runtime_span_samples: int = Field(ge=1, le=100_000)
    runtime_metric_samples: int = Field(ge=1, le=100_000)
    pod_resource_samples: int = Field(ge=2, le=100_000)
    client_p99_milliseconds: float = Field(gt=0, le=300_000)
    gateway_p99_milliseconds: float = Field(gt=0, le=300_000)
    runtime_span_p99_milliseconds: float = Field(gt=0, le=300_000)
    runtime_metric_p99_milliseconds: float = Field(gt=0, le=300_000)
    pod_cpu_millicores_peak: float = Field(ge=0, le=1_000_000)
    pod_rss_mebibytes_peak: float = Field(gt=0, le=4_096)

    @model_validator(mode="after")
    def sources_cover_the_agentgateway_window(self) -> Self:
        source_samples = (
            self.client_samples,
            self.gateway_tool_calls,
            self.runtime_span_samples,
            self.runtime_metric_samples,
        )
        if (
            self.lane is not ReliabilityLane.AGENTGATEWAY
            or any(samples != self.requests for samples in source_samples)
            or self.gateway_metric_samples < self.gateway_tool_calls
        ):
            raise ValueError(
                "correlation requires an AgentGateway window with complete source samples"
            )
        return self


class ReliabilityResourceEvidence(_ReliabilityModel):
    resource: ReliabilityResource
    baseline: float = Field(ge=0, le=1_000_000)
    peak: float = Field(ge=0, le=1_000_000)
    final: float = Field(ge=0, le=1_000_000)
    maximum: float = Field(gt=0, le=1_000_000)
    permitted_growth: float = Field(ge=0, le=1_000_000)
    samples: int = Field(ge=2, le=100_000)

    @model_validator(mode="after")
    def consistent_samples(self) -> Self:
        if self.peak < max(self.baseline, self.final) or self.peak > self.maximum:
            raise ValueError("resource peak must cover samples within the maximum")
        return self

    @property
    def growth(self) -> float:
        return self.final - self.baseline


class ReliabilitySoakResult(_ReliabilityModel):
    loads: tuple[ReliabilityLoadEvidence, ...] = Field(
        min_length=1,
        max_length=100_000,
    )
    resources: tuple[ReliabilityResourceEvidence, ...] = Field(
        min_length=len(ReliabilityResource),
        max_length=len(ReliabilityResource),
    )

    @model_validator(mode="after")
    def covers_every_resource(self) -> Self:
        resources = {evidence.resource for evidence in self.resources}
        if resources != set(ReliabilityResource):
            raise ValueError("soak result must cover every bounded resource once")
        expected_samples = len(self.loads) + 1
        if any(item.samples != expected_samples for item in self.resources):
            raise ValueError("resource samples must cover every soak cycle boundary")
        return self

    @property
    def completed_calls(self) -> int:
        return sum(load.completed for load in self.loads)


class ReliabilityFairnessPlan(_ReliabilityModel):
    lane: ReliabilityLane
    global_limit: int = Field(ge=1, le=1_024)
    tool_limit: int = Field(ge=1, le=1_024)
    tenant_limit: int = Field(ge=1, le=1_024)
    noisy_started: int = Field(ge=1, le=100_000)
    reserved_started: int = Field(ge=1, le=100_000)

    @model_validator(mode="after")
    def scenario_fits_the_reviewed_limits(self) -> Self:
        if not self.tenant_limit <= self.tool_limit <= self.global_limit:
            raise ValueError("tenant, tool, global fairness limits must be nested")
        if self.noisy_started < self.tenant_limit:
            raise ValueError("noisy calls must reach the tenant limit")
        if self.tenant_limit + self.reserved_started > self.tool_limit:
            raise ValueError("tool limit must preserve the reserved calls")
        return self


@runtime_checkable
class ReliabilityFairnessTarget(Protocol):
    lane: ReliabilityLane
    global_limit: int
    tool_limit: int
    tenant_limit: int

    async def invoke_noisy(self, sequence: int) -> ReliabilityTargetResult: ...

    async def wait_until_noisy_classified(self) -> None: ...

    async def invoke_reserved(self, sequence: int) -> ReliabilityTargetResult: ...

    async def release_noisy(self) -> None: ...


class ReliabilityFairnessEvidence(_ReliabilityModel):
    global_limit: int = Field(ge=1, le=1_024)
    tool_limit: int = Field(ge=1, le=1_024)
    tenant_limit: int = Field(ge=1, le=1_024)
    noisy_started: int = Field(ge=1, le=100_000)
    noisy_admitted: int = Field(ge=0, le=100_000)
    noisy_overloaded: int = Field(ge=0, le=100_000)
    reserved_started: int = Field(ge=1, le=100_000)
    reserved_successful: int = Field(ge=0, le=100_000)

    @model_validator(mode="after")
    def consistent_calls(self) -> Self:
        if not self.tenant_limit <= self.tool_limit <= self.global_limit:
            raise ValueError("tenant, tool, and global evidence limits must be nested")
        if self.noisy_admitted + self.noisy_overloaded != self.noisy_started:
            raise ValueError("noisy tenant calls must be completely classified")
        if self.reserved_successful > self.reserved_started:
            raise ValueError("reserved tenant successes cannot exceed attempts")
        return self


class ReliabilityStatelessEvidence(_ReliabilityModel):
    deliveries: int = Field(ge=2, le=100_000)
    replicas: int = Field(ge=2, le=100)
    successful_calls: int = Field(ge=0, le=100_000)
    replica_switches: int = Field(ge=0, le=100_000)
    external_effects: int = Field(ge=0, le=100_000)
    request_memory_entries: int = Field(ge=0, le=1_000_000)
    request_filesystem_entries: int = Field(ge=0, le=1_000_000)
    session_affinity_required: bool

    @model_validator(mode="after")
    def counts_are_consistent(self) -> Self:
        if self.successful_calls > self.deliveries:
            raise ValueError("stateless successes cannot exceed deliveries")
        if self.replica_switches >= self.deliveries:
            raise ValueError("replica switches cannot exceed delivery boundaries")
        return self


class ReliabilityRetryCount(_ReliabilityModel):
    layer: ReliabilityRetryLayer
    count: int = Field(ge=0, le=1_000_000)


class ReliabilityRetryEvidence(_ReliabilityModel):
    owning_layer: ReliabilityRetryLayer
    maximum_attempts: int = Field(ge=1, le=10)
    calls: int = Field(ge=1, le=100_000)
    effects: int = Field(ge=0, le=100_000)
    retries: tuple[ReliabilityRetryCount, ...]

    @model_validator(mode="after")
    def every_layer_is_measured_once(self) -> Self:
        layers = tuple(item.layer for item in self.retries)
        if len(set(layers)) != len(layers) or set(layers) != set(ReliabilityRetryLayer):
            raise ValueError("every retry layer must be measured exactly once")
        return self

    def retry_count(self, layer: ReliabilityRetryLayer) -> int:
        return next(item.count for item in self.retries if item.layer is layer)


class ReliabilityRetryPlan(_ReliabilityModel):
    lane: ReliabilityLane
    owning_layer: ReliabilityRetryLayer
    maximum_attempts: int = Field(ge=1, le=10)
    calls: int = Field(ge=1, le=100_000)


class ReliabilityRetrySnapshot(_ReliabilityModel):
    effects: int = Field(ge=0, le=100_000)
    retries: tuple[ReliabilityRetryCount, ...]

    @model_validator(mode="after")
    def every_layer_is_measured_once(self) -> Self:
        layers = tuple(item.layer for item in self.retries)
        if len(set(layers)) != len(layers) or set(layers) != set(ReliabilityRetryLayer):
            raise ValueError("every retry layer must be measured exactly once")
        return self

    def retry_count(self, layer: ReliabilityRetryLayer) -> int:
        return next(item.count for item in self.retries if item.layer is layer)


@runtime_checkable
class ReliabilityRetryTarget(Protocol):
    lane: ReliabilityLane
    owning_layer: ReliabilityRetryLayer
    maximum_attempts: int

    async def snapshot(self) -> ReliabilityRetrySnapshot: ...

    async def invoke_duplicate(self, delivery: int) -> ReliabilityTargetResult: ...


class ReliabilityDependencyEvidence(_ReliabilityModel):
    dependency: ReliabilityDependency
    affected_calls: int = Field(ge=1, le=100_000)
    affected_outcome: ReliabilityOutcome
    unaffected_successes: int = Field(ge=0, le=100_000)
    maximum_queue_depth: int = Field(ge=0, le=10_000)
    runtime_retries: int = Field(ge=0, le=1_000_000)
    circuit_open_count: int = Field(ge=0, le=1_000_000)
    telemetry_drop_count: int = Field(ge=0, le=1_000_000)
    stale_cache_successes: int = Field(ge=0, le=100_000)
    fail_closed_count: int = Field(ge=0, le=100_000)


class ReliabilityRolloutEvidence(_ReliabilityModel):
    scenario: ReliabilityRolloutScenario
    accepted_calls: int = Field(ge=1, le=100_000)
    completed_calls: int = Field(ge=0, le=100_000)
    rejected_new_calls: int = Field(ge=0, le=100_000)
    interruption_seconds: float = Field(ge=0, le=300)
    drain_seconds: float = Field(ge=0, le=300)
    previous_capacity_preserved: bool
    rollback_restored: bool

    @model_validator(mode="after")
    def completed_calls_were_accepted(self) -> Self:
        if self.completed_calls > self.accepted_calls:
            raise ValueError("completed calls cannot exceed accepted calls")
        return self


class ReliabilityRolloutPlan(_ReliabilityModel):
    scenario: ReliabilityRolloutScenario
    accepted_calls: int = Field(ge=1, le=100_000)
    new_calls: int = Field(ge=1, le=100_000)

    @model_validator(mode="after")
    def bounded_calls(self) -> Self:
        if self.accepted_calls + self.new_calls > 100_000:
            raise ValueError("rollout plan exceeds the bounded invocation count")
        return self


class ReliabilityRolloutSnapshot(_ReliabilityModel):
    accepted_calls: int = Field(ge=0, le=100_000)
    completed_calls: int = Field(ge=0, le=100_000)
    rejected_new_calls: int = Field(ge=0, le=100_000)
    interruption_seconds: float = Field(ge=0, le=1_000_000)
    drain_seconds: float = Field(ge=0, le=1_000_000)
    previous_capacity_preserved: bool
    rollback_restored: bool

    @model_validator(mode="after")
    def completed_calls_were_accepted(self) -> Self:
        if self.completed_calls > self.accepted_calls:
            raise ValueError("completed calls cannot exceed accepted calls")
        return self


@runtime_checkable
class ReliabilityRolloutTarget(Protocol):
    scenario: ReliabilityRolloutScenario

    async def snapshot(self) -> ReliabilityRolloutSnapshot: ...

    async def accept(self, calls: int) -> None: ...

    async def begin_transition(self) -> None: ...

    async def reject_new(self, calls: int) -> None: ...

    async def drain(self) -> None: ...

    async def restore(self) -> None: ...


class ReliabilityCapacityPlan(_ReliabilityModel):
    observed_sustained_requests_per_second: float = Field(gt=0, le=1_000_000)
    observed_burst_requests_per_second: float = Field(gt=0, le=1_000_000)
    handler_p99_milliseconds: float = Field(gt=0, le=300_000)
    maximum_concurrency: int = Field(ge=1, le=1_024)
    normal_occupancy_ratio: float = Field(gt=0, le=1)
    minimum_replicas: int = Field(ge=2, le=100)
    maximum_replicas: int = Field(ge=2, le=1_000)
    observed_peak_rss_mebibytes: float = Field(gt=0, le=4_096)
    memory_request_mebibytes: int = Field(ge=1, le=4_096)
    memory_limit_mebibytes: int = Field(ge=1, le=8_192)
    termination_grace_seconds: float = Field(gt=0, le=300)
    scaling_metric: str = Field(pattern=r"^mcp_server_saturation_ratio$")
    scaling_target: float = Field(gt=0, le=1)

    @model_validator(mode="after")
    def capacity_covers_observations(self) -> Self:
        required = max(
            2,
            math.ceil(
                self.observed_burst_requests_per_second
                * (self.handler_p99_milliseconds / 1_000)
                / (self.maximum_concurrency * self.normal_occupancy_ratio)
            ),
        )
        if self.minimum_replicas < required or self.maximum_replicas < self.minimum_replicas:
            raise ValueError("replica bounds do not cover observed burst concurrency")
        if (
            self.memory_request_mebibytes < math.ceil(self.observed_peak_rss_mebibytes)
            or self.memory_limit_mebibytes < self.memory_request_mebibytes
        ):
            raise ValueError("memory resources do not cover the observed peak")
        return self


class ReliabilityReportBinding(_ReliabilityModel):
    source_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    runtime_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    profile_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ReliabilityDecision(_ReliabilityModel):
    approved: bool
    reasons: tuple[str, ...]
    evidence_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ReliabilityReport(_ReliabilityModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    binding: ReliabilityReportBinding
    complete: bool
    startup_seconds: float = Field(gt=0, le=300)
    idle_rss_mebibytes: float = Field(gt=0, le=4_096)
    loads: tuple[ReliabilityLoadEvidence, ...] = Field(min_length=1, max_length=64)
    correlations: tuple[ReliabilityCorrelationEvidence, ...] = Field(
        min_length=1,
        max_length=16,
    )
    resources: tuple[ReliabilityResourceEvidence, ...] = Field(min_length=1, max_length=16)
    fairness: ReliabilityFairnessEvidence
    statelessness: ReliabilityStatelessEvidence
    retry: ReliabilityRetryEvidence
    dependencies: tuple[ReliabilityDependencyEvidence, ...] = Field(
        min_length=1,
        max_length=16,
    )
    rollouts: tuple[ReliabilityRolloutEvidence, ...] = Field(min_length=1, max_length=16)
    capacity: ReliabilityCapacityPlan

    @model_validator(mode="after")
    def evidence_keys_are_unique(self) -> Self:
        if (
            len({(item.lane, item.kind) for item in self.loads}) != len(self.loads)
            or len({(item.lane, item.kind) for item in self.correlations}) != len(self.correlations)
            or len({item.resource for item in self.resources}) != len(self.resources)
            or len({item.dependency for item in self.dependencies}) != len(self.dependencies)
            or len({item.scenario for item in self.rollouts}) != len(self.rollouts)
        ):
            raise ValueError("reliability evidence keys must be unique")
        return self

    def to_json(self) -> str:
        return self.model_dump_json(indent=2) + "\n"

    def to_markdown(self) -> str:
        decision = assess_reliability_report(
            self,
            profile=standard_reliability_profile(),
            binding=self.binding,
        )
        return "\n".join(
            (
                "# Reliability evidence",
                "",
                f"- approved: {str(decision.approved).lower()}",
                f"- complete: {str(self.complete).lower()}",
                f"- load profiles: {len(self.loads)}",
                f"- correlated gateway windows: {len(self.correlations)}",
                f"- stateless replicas: {self.statelessness.replicas}",
                f"- dependency faults: {len(self.dependencies)}",
                f"- rollout scenarios: {len(self.rollouts)}",
                f"- evidence digest: {decision.evidence_digest}",
                "",
            )
        )


class ReliabilityProfile(_ReliabilityModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    sustained_requests_per_second: int = Field(default=50, ge=1, le=10_000)
    burst_requests_per_second: int = Field(default=200, ge=1, le=50_000)
    request_bytes: int = Field(default=65_536, ge=1, le=65_536)
    response_bytes: int = Field(default=524_288, ge=1, le=524_288)
    runtime_added_p99_milliseconds: float = Field(default=15, gt=0, le=1_000)
    startup_seconds: float = Field(default=2, gt=0, le=60)
    idle_rss_mebibytes: float = Field(default=128, gt=0, le=4_096)
    maximum_interruption_seconds: float = Field(default=5, ge=0, le=300)
    termination_grace_seconds: float = Field(default=45, gt=0, le=300)
    maximum_queue_depth: int = Field(default=0, ge=0, le=10_000)
    maximum_global_concurrency: int = Field(default=64, ge=1, le=1_024)
    maximum_tool_concurrency: int = Field(default=32, ge=1, le=1_024)
    maximum_tenant_concurrency: int = Field(default=16, ge=1, le=1_024)
    minimum_replicas: int = Field(default=2, ge=2, le=100)
    normal_occupancy_ratio: float = Field(default=0.5, gt=0, le=1)
    required_lanes: tuple[ReliabilityLane, ...] = (
        ReliabilityLane.IN_PROCESS,
        ReliabilityLane.DIRECT_HTTP,
        ReliabilityLane.AGENTGATEWAY,
    )

    @model_validator(mode="after")
    def consistent_limits(self) -> Self:
        if self.sustained_requests_per_second > self.burst_requests_per_second:
            raise ValueError("sustained rate cannot exceed burst rate")
        if not (
            self.maximum_tenant_concurrency
            <= self.maximum_tool_concurrency
            <= self.maximum_global_concurrency
        ):
            raise ValueError("tenant, tool, and global concurrency must be nested")
        if len(set(self.required_lanes)) != len(self.required_lanes):
            raise ValueError("required lanes must be unique")
        if set(self.required_lanes) != set(ReliabilityLane):
            raise ValueError("the standard reliability profile requires every lane")
        return self


def standard_reliability_profile() -> ReliabilityProfile:
    return ReliabilityProfile()


_RESOURCE_CEILINGS: dict[ReliabilityResource, float] = {
    ReliabilityResource.RSS_MEBIBYTES: 128,
    ReliabilityResource.TASKS: 256,
    ReliabilityResource.CONNECTIONS: 64,
    ReliabilityResource.SESSIONS: 128,
    ReliabilityResource.TELEMETRY_BUFFER: 2_048,
    ReliabilityResource.CREDENTIAL_CACHE: 32,
}


def reliability_profile_digest(profile: ReliabilityProfile) -> str:
    if not _is_runtime_instance(profile, ReliabilityProfile):
        raise TypeError("profile digest requires a validated reliability profile")
    encoded = json.dumps(
        profile.model_dump(mode="json"),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _evidence_digest(report: ReliabilityReport) -> str:
    encoded = json.dumps(
        report.model_dump(mode="json"),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def assess_reliability_report(
    report: ReliabilityReport,
    *,
    profile: ReliabilityProfile,
    binding: ReliabilityReportBinding,
) -> ReliabilityDecision:
    if (
        not _is_runtime_instance(report, ReliabilityReport)
        or not _is_runtime_instance(profile, ReliabilityProfile)
        or not _is_runtime_instance(binding, ReliabilityReportBinding)
    ):
        raise TypeError("reliability assessment requires validated evidence and profile")
    reasons: set[str] = set()
    if report.binding != binding:
        reasons.add("binding_mismatch")
    if report.binding.profile_digest != reliability_profile_digest(profile):
        reasons.add("profile_digest_mismatch")
    if not report.complete:
        reasons.add("report_incomplete")
    if report.startup_seconds > profile.startup_seconds:
        reasons.add("startup_target_missed")
    if report.idle_rss_mebibytes > profile.idle_rss_mebibytes:
        reasons.add("idle_rss_target_missed")

    loads = {(item.lane, item.kind): item for item in report.loads}
    for lane in profile.required_lanes:
        for kind in ReliabilityLoadKind:
            load_evidence = loads.get((lane, kind))
            if load_evidence is None:
                reasons.add(f"load_missing:{lane.value}:{kind.value}")
                continue
            if load_evidence.successful != load_evidence.completed:
                reasons.add(f"load_errors:{lane.value}:{kind.value}")
            if load_evidence.maximum_queue_depth > profile.maximum_queue_depth:
                reasons.add(f"queue_depth:{lane.value}:{kind.value}")
            if kind is ReliabilityLoadKind.SUSTAINED and (
                load_evidence.throughput_requests_per_second < profile.sustained_requests_per_second
            ):
                reasons.add(f"sustained_throughput:{lane.value}")
            if kind is ReliabilityLoadKind.BURST and (
                load_evidence.throughput_requests_per_second < profile.burst_requests_per_second
            ):
                reasons.add(f"burst_throughput:{lane.value}")
            if kind is ReliabilityLoadKind.BOUNDARY and (
                load_evidence.request_bytes < profile.request_bytes
                or load_evidence.response_bytes < profile.response_bytes
            ):
                reasons.add(f"payload_boundary:{lane.value}")
            if (
                lane is ReliabilityLane.IN_PROCESS
                and load_evidence.latency.p99_milliseconds > profile.runtime_added_p99_milliseconds
            ):
                reasons.add(f"runtime_p99:{kind.value}")

    correlations = {(item.lane, item.kind): item for item in report.correlations}
    for kind in ReliabilityLoadKind:
        correlation = correlations.get((ReliabilityLane.AGENTGATEWAY, kind))
        if correlation is None:
            reasons.add(f"correlation_missing:{kind.value}")
            continue
        load_evidence = loads.get((ReliabilityLane.AGENTGATEWAY, kind))
        if load_evidence is None:
            continue
        if correlation.requests != load_evidence.completed:
            reasons.add(f"correlation_request_count:{kind.value}")
        elif correlation.client_p99_milliseconds != load_evidence.latency.p99_milliseconds:
            reasons.add(f"correlation_client_p99:{kind.value}")

    resources = {item.resource: item for item in report.resources}
    for resource, ceiling in _RESOURCE_CEILINGS.items():
        resource_evidence = resources.get(resource)
        if resource_evidence is None:
            reasons.add(f"resource_missing:{resource.value}")
            continue
        if resource_evidence.growth > resource_evidence.permitted_growth:
            reasons.add(f"resource_growth:{resource.value}")
        if resource_evidence.peak > ceiling:
            reasons.add(f"resource_peak:{resource.value}")

    fairness = report.fairness
    if fairness.global_limit != profile.maximum_global_concurrency:
        reasons.add("global_limit_mismatch")
    if fairness.tool_limit != profile.maximum_tool_concurrency:
        reasons.add("tool_limit_mismatch")
    if fairness.tenant_limit != profile.maximum_tenant_concurrency:
        reasons.add("tenant_limit_mismatch")
    if fairness.noisy_admitted > fairness.tenant_limit:
        reasons.add("noisy_tenant_exceeded_limit")
    if fairness.reserved_successful != fairness.reserved_started:
        reasons.add("reserved_tenant_starved")

    statelessness = report.statelessness
    if statelessness.replicas < profile.minimum_replicas:
        reasons.add("stateless_replica_floor")
    if statelessness.successful_calls != statelessness.deliveries:
        reasons.add("stateless_call_failed")
    if statelessness.replica_switches != statelessness.deliveries - 1:
        reasons.add("stateless_replica_affinity")
    if statelessness.external_effects != 1:
        reasons.add("stateless_duplicate_effect")
    if statelessness.request_memory_entries:
        reasons.add("stateless_request_memory")
    if statelessness.request_filesystem_entries:
        reasons.add("stateless_request_filesystem")
    if statelessness.session_affinity_required:
        reasons.add("stateless_session_affinity")

    retry = report.retry
    if retry.owning_layer is not ReliabilityRetryLayer.RUNTIME:
        reasons.add("retry_owner")
    for layer in ReliabilityRetryLayer:
        count = retry.retry_count(layer)
        if layer is not retry.owning_layer and count:
            reasons.add(f"retry_amplification:{layer.value}")
    if retry.retry_count(retry.owning_layer) > retry.calls * (retry.maximum_attempts - 1):
        reasons.add("runtime_retry_cap")
    if retry.effects != 1:
        reasons.add("duplicate_effect")

    dependencies = {item.dependency: item for item in report.dependencies}
    for dependency in ReliabilityDependency:
        dependency_evidence = dependencies.get(dependency)
        if dependency_evidence is None:
            reasons.add(f"dependency_missing:{dependency.value}")
            continue
        if dependency_evidence.maximum_queue_depth > profile.maximum_queue_depth:
            reasons.add(f"dependency_queue:{dependency.value}")
        if dependency_evidence.unaffected_successes == 0:
            reasons.add(f"dependency_blast_radius:{dependency.value}")
        if dependency in {ReliabilityDependency.REGISTRY, ReliabilityDependency.TELEMETRY}:
            if dependency_evidence.affected_outcome is not ReliabilityOutcome.SUCCESS:
                reasons.add(f"dependency_degraded:{dependency.value}")
        elif dependency is ReliabilityDependency.IDENTITY:
            if (
                dependency_evidence.affected_outcome is not ReliabilityOutcome.AUTHENTICATION_DENIED
                or dependency_evidence.stale_cache_successes == 0
                or dependency_evidence.fail_closed_count == 0
            ):
                reasons.add("identity_cache_policy")
        elif dependency_evidence.affected_outcome not in {
            ReliabilityOutcome.UNAVAILABLE,
            ReliabilityOutcome.TIMEOUT,
        }:
            reasons.add(f"dependency_outcome:{dependency.value}")
        if (
            dependency is ReliabilityDependency.TELEMETRY
            and dependency_evidence.telemetry_drop_count == 0
        ):
            reasons.add("telemetry_drop_unmeasured")
        if (
            dependency
            in {
                ReliabilityDependency.DNS,
                ReliabilityDependency.BACKING_API,
            }
            and dependency_evidence.circuit_open_count == 0
        ):
            reasons.add(f"circuit_not_opened:{dependency.value}")

    rollouts = {item.scenario: item for item in report.rollouts}
    for scenario in ReliabilityRolloutScenario:
        rollout_evidence = rollouts.get(scenario)
        if rollout_evidence is None:
            reasons.add(f"rollout_missing:{scenario.value}")
            continue
        if rollout_evidence.completed_calls != rollout_evidence.accepted_calls:
            reasons.add(f"drain_incomplete:{scenario.value}")
        if rollout_evidence.rejected_new_calls == 0:
            reasons.add(f"drain_admission_open:{scenario.value}")
        if rollout_evidence.interruption_seconds > profile.maximum_interruption_seconds:
            reasons.add(f"interruption_target:{scenario.value}")
        if rollout_evidence.drain_seconds > profile.termination_grace_seconds:
            reasons.add(f"drain_target:{scenario.value}")
        if not rollout_evidence.previous_capacity_preserved:
            reasons.add(f"previous_capacity_lost:{scenario.value}")
        if not rollout_evidence.rollback_restored:
            reasons.add(f"rollback_failed:{scenario.value}")

    capacity = report.capacity
    if capacity.observed_sustained_requests_per_second < profile.sustained_requests_per_second:
        reasons.add("capacity_sustained")
    if capacity.observed_burst_requests_per_second < profile.burst_requests_per_second:
        reasons.add("capacity_burst")
    if capacity.minimum_replicas < profile.minimum_replicas:
        reasons.add("capacity_replica_floor")
    if capacity.termination_grace_seconds < profile.termination_grace_seconds:
        reasons.add("capacity_termination_grace")
    if capacity.scaling_target != profile.normal_occupancy_ratio:
        reasons.add("capacity_scaling_target")
    return ReliabilityDecision(
        approved=not reasons,
        reasons=tuple(sorted(reasons)),
        evidence_digest=_evidence_digest(report),
    )


def _percentile(samples: list[int], quantile: float) -> float:
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return ordered[index] / 1_000_000


async def run_reliability_load(
    plan: ReliabilityLoadPlan,
    target: ReliabilityTarget,
) -> ReliabilityLoadEvidence:
    if not _is_runtime_instance(plan, ReliabilityLoadPlan) or not _is_runtime_instance(
        target, ReliabilityTarget
    ):
        raise TypeError("reliability load requires validated plan and target")
    if target.lane is not plan.lane:
        raise ValueError("reliability target lane must match the load plan")
    semaphore = asyncio.Semaphore(plan.concurrency)
    durations = [0] * plan.requests
    results: list[ReliabilityTargetResult | None] = [None] * plan.requests
    active = 0
    peak = 0
    cancelled = False

    async def invoke(sequence: int) -> None:
        nonlocal active, cancelled, peak
        async with semaphore:
            active += 1
            peak = max(peak, active)
            started = time.perf_counter_ns()
            request = ReliabilityRequest(
                sequence=sequence,
                lane=plan.lane,
                tenant=f"reliability-tenant-{sequence % plan.tenants}",
                request_bytes=plan.request_bytes,
                response_bytes=plan.response_bytes,
            )
            try:
                results[sequence] = await target.invoke(request)
            except asyncio.CancelledError:
                cancelled = True
                raise
            except Exception:
                results[sequence] = ReliabilityTargetResult(outcome=ReliabilityOutcome.UNAVAILABLE)
            finally:
                durations[sequence] = max(0, time.perf_counter_ns() - started)
                active -= 1

    started = time.perf_counter()
    async with asyncio.TaskGroup() as group:
        for sequence in range(plan.requests):
            group.create_task(invoke(sequence))
    if cancelled:
        raise asyncio.CancelledError
    duration = max(time.perf_counter() - started, 1e-9)
    completed_results = tuple(result for result in results if result is not None)
    if len(completed_results) != plan.requests:
        raise RuntimeError("reliability runner lost a request result")
    counts = Counter(result.outcome for result in completed_results)
    outcomes = tuple(
        ReliabilityOutcomeCount(outcome=outcome, count=counts[outcome])
        for outcome in ReliabilityOutcome
        if counts[outcome]
    )
    sample_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                {
                    "durations": durations,
                    "outcomes": [result.outcome.value for result in completed_results],
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
    )
    return ReliabilityLoadEvidence(
        name=plan.name,
        lane=plan.lane,
        kind=plan.kind,
        request_bytes=plan.request_bytes,
        response_bytes=max(
            (result.response_bytes for result in completed_results),
            default=0,
        ),
        completed=plan.requests,
        successful=counts[ReliabilityOutcome.SUCCESS],
        outcomes=outcomes,
        duration_seconds=duration,
        throughput_requests_per_second=plan.requests / duration,
        latency=ReliabilityLatency(
            p50_milliseconds=_percentile(durations, 0.50),
            p95_milliseconds=_percentile(durations, 0.95),
            p99_milliseconds=_percentile(durations, 0.99),
            maximum_milliseconds=max(durations) / 1_000_000,
        ),
        peak_client_concurrency=peak,
        maximum_queue_depth=max(result.queue_depth for result in completed_results),
        sample_digest=sample_digest,
    )


def _resource_value(
    snapshot: ReliabilityResourceSnapshot,
    resource: ReliabilityResource,
) -> float:
    match resource:
        case ReliabilityResource.RSS_MEBIBYTES:
            return snapshot.rss_mebibytes
        case ReliabilityResource.TASKS:
            return float(snapshot.tasks)
        case ReliabilityResource.CONNECTIONS:
            return float(snapshot.connections)
        case ReliabilityResource.SESSIONS:
            return float(snapshot.sessions)
        case ReliabilityResource.TELEMETRY_BUFFER:
            return float(snapshot.telemetry_buffer)
        case ReliabilityResource.CREDENTIAL_CACHE:
            return float(snapshot.credential_cache)


async def run_reliability_soak(
    plan: ReliabilitySoakPlan,
    target: ReliabilityTarget,
    probe: ReliabilityResourceProbe,
) -> ReliabilitySoakResult:
    if not _is_runtime_instance(plan, ReliabilitySoakPlan) or not _is_runtime_instance(
        probe, ReliabilityResourceProbe
    ):
        raise TypeError("reliability soak requires validated plan and resource probe")

    async def snapshot() -> ReliabilityResourceSnapshot:
        sample = await probe.snapshot()
        if not _is_runtime_instance(sample, ReliabilityResourceSnapshot):
            raise TypeError("resource probe returned an invalid snapshot")
        return sample

    samples = [await snapshot()]
    loads: list[ReliabilityLoadEvidence] = []
    for _ in range(plan.cycles):
        loads.append(await run_reliability_load(plan.load, target))
        samples.append(await snapshot())

    budgets = {budget.resource: budget for budget in plan.budgets}
    resources = tuple(
        ReliabilityResourceEvidence(
            resource=resource,
            baseline=_resource_value(samples[0], resource),
            peak=max(_resource_value(sample, resource) for sample in samples),
            final=_resource_value(samples[-1], resource),
            maximum=budgets[resource].maximum,
            permitted_growth=budgets[resource].permitted_growth,
            samples=len(samples),
        )
        for resource in ReliabilityResource
    )
    return ReliabilitySoakResult(loads=tuple(loads), resources=resources)


def _dependency_counter_delta(
    before: ReliabilityDependencySnapshot,
    after: ReliabilityDependencySnapshot,
    field: str,
) -> int:
    initial = getattr(before, field)
    final = getattr(after, field)
    if not isinstance(initial, int) or not isinstance(final, int) or final < initial:
        raise ValueError("dependency counters must be monotonic integers")
    return final - initial


async def run_reliability_dependency_failure(
    plan: ReliabilityDependencyPlan,
    target: ReliabilityDependencyTarget,
) -> ReliabilityDependencyEvidence:
    if target.lane is not plan.lane:
        raise ValueError("dependency target lane does not match the evidence plan")
    if target.dependency is not plan.dependency:
        raise ValueError("dependency target does not match the evidence plan")

    before = await target.snapshot()
    affected_results: list[ReliabilityTargetResult] = []
    unaffected_results: list[ReliabilityTargetResult] = []

    async def invoke_affected(sequence: int) -> None:
        request = ReliabilityRequest(
            sequence=sequence,
            lane=plan.lane,
            tenant="reliability-tenant-affected",
            request_bytes=plan.request_bytes,
            response_bytes=plan.response_bytes,
        )
        affected_results.append(await target.invoke_affected(request))

    async def invoke_unaffected(sequence: int) -> None:
        request = ReliabilityRequest(
            sequence=plan.affected_calls + sequence,
            lane=plan.lane,
            tenant="reliability-tenant-unaffected",
            request_bytes=plan.request_bytes,
            response_bytes=plan.response_bytes,
        )
        unaffected_results.append(await target.invoke_unaffected(request))

    async with asyncio.TaskGroup() as tasks:
        for sequence in range(plan.affected_calls):
            tasks.create_task(invoke_affected(sequence))
        for sequence in range(plan.unaffected_calls):
            tasks.create_task(invoke_unaffected(sequence))

    after = await target.snapshot()
    affected_outcomes = {result.outcome for result in affected_results}
    if len(affected_outcomes) != 1:
        raise ValueError("affected dependency calls must have one terminal outcome")
    all_results = affected_results + unaffected_results
    fields = (
        "runtime_retries",
        "circuit_open_count",
        "telemetry_drop_count",
        "stale_cache_successes",
        "fail_closed_count",
    )
    deltas = {field: _dependency_counter_delta(before, after, field) for field in fields}
    return ReliabilityDependencyEvidence(
        dependency=plan.dependency,
        affected_calls=len(affected_results),
        affected_outcome=next(iter(affected_outcomes)),
        unaffected_successes=sum(
            result.outcome is ReliabilityOutcome.SUCCESS for result in unaffected_results
        ),
        maximum_queue_depth=max(result.queue_depth for result in all_results),
        runtime_retries=deltas["runtime_retries"],
        circuit_open_count=deltas["circuit_open_count"],
        telemetry_drop_count=deltas["telemetry_drop_count"],
        stale_cache_successes=deltas["stale_cache_successes"],
        fail_closed_count=deltas["fail_closed_count"],
    )


async def run_reliability_retry_scenario(
    plan: ReliabilityRetryPlan,
    target: ReliabilityRetryTarget,
) -> ReliabilityRetryEvidence:
    if target.lane is not plan.lane:
        raise ValueError("retry target lane does not match the evidence plan")
    if target.owning_layer is not plan.owning_layer:
        raise ValueError("retry target owner does not match the evidence plan")
    if target.maximum_attempts != plan.maximum_attempts:
        raise ValueError("retry target attempt cap does not match the evidence plan")

    before = await target.snapshot()
    results: list[ReliabilityTargetResult] = []

    async def invoke(delivery: int) -> None:
        results.append(await target.invoke_duplicate(delivery))

    async with asyncio.TaskGroup() as tasks:
        for delivery in range(plan.calls):
            tasks.create_task(invoke(delivery))

    if any(result.outcome is not ReliabilityOutcome.SUCCESS for result in results):
        raise ValueError("duplicate deliveries must return the recorded result")
    after = await target.snapshot()
    if after.effects < before.effects:
        raise ValueError("retry effect counter must be monotonic")
    retries = tuple(
        ReliabilityRetryCount(
            layer=layer,
            count=after.retry_count(layer) - before.retry_count(layer),
        )
        for layer in ReliabilityRetryLayer
    )
    if any(item.count < 0 for item in retries):
        raise ValueError("retry counters must be monotonic")
    return ReliabilityRetryEvidence(
        owning_layer=plan.owning_layer,
        maximum_attempts=plan.maximum_attempts,
        calls=len(results),
        effects=after.effects - before.effects,
        retries=retries,
    )


def _rollout_counter_delta(
    before: ReliabilityRolloutSnapshot,
    after: ReliabilityRolloutSnapshot,
    field: str,
) -> int:
    initial = getattr(before, field)
    final = getattr(after, field)
    if not isinstance(initial, int) or not isinstance(final, int) or final < initial:
        raise ValueError("rollout counters must be monotonic integers")
    return final - initial


def _rollout_duration_delta(
    before: ReliabilityRolloutSnapshot,
    after: ReliabilityRolloutSnapshot,
    field: str,
) -> float:
    initial = getattr(before, field)
    final = getattr(after, field)
    if not isinstance(initial, float) or not isinstance(final, float) or final < initial:
        raise ValueError("rollout durations must be monotonic")
    return final - initial


async def run_reliability_rollout_scenario(
    plan: ReliabilityRolloutPlan,
    target: ReliabilityRolloutTarget,
) -> ReliabilityRolloutEvidence:
    if target.scenario is not plan.scenario:
        raise ValueError("rollout target does not match the evidence plan")

    before = await target.snapshot()
    await target.accept(plan.accepted_calls)
    await target.begin_transition()
    await target.reject_new(plan.new_calls)
    await target.drain()
    await target.restore()
    after = await target.snapshot()
    return ReliabilityRolloutEvidence(
        scenario=plan.scenario,
        accepted_calls=_rollout_counter_delta(before, after, "accepted_calls"),
        completed_calls=_rollout_counter_delta(before, after, "completed_calls"),
        rejected_new_calls=_rollout_counter_delta(before, after, "rejected_new_calls"),
        interruption_seconds=_rollout_duration_delta(
            before,
            after,
            "interruption_seconds",
        ),
        drain_seconds=_rollout_duration_delta(before, after, "drain_seconds"),
        previous_capacity_preserved=after.previous_capacity_preserved,
        rollback_restored=after.rollback_restored,
    )


async def run_reliability_stateless_scenario(
    plan: ReliabilityStatelessPlan,
    target: ReliabilityStatelessTarget,
) -> ReliabilityStatelessEvidence:
    if target.replica_count != plan.replicas:
        raise ValueError("stateless target replica count does not match the evidence plan")
    before = await target.snapshot()
    if len(before.request_memory_entries) != plan.replicas:
        raise ValueError("stateless target snapshot does not cover every replica")

    results: list[ReliabilityTargetResult] = []
    replicas: list[int] = []
    for delivery in range(plan.deliveries):
        replica = delivery % plan.replicas
        replicas.append(replica)
        request = ReliabilityStatelessRequest(
            sequence=delivery,
            workload_identity="reliability-workload-0",
            tenant="reliability-tenant-0",
            tool_name="reliability_tool",
            capability_ref="cap/reliability",
            tool_version="1.0.0",
            schema_fingerprint="sha256:" + "a" * 64,
            arguments=(("value", "synthetic"),),
            authorization_token="reliability-token-synthetic",
            authorization_scopes=("reliability:invoke",),
            approval_reference="reliability-approval-shared",
            request_id=f"reliability-request-{delivery}",
            correlation_id="reliability-correlation-shared",
            trace_id="1" * 32,
            run_id="reliability-run-shared",
            conversation_reference="reliability-conversation-shared",
            workflow_reference="reliability-workflow-shared",
            resource_reference="reliability-resource-shared",
            timeout_milliseconds=5_000,
            retry_owner=ReliabilityRetryLayer.RUNTIME,
            maximum_attempts=3,
            idempotency_key="reliability-idempotency-shared",
            idempotency_request_digest="sha256:" + "b" * 64,
        )
        results.append(await target.invoke(replica, request))

    after = await target.snapshot()
    if len(after.request_memory_entries) != plan.replicas:
        raise ValueError("stateless target snapshot does not cover every replica")
    if after.external_effects < before.external_effects:
        raise ValueError("external effect counter must be monotonic")
    return ReliabilityStatelessEvidence(
        deliveries=len(results),
        replicas=plan.replicas,
        successful_calls=sum(result.outcome is ReliabilityOutcome.SUCCESS for result in results),
        replica_switches=sum(left != right for left, right in pairwise(replicas)),
        external_effects=after.external_effects - before.external_effects,
        request_memory_entries=sum(after.request_memory_entries),
        request_filesystem_entries=sum(after.request_filesystem_entries),
        session_affinity_required=after.session_affinity_required,
    )


async def run_reliability_fairness_scenario(
    plan: ReliabilityFairnessPlan,
    target: ReliabilityFairnessTarget,
) -> ReliabilityFairnessEvidence:
    if target.lane is not plan.lane:
        raise ValueError("fairness target lane does not match the evidence plan")
    if (
        target.global_limit,
        target.tool_limit,
        target.tenant_limit,
    ) != (plan.global_limit, plan.tool_limit, plan.tenant_limit):
        raise ValueError("fairness target limits do not match the evidence plan")

    noisy_results: list[ReliabilityTargetResult] = []
    reserved_results: list[ReliabilityTargetResult] = []

    async def invoke_noisy(sequence: int) -> None:
        noisy_results.append(await target.invoke_noisy(sequence))

    async with asyncio.TaskGroup() as tasks:
        for sequence in range(plan.noisy_started):
            tasks.create_task(invoke_noisy(sequence))
        await target.wait_until_noisy_classified()
        for sequence in range(plan.reserved_started):
            reserved_results.append(await target.invoke_reserved(sequence))
        await target.release_noisy()

    noisy_admitted = sum(result.outcome is ReliabilityOutcome.SUCCESS for result in noisy_results)
    noisy_overloaded = sum(
        result.outcome is ReliabilityOutcome.OVERLOADED for result in noisy_results
    )
    if noisy_admitted + noisy_overloaded != len(noisy_results):
        raise ValueError("noisy calls must be successful or overloaded")
    return ReliabilityFairnessEvidence(
        global_limit=plan.global_limit,
        tool_limit=plan.tool_limit,
        tenant_limit=plan.tenant_limit,
        noisy_started=len(noisy_results),
        noisy_admitted=noisy_admitted,
        noisy_overloaded=noisy_overloaded,
        reserved_started=len(reserved_results),
        reserved_successful=sum(
            result.outcome is ReliabilityOutcome.SUCCESS for result in reserved_results
        ),
    )


__all__ = [
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
    "ReliabilityResourceEvidence",
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
    "run_reliability_stateless_scenario",
    "standard_reliability_profile",
]
