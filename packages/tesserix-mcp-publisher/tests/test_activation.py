from __future__ import annotations

import asyncio
import copy
from collections.abc import Mapping
from typing import Any, cast

import pytest
from tesserix_mcp_publisher import (
    ActivationClient,
    ActivationClock,
    ActivationContractError,
    ActivationPhase,
    ActivationStatus,
    ActivationTarget,
    ActivationTerminalError,
    ActivationTimeoutError,
    ActivationWaiter,
    PublicationError,
    PublicationErrorCode,
    SystemActivationClock,
)

REGISTRY_DIGEST = f"sha256:{'a' * 64}"
ARTIFACT_DIGEST = f"sha256:{'b' * 64}"
REF = "mcpservers/tenant-orders/io.github.tesserix/orders@1.2.3"

ACTORS = {
    "Published": "registry",
    "DeploymentReady": "gateway-reconciler",
    "ProbeReady": "protocol-prober",
    "RouteReady": "gateway-reconciler",
    "Healthy": "protocol-prober",
    "Failed": "registry",
}


def condition(condition_type: str, status: str = "True") -> dict[str, object]:
    return {
        "type": condition_type,
        "status": status,
        "actor": ACTORS[condition_type],
        "reason": f"{condition_type}Observed",
        "observedGeneration": 7,
        "registryDigest": REGISTRY_DIGEST,
        "artifactDigest": ARTIFACT_DIGEST,
        "lastTransitionTime": "2026-08-30T12:00:00Z",
        "requestId": f"request-{condition_type.lower()}",
    }


def activation_document(
    phase: str,
    *,
    desired_state: str = "published",
    true_conditions: tuple[str, ...] = ("Published",),
    false_conditions: tuple[str, ...] = (),
    active_at: str | None = None,
) -> dict[str, Any]:
    conditions = [condition(name) for name in true_conditions]
    conditions.extend(condition(name, "False") for name in false_conditions)
    return {
        "schemaVersion": "v1alpha1",
        "ref": REF,
        "registryDigest": REGISTRY_DIGEST,
        "artifactDigest": ARTIFACT_DIGEST,
        "generation": 7,
        "desiredState": desired_state,
        "phase": phase,
        "publishedAt": (None if desired_state == "draft" else "2026-08-30T11:59:00Z"),
        "activeAt": active_at,
        "observedAt": "2026-08-30T12:00:00Z",
        "conditions": conditions,
    }


@pytest.mark.parametrize(
    ("phase", "document"),
    [
        (
            ActivationPhase.DRAFT,
            activation_document("draft", desired_state="draft", true_conditions=()),
        ),
        (ActivationPhase.PUBLISHED, activation_document("published")),
        (
            ActivationPhase.DEPLOYED,
            activation_document(
                "deployed",
                true_conditions=("Published", "DeploymentReady"),
            ),
        ),
        (
            ActivationPhase.PROBED,
            activation_document(
                "probed",
                true_conditions=(
                    "Published",
                    "DeploymentReady",
                    "ProbeReady",
                    "Healthy",
                ),
            ),
        ),
        (
            ActivationPhase.ACTIVE,
            activation_document(
                "active",
                true_conditions=(
                    "Published",
                    "DeploymentReady",
                    "ProbeReady",
                    "RouteReady",
                    "Healthy",
                ),
                active_at="2026-08-30T12:00:00Z",
            ),
        ),
        (
            ActivationPhase.DEGRADED,
            activation_document(
                "degraded",
                true_conditions=(
                    "Published",
                    "DeploymentReady",
                    "ProbeReady",
                    "RouteReady",
                ),
                false_conditions=("Healthy",),
                active_at="2026-08-30T11:59:30Z",
            ),
        ),
        (
            ActivationPhase.DEPRECATED,
            activation_document(
                "deprecated",
                desired_state="deprecated",
                true_conditions=(
                    "Published",
                    "DeploymentReady",
                    "ProbeReady",
                    "RouteReady",
                    "Healthy",
                ),
                active_at="2026-08-30T11:59:30Z",
            ),
        ),
        (
            ActivationPhase.RETIRED,
            activation_document(
                "retired",
                desired_state="retired",
                true_conditions=("Published",),
                active_at="2026-08-30T11:59:30Z",
            ),
        ),
        (
            ActivationPhase.FAILED,
            activation_document(
                "failed",
                true_conditions=("Published", "Failed"),
            ),
        ),
    ],
)
def test_activation_phase_is_derived_and_explained_without_payloads(
    phase: ActivationPhase,
    document: Mapping[str, Any],
) -> None:
    status = ActivationStatus.from_document(document)

    assert status.phase is phase
    explanation = status.explain(request_id="request-cli")
    assert explanation["phase"] == phase.value
    assert explanation["summary"]
    assert explanation["ref"] == REF
    assert explanation["registry_digest"] == REGISTRY_DIGEST
    assert explanation["artifact_digest"] == ARTIFACT_DIGEST
    assert explanation["request_id"] == "request-cli"
    assert "message" not in explanation
    assert "spec" not in explanation


class FakeActivationClient:
    def __init__(self, statuses: list[ActivationStatus | PublicationError]) -> None:
        self.statuses = statuses
        self.calls: list[tuple[ActivationTarget, str]] = []

    async def fetch_activation(
        self,
        target: ActivationTarget,
        *,
        request_id: str,
    ) -> ActivationStatus:
        self.calls.append((target, request_id))
        if not self.statuses:
            raise AssertionError("unexpected activation fetch")
        result = self.statuses.pop(0)
        if isinstance(result, PublicationError):
            raise result
        return result


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.now += delay


def parsed_status(document: Mapping[str, Any]) -> ActivationStatus:
    return ActivationStatus.from_document(document)


def test_waiter_polls_monotonically_until_the_digest_bound_target_is_active() -> None:
    client = FakeActivationClient(
        [
            parsed_status(activation_document("published")),
            parsed_status(
                activation_document(
                    "deployed",
                    true_conditions=("Published", "DeploymentReady"),
                )
            ),
            parsed_status(
                activation_document(
                    "probed",
                    true_conditions=(
                        "Published",
                        "DeploymentReady",
                        "ProbeReady",
                        "Healthy",
                    ),
                )
            ),
            parsed_status(
                activation_document(
                    "active",
                    true_conditions=(
                        "Published",
                        "DeploymentReady",
                        "ProbeReady",
                        "RouteReady",
                        "Healthy",
                    ),
                    active_at="2026-08-30T12:00:00Z",
                )
            ),
        ]
    )
    clock = FakeClock()
    waiter = ActivationWaiter(
        client=client,
        clock=clock,
    )
    target = ActivationTarget(
        ref=REF,
        registry_digest=REGISTRY_DIGEST,
        artifact_digest=ARTIFACT_DIGEST,
    )

    status = asyncio.run(
        waiter.wait(
            target,
            target_phase=ActivationPhase.ACTIVE,
            timeout_seconds=120.0,
            poll_interval_seconds=2.0,
            request_id="request-wait",
        )
    )

    assert status.phase is ActivationPhase.ACTIVE
    assert clock.sleeps == [2.0, 2.0, 2.0]
    assert client.calls == [(target, "request-wait")] * 4
    assert isinstance(client, ActivationClient)
    assert isinstance(clock, ActivationClock)


def test_waiter_returns_payload_free_terminal_failure_and_timeout_details() -> None:
    target = ActivationTarget(
        ref=REF,
        registry_digest=REGISTRY_DIGEST,
        artifact_digest=ARTIFACT_DIGEST,
    )
    failed = parsed_status(
        activation_document(
            "failed",
            true_conditions=("Published", "Failed"),
        )
    )
    with pytest.raises(ActivationTerminalError) as terminal:
        asyncio.run(
            ActivationWaiter(
                client=FakeActivationClient([failed]),
                clock=FakeClock(),
            ).wait(
                target,
                target_phase=ActivationPhase.ACTIVE,
                timeout_seconds=120.0,
                poll_interval_seconds=2.0,
                request_id="request-terminal",
            )
        )

    assert terminal.value.code is PublicationErrorCode.ACTIVATION_FAILED
    terminal_document = terminal.value.to_dict()
    terminal_activation = cast(dict[str, object], terminal_document["activation"])
    assert terminal_activation["phase"] == "failed"
    assert terminal_activation["request_id"] == "request-terminal"
    assert "message" not in terminal_activation

    published = parsed_status(activation_document("published"))
    clock = FakeClock()
    with pytest.raises(ActivationTimeoutError) as timed_out:
        asyncio.run(
            ActivationWaiter(
                client=FakeActivationClient([published, published, published, published]),
                clock=clock,
            ).wait(
                target,
                target_phase=ActivationPhase.ACTIVE,
                timeout_seconds=5.0,
                poll_interval_seconds=2.0,
                request_id="request-timeout",
            )
        )

    assert timed_out.value.code is PublicationErrorCode.ACTIVATION_TIMEOUT
    timeout_activation = cast(
        dict[str, object],
        timed_out.value.to_dict()["activation"],
    )
    assert timeout_activation["phase"] == "published"
    assert clock.sleeps == [2.0, 2.0, 1.0]
    assert clock.now == 105.0


def test_waiter_retries_only_retryable_reads_and_rejects_superseded_generation() -> None:
    active = parsed_status(
        activation_document(
            "active",
            true_conditions=(
                "Published",
                "DeploymentReady",
                "ProbeReady",
                "RouteReady",
                "Healthy",
            ),
            active_at="2026-08-30T12:00:00Z",
        )
    )
    retryable = PublicationError(
        PublicationErrorCode.UNAVAILABLE,
        request_id="registry-read",
        retryable=True,
    )
    clock = FakeClock()
    target = ActivationTarget(
        ref=REF,
        registry_digest=REGISTRY_DIGEST,
        artifact_digest=ARTIFACT_DIGEST,
    )

    status = asyncio.run(
        ActivationWaiter(
            client=FakeActivationClient([retryable, active]),
            clock=clock,
        ).wait(
            target,
            target_phase=ActivationPhase.ACTIVE,
            timeout_seconds=120.0,
            poll_interval_seconds=2.0,
            request_id="request-retry",
        )
    )

    assert status.phase is ActivationPhase.ACTIVE
    assert clock.sleeps == [2.0]

    moved = activation_document("published")
    moved["generation"] = 8
    for item in moved["conditions"]:
        item["observedGeneration"] = 8
    moved_status = parsed_status(moved)
    with pytest.raises(PublicationError) as superseded:
        asyncio.run(
            ActivationWaiter(
                client=FakeActivationClient(
                    [parsed_status(activation_document("published")), moved_status]
                ),
                clock=FakeClock(),
            ).wait(
                target,
                target_phase=ActivationPhase.ACTIVE,
                timeout_seconds=120.0,
                poll_interval_seconds=2.0,
                request_id="request-superseded",
            )
        )

    assert superseded.value.code is PublicationErrorCode.ACTIVATION_SUPERSEDED
    assert superseded.value.retryable is False


def test_status_and_waiter_fail_closed_on_mixed_or_stale_observations() -> None:
    unsafe = activation_document("published")
    unsafe["conditions"][0]["actor"] = "protocol-prober"
    unsafe["conditions"][0]["message"] = "Bearer CCCCCCCCCCCCCCCC"

    with pytest.raises(ActivationContractError) as invalid:
        ActivationStatus.from_document(unsafe, request_id="request-invalid-status")

    assert invalid.value.code is PublicationErrorCode.ACTIVATION_CONTRACT_INVALID
    assert invalid.value.request_id == "request-invalid-status"
    assert "CCCCCCCCCCCCCCCC" not in str(invalid.value)

    newer = activation_document("published")
    newer["observedAt"] = "2026-08-30T12:01:00Z"
    older = activation_document("published")
    target = ActivationTarget(
        ref=REF,
        registry_digest=REGISTRY_DIGEST,
        artifact_digest=ARTIFACT_DIGEST,
    )

    with pytest.raises(ActivationContractError) as stale:
        asyncio.run(
            ActivationWaiter(
                client=FakeActivationClient([parsed_status(newer), parsed_status(older)]),
                clock=FakeClock(),
            ).wait(
                target,
                target_phase=ActivationPhase.ACTIVE,
                timeout_seconds=120.0,
                poll_interval_seconds=2.0,
                request_id="request-stale-status",
            )
        )

    assert stale.value.request_id == "request-stale-status"


@pytest.mark.parametrize(
    "ref",
    [
        "mcpservers/tenant-orders/orders api@1.2.3",
        "mcpservers/tenant-orders/../orders@1.2.3",
        "mcpservers/tenant-orders/orders?token=CCCCCCCCCCCCCCCC@1.2.3",
        "https://registry.example.com/mcpservers/orders@1.2.3",
    ],
    ids=["space", "traversal", "query", "absolute-url"],
)
def test_activation_target_rejects_unsafe_refs_without_echoing_them(ref: str) -> None:
    with pytest.raises(PublicationError) as invalid:
        ActivationTarget(
            ref=ref,
            registry_digest=REGISTRY_DIGEST,
            artifact_digest=ARTIFACT_DIGEST,
        )

    assert invalid.value.code is PublicationErrorCode.INVALID_ARGUMENT
    assert ref not in str(invalid.value)
    assert "CCCCCCCCCCCCCCCC" not in str(invalid.value)


def test_activation_contract_rejects_invalid_shapes_and_state_invariants() -> None:
    invalid: list[object] = [[]]

    wrong_digest = activation_document("published")
    wrong_digest["registryDigest"] = "sha256:not-a-digest"
    invalid.append(wrong_digest)

    invalid_timestamp = activation_document("published")
    invalid_timestamp["observedAt"] = "not-a-timeZ"
    invalid.append(invalid_timestamp)

    noncanonical_timestamp = activation_document("published")
    noncanonical_timestamp["observedAt"] = "2026-08-30T12:00:00.000000Z"
    invalid.append(noncanonical_timestamp)

    nontext_enum = activation_document("published")
    nontext_enum["desiredState"] = 1
    invalid.append(nontext_enum)

    unknown_enum = activation_document("published")
    unknown_enum["desiredState"] = "removed"
    invalid.append(unknown_enum)

    wrong_actor = activation_document("published")
    wrong_actor["conditions"][0]["actor"] = "protocol-prober"
    invalid.append(wrong_actor)

    invalid_condition_generation = activation_document("published")
    invalid_condition_generation["conditions"][0]["observedGeneration"] = True
    invalid.append(invalid_condition_generation)

    invalid_top_generation = activation_document("published")
    invalid_top_generation["generation"] = False
    invalid.append(invalid_top_generation)

    too_many_conditions = activation_document("published")
    too_many_conditions["conditions"] = [condition("Published")] * 7
    invalid.append(too_many_conditions)

    overlong_ref = activation_document("published")
    overlong_ref["ref"] = "mcpservers/tenant-orders/" + "/".join(["a" * 255] * 9) + "@1.2.3"
    invalid.append(overlong_ref)

    duplicate = activation_document("published")
    duplicate["conditions"].append(copy.deepcopy(duplicate["conditions"][0]))
    invalid.append(duplicate)

    mixed_generation = activation_document("published")
    mixed_generation["conditions"][0]["observedGeneration"] = 6
    invalid.append(mixed_generation)

    future_condition = activation_document("published")
    future_condition["conditions"][0]["lastTransitionTime"] = "2026-08-30T12:01:00Z"
    invalid.append(future_condition)

    future_publication = activation_document("published")
    future_publication["publishedAt"] = "2026-08-30T12:01:00Z"
    invalid.append(future_publication)

    phase_mismatch = activation_document("active")
    invalid.append(phase_mismatch)

    invalid_draft = activation_document(
        "draft",
        desired_state="draft",
        true_conditions=("Published",),
    )
    invalid.append(invalid_draft)

    unpublished = activation_document("published")
    unpublished["publishedAt"] = None
    invalid.append(unpublished)

    invalid.append(
        activation_document(
            "retired",
            desired_state="retired",
            active_at=None,
        )
    )
    invalid.append(
        activation_document(
            "deprecated",
            desired_state="deprecated",
            active_at=None,
        )
    )
    invalid.append(
        activation_document(
            "failed",
            true_conditions=("Published", "Failed"),
            active_at="2026-08-30T12:00:00Z",
        )
    )
    invalid.append(
        activation_document(
            "active",
            true_conditions=(
                "Published",
                "DeploymentReady",
                "ProbeReady",
                "RouteReady",
                "Healthy",
            ),
            active_at=None,
        )
    )

    for document in invalid:
        with pytest.raises(ActivationContractError):
            ActivationStatus.from_document(document)

    with pytest.raises(ValueError):
        parsed_status(activation_document("published")).explain(request_id="unsafe id")


def test_waiter_validates_boundaries_and_handles_read_failure_deadlines() -> None:
    with pytest.raises(TypeError):
        ActivationWaiter(client=cast(ActivationClient, object()))
    with pytest.raises(TypeError):
        ActivationWaiter(
            client=FakeActivationClient([]),
            clock=cast(ActivationClock, object()),
        )

    target = ActivationTarget(
        ref=REF,
        registry_digest=REGISTRY_DIGEST,
        artifact_digest=ARTIFACT_DIGEST,
    )
    with pytest.raises(PublicationError) as invalid:
        asyncio.run(
            ActivationWaiter(
                client=FakeActivationClient([]),
                clock=FakeClock(),
            ).wait(
                target,
                target_phase=ActivationPhase.ACTIVE,
                timeout_seconds=float("inf"),
                poll_interval_seconds=2.0,
                request_id="unsafe id",
            )
        )
    assert invalid.value.code is PublicationErrorCode.INVALID_ARGUMENT
    assert invalid.value.request_id == "activation-validation"

    terminal_read = PublicationError(
        PublicationErrorCode.COMMAND_FAILED,
        request_id="registry-read",
    )
    with pytest.raises(PublicationError) as terminal:
        asyncio.run(
            ActivationWaiter(
                client=FakeActivationClient([terminal_read]),
                clock=FakeClock(),
            ).wait(
                target,
                target_phase=ActivationPhase.ACTIVE,
                timeout_seconds=1.0,
                poll_interval_seconds=0.1,
                request_id="request-read-terminal",
            )
        )
    assert terminal.value is terminal_read

    retryable = PublicationError(
        PublicationErrorCode.UNAVAILABLE,
        request_id="registry-read",
        retryable=True,
    )
    with pytest.raises(PublicationError) as no_status:
        asyncio.run(
            ActivationWaiter(
                client=FakeActivationClient([retryable, retryable]),
                clock=FakeClock(),
            ).wait(
                target,
                target_phase=ActivationPhase.ACTIVE,
                timeout_seconds=0.1,
                poll_interval_seconds=0.1,
                request_id="request-read-timeout",
            )
        )
    assert no_status.value.code is PublicationErrorCode.ACTIVATION_TIMEOUT
    assert no_status.value.retryable is True

    published = parsed_status(activation_document("published"))
    with pytest.raises(ActivationTimeoutError) as with_status:
        asyncio.run(
            ActivationWaiter(
                client=FakeActivationClient([published, *([retryable] * 10)]),
                clock=FakeClock(),
            ).wait(
                target,
                target_phase=ActivationPhase.ACTIVE,
                timeout_seconds=0.2,
                poll_interval_seconds=0.1,
                request_id="request-read-timeout-status",
            )
        )
    assert with_status.value.status is published


def test_system_activation_clock_uses_monotonic_time_and_async_delay() -> None:
    clock = SystemActivationClock()

    before = clock.monotonic()
    asyncio.run(clock.sleep(0.0))

    assert clock.monotonic() >= before


def test_waiter_does_not_accept_a_status_observed_after_its_deadline() -> None:
    clock = FakeClock()
    active = parsed_status(
        activation_document(
            "active",
            true_conditions=(
                "Published",
                "DeploymentReady",
                "ProbeReady",
                "RouteReady",
                "Healthy",
            ),
            active_at="2026-08-30T12:00:00Z",
        )
    )

    class LateClient:
        async def fetch_activation(
            self,
            target: ActivationTarget,
            *,
            request_id: str,
        ) -> ActivationStatus:
            del target, request_id
            clock.now += 121.0
            return active

    target = ActivationTarget(
        ref=REF,
        registry_digest=REGISTRY_DIGEST,
        artifact_digest=ARTIFACT_DIGEST,
    )

    with pytest.raises(ActivationTimeoutError) as timed_out:
        asyncio.run(
            ActivationWaiter(client=LateClient(), clock=clock).wait(
                target,
                target_phase=ActivationPhase.ACTIVE,
                timeout_seconds=120.0,
                poll_interval_seconds=2.0,
                request_id="request-late-status",
            )
        )

    assert timed_out.value.status is active
