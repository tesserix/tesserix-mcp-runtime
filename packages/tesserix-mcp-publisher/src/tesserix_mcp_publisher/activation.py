"""Digest-bound Gateway activation status contract."""

from __future__ import annotations

import asyncio
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol, Self, TypeGuard, cast, runtime_checkable

from tesserix_mcp_runtime import JsonValue

from .errors import PublicationError, PublicationErrorCode

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REF_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}"
_REF = re.compile(
    rf"mcpservers/{_REF_SEGMENT}/{_REF_SEGMENT}(?:/{_REF_SEGMENT})*"
    r"@[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z"
)
_REASON = re.compile(r"[A-Z][A-Za-z0-9]{0,63}\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}\Z")
_SCHEMA_VERSION = "v1alpha1"
_MAX_GENERATION = (1 << 63) - 1


class ActivationPhase(StrEnum):
    """One deterministic authoring-to-routing state."""

    DRAFT = "draft"
    PUBLISHED = "published"
    DEPLOYED = "deployed"
    PROBED = "probed"
    ACTIVE = "active"
    DEGRADED = "degraded"
    DEPRECATED = "deprecated"
    RETIRED = "retired"
    FAILED = "failed"


class ActivationDesiredState(StrEnum):
    """Registry-owned lifecycle intent, separate from process lifecycle."""

    DRAFT = "draft"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class ActivationConditionStatus(StrEnum):
    """Kubernetes-compatible condition truth value."""

    TRUE = "True"
    FALSE = "False"
    UNKNOWN = "Unknown"


class ActivationActor(StrEnum):
    """Exclusive writer identity for one activation condition."""

    REGISTRY = "registry"
    GATEWAY_RECONCILER = "gateway-reconciler"
    PROTOCOL_PROBER = "protocol-prober"


class ActivationConditionType(StrEnum):
    """Closed v1alpha1 condition vocabulary."""

    PUBLISHED = "Published"
    DEPLOYMENT_READY = "DeploymentReady"
    PROBE_READY = "ProbeReady"
    ROUTE_READY = "RouteReady"
    HEALTHY = "Healthy"
    FAILED = "Failed"


_CONDITION_OWNERS = {
    ActivationConditionType.PUBLISHED: ActivationActor.REGISTRY,
    ActivationConditionType.DEPLOYMENT_READY: ActivationActor.GATEWAY_RECONCILER,
    ActivationConditionType.PROBE_READY: ActivationActor.PROTOCOL_PROBER,
    ActivationConditionType.ROUTE_READY: ActivationActor.GATEWAY_RECONCILER,
    ActivationConditionType.HEALTHY: ActivationActor.PROTOCOL_PROBER,
    ActivationConditionType.FAILED: ActivationActor.REGISTRY,
}

_READINESS_SEQUENCE = (
    ActivationConditionType.PUBLISHED,
    ActivationConditionType.DEPLOYMENT_READY,
    ActivationConditionType.PROBE_READY,
    ActivationConditionType.HEALTHY,
    ActivationConditionType.ROUTE_READY,
)

_SUMMARIES = {
    ActivationPhase.DRAFT: "Artifact has not been committed to Registry.",
    ActivationPhase.PUBLISHED: (
        "Immutable Registry version exists; Gateway deployment has not been accepted."
    ),
    ActivationPhase.DEPLOYED: (
        "Digest-bound backend and probe route are accepted; authenticated probe is pending."
    ),
    ActivationPhase.PROBED: (
        "Authenticated MCP initialize and tools/list succeeded; public route promotion is pending."
    ),
    ActivationPhase.ACTIVE: (
        "Digest-bound deployment, probe, health, and public route are accepted."
    ),
    ActivationPhase.DEGRADED: (
        "A previously active version is unhealthy; last-known-good routing remains in effect."
    ),
    ActivationPhase.DEPRECATED: ("The version remains observable but is scheduled for retirement."),
    ActivationPhase.RETIRED: "The version is withdrawn and must not be routed or discovered.",
    ActivationPhase.FAILED: (
        "Activation ended before public routing; inspect condition reasons and request IDs."
    ),
}

_TOP_LEVEL_KEYS = frozenset(
    {
        "schemaVersion",
        "ref",
        "registryDigest",
        "artifactDigest",
        "generation",
        "desiredState",
        "phase",
        "publishedAt",
        "activeAt",
        "observedAt",
        "conditions",
    }
)
_CONDITION_KEYS = frozenset(
    {
        "type",
        "status",
        "actor",
        "reason",
        "observedGeneration",
        "registryDigest",
        "artifactDigest",
        "lastTransitionTime",
        "requestId",
    }
)


class ActivationContractError(PublicationError):
    """Registry returned a status that cannot safely drive activation."""

    def __init__(self, *, request_id: str = "activation-contract") -> None:
        super().__init__(PublicationErrorCode.ACTIVATION_CONTRACT_INVALID, request_id=request_id)


def _contract_error(request_id: str) -> ActivationContractError:
    return ActivationContractError(request_id=request_id)


def _is_runtime_instance(
    value: object,
    expected: type[Any] | tuple[type[Any], ...],
) -> bool:
    return isinstance(value, expected)


def _is_string_mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    if not isinstance(value, Mapping):
        return False
    mapping = cast(Mapping[object, object], value)
    return all(isinstance(key, str) for key in mapping)


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _mapping(value: object, *, request_id: str) -> Mapping[str, object]:
    if not _is_string_mapping(value):
        raise _contract_error(request_id)
    return value


def _text(
    value: object,
    *,
    pattern: re.Pattern[str],
    request_id: str,
) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _contract_error(request_id)
    return value


def _timestamp(value: object, *, request_id: str) -> datetime:
    if not isinstance(value, str) or len(value) > 32 or not value.endswith("Z"):
        raise _contract_error(request_id)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise _contract_error(request_id) from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise _contract_error(request_id)
    return parsed


def _optional_timestamp(value: object, *, request_id: str) -> datetime | None:
    if value is None:
        return None
    return _timestamp(value, request_id=request_id)


def _enum[EnumT: StrEnum](
    enum_type: type[EnumT],
    value: object,
    *,
    request_id: str,
) -> EnumT:
    if not isinstance(value, str):
        raise _contract_error(request_id)
    try:
        return enum_type(value)
    except ValueError as error:
        raise _contract_error(request_id) from error


def _format_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True, kw_only=True)
class ActivationTarget:
    """Exact immutable Registry and delivery identity a waiter follows."""

    ref: str
    registry_digest: str
    artifact_digest: str
    generation: int | None = None

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.ref, str)
            or len(self.ref) > 2_048
            or _REF.fullmatch(self.ref) is None
            or not _is_runtime_instance(self.registry_digest, str)
            or _DIGEST.fullmatch(self.registry_digest) is None
            or not _is_runtime_instance(self.artifact_digest, str)
            or _DIGEST.fullmatch(self.artifact_digest) is None
            or (
                self.generation is not None
                and (
                    not _is_runtime_instance(self.generation, int)
                    or isinstance(self.generation, bool)
                    or not 1 <= self.generation <= _MAX_GENERATION
                )
            )
        ):
            raise PublicationError(
                PublicationErrorCode.INVALID_ARGUMENT,
                request_id="activation-validation",
            )

    @property
    def namespace(self) -> str:
        return self.ref.removeprefix("mcpservers/").split("/", 1)[0]

    @property
    def name(self) -> str:
        name_and_version = self.ref.removeprefix("mcpservers/").split("/", 1)[1]
        return name_and_version.rsplit("@", 1)[0]

    @property
    def version(self) -> str:
        return self.ref.rsplit("@", 1)[1]


@dataclass(frozen=True, slots=True, kw_only=True)
class ActivationCondition:
    """One immutable actor-owned observation for the desired generation."""

    type: ActivationConditionType
    status: ActivationConditionStatus
    actor: ActivationActor
    reason: str
    observed_generation: int
    registry_digest: str
    artifact_digest: str
    last_transition_time: datetime
    request_id: str

    @classmethod
    def from_document(
        cls,
        value: object,
        *,
        request_id: str,
    ) -> Self:
        document = _mapping(value, request_id=request_id)
        if frozenset(document) != _CONDITION_KEYS:
            raise _contract_error(request_id)
        condition_type = _enum(
            ActivationConditionType,
            document["type"],
            request_id=request_id,
        )
        actor = _enum(ActivationActor, document["actor"], request_id=request_id)
        if actor is not _CONDITION_OWNERS[condition_type]:
            raise _contract_error(request_id)
        generation = document["observedGeneration"]
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or not 1 <= generation <= _MAX_GENERATION
        ):
            raise _contract_error(request_id)
        return cls(
            type=condition_type,
            status=_enum(
                ActivationConditionStatus,
                document["status"],
                request_id=request_id,
            ),
            actor=actor,
            reason=_text(document["reason"], pattern=_REASON, request_id=request_id),
            observed_generation=generation,
            registry_digest=_text(
                document["registryDigest"],
                pattern=_DIGEST,
                request_id=request_id,
            ),
            artifact_digest=_text(
                document["artifactDigest"],
                pattern=_DIGEST,
                request_id=request_id,
            ),
            last_transition_time=_timestamp(
                document["lastTransitionTime"],
                request_id=request_id,
            ),
            request_id=_text(
                document["requestId"],
                pattern=_REQUEST_ID,
                request_id=request_id,
            ),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ActivationStatus:
    """Validated v1alpha1 Registry projection for one immutable version."""

    ref: str
    registry_digest: str
    artifact_digest: str
    generation: int
    desired_state: ActivationDesiredState
    phase: ActivationPhase
    published_at: datetime | None
    active_at: datetime | None
    observed_at: datetime
    conditions: tuple[ActivationCondition, ...]

    @classmethod
    def from_document(
        cls,
        value: object,
        *,
        request_id: str = "activation-contract",
    ) -> Self:
        document = _mapping(value, request_id=request_id)
        if frozenset(document) != _TOP_LEVEL_KEYS or document["schemaVersion"] != _SCHEMA_VERSION:
            raise _contract_error(request_id)
        generation = document["generation"]
        raw_conditions = document["conditions"]
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or not 1 <= generation <= _MAX_GENERATION
            or not _is_object_list(raw_conditions)
            or len(raw_conditions) > len(ActivationConditionType)
        ):
            raise _contract_error(request_id)
        ref = _text(document["ref"], pattern=_REF, request_id=request_id)
        if len(ref) > 2_048:
            raise _contract_error(request_id)
        registry_digest = _text(document["registryDigest"], pattern=_DIGEST, request_id=request_id)
        artifact_digest = _text(document["artifactDigest"], pattern=_DIGEST, request_id=request_id)
        observed_at = _timestamp(document["observedAt"], request_id=request_id)
        conditions = tuple(
            ActivationCondition.from_document(item, request_id=request_id)
            for item in raw_conditions
        )
        condition_types = {condition.type for condition in conditions}
        if len(condition_types) != len(conditions):
            raise _contract_error(request_id)
        if any(
            condition.observed_generation != generation
            or condition.registry_digest != registry_digest
            or condition.artifact_digest != artifact_digest
            or condition.last_transition_time > observed_at
            for condition in conditions
        ):
            raise _contract_error(request_id)
        desired_state = _enum(
            ActivationDesiredState,
            document["desiredState"],
            request_id=request_id,
        )
        published_at = _optional_timestamp(document["publishedAt"], request_id=request_id)
        active_at = _optional_timestamp(document["activeAt"], request_id=request_id)
        if (
            (published_at is not None and published_at > observed_at)
            or (active_at is not None and active_at > observed_at)
            or (published_at is not None and active_at is not None and active_at < published_at)
        ):
            raise _contract_error(request_id)
        status = cls(
            ref=ref,
            registry_digest=registry_digest,
            artifact_digest=artifact_digest,
            generation=generation,
            desired_state=desired_state,
            phase=_enum(ActivationPhase, document["phase"], request_id=request_id),
            published_at=published_at,
            active_at=active_at,
            observed_at=observed_at,
            conditions=conditions,
        )
        if status._derived_phase(request_id=request_id) is not status.phase:
            raise _contract_error(request_id)
        return status

    def _condition_is_true(self, condition_type: ActivationConditionType) -> bool:
        return any(
            condition.type is condition_type and condition.status is ActivationConditionStatus.TRUE
            for condition in self.conditions
        )

    def _derived_phase(self, *, request_id: str) -> ActivationPhase:
        published = self._condition_is_true(ActivationConditionType.PUBLISHED)
        failed = self._condition_is_true(ActivationConditionType.FAILED)
        if self.desired_state is ActivationDesiredState.DRAFT:
            if self.published_at is not None or self.active_at is not None or published:
                raise _contract_error(request_id)
            return ActivationPhase.DRAFT
        if self.published_at is None or not published:
            raise _contract_error(request_id)
        if self.desired_state is ActivationDesiredState.RETIRED:
            if self.active_at is None:
                raise _contract_error(request_id)
            return ActivationPhase.RETIRED
        if self.desired_state is ActivationDesiredState.DEPRECATED:
            if self.active_at is None:
                raise _contract_error(request_id)
            return ActivationPhase.DEPRECATED
        if failed:
            if self.active_at is not None:
                raise _contract_error(request_id)
            return ActivationPhase.FAILED
        ready = all(self._condition_is_true(item) for item in _READINESS_SEQUENCE)
        if ready:
            if self.active_at is None:
                raise _contract_error(request_id)
            return ActivationPhase.ACTIVE
        if self.active_at is not None:
            return ActivationPhase.DEGRADED
        if (
            self._condition_is_true(ActivationConditionType.DEPLOYMENT_READY)
            and self._condition_is_true(ActivationConditionType.PROBE_READY)
            and self._condition_is_true(ActivationConditionType.HEALTHY)
        ):
            return ActivationPhase.PROBED
        if self._condition_is_true(ActivationConditionType.DEPLOYMENT_READY):
            return ActivationPhase.DEPLOYED
        return ActivationPhase.PUBLISHED

    def explain(self, *, request_id: str) -> dict[str, JsonValue]:
        """Return a bounded payload-free operator projection."""
        if _REQUEST_ID.fullmatch(request_id) is None:
            raise ValueError("request_id must be a bounded safe identifier")
        blocking: list[JsonValue] = [
            condition_type.value
            for condition_type in _READINESS_SEQUENCE
            if not self._condition_is_true(condition_type)
        ]
        condition_summaries: list[JsonValue] = [
            {
                "type": condition.type.value,
                "status": condition.status.value,
                "reason": condition.reason,
                "request_id": condition.request_id,
            }
            for condition in self.conditions
        ]
        return {
            "active_at": _format_timestamp(self.active_at),
            "artifact_digest": self.artifact_digest,
            "blocking_conditions": blocking,
            "conditions": condition_summaries,
            "desired_state": self.desired_state.value,
            "generation": self.generation,
            "observed_at": _format_timestamp(self.observed_at),
            "phase": self.phase.value,
            "published_at": _format_timestamp(self.published_at),
            "ref": self.ref,
            "registry_digest": self.registry_digest,
            "request_id": request_id,
            "retryable": self.phase
            not in {
                ActivationPhase.ACTIVE,
                ActivationPhase.DEPRECATED,
                ActivationPhase.RETIRED,
                ActivationPhase.FAILED,
            },
            "summary": _SUMMARIES[self.phase],
            "terminal": self.phase
            in {
                ActivationPhase.DEPRECATED,
                ActivationPhase.RETIRED,
                ActivationPhase.FAILED,
            },
        }


@runtime_checkable
class ActivationClient(Protocol):
    """Read one exact Registry activation projection."""

    async def fetch_activation(
        self,
        target: ActivationTarget,
        *,
        request_id: str,
    ) -> ActivationStatus: ...


@runtime_checkable
class ActivationClock(Protocol):
    """Injectable monotonic time and cancellation-aware delay."""

    def monotonic(self) -> float: ...

    async def sleep(self, delay: float) -> None: ...


class SystemActivationClock:
    """Production activation clock."""

    def monotonic(self) -> float:
        return time.monotonic()

    async def sleep(self, delay: float) -> None:
        await asyncio.sleep(delay)


class ActivationSupersededError(PublicationError):
    """The immutable wait target no longer matches observed status."""

    def __init__(self, *, request_id: str) -> None:
        super().__init__(PublicationErrorCode.ACTIVATION_SUPERSEDED, request_id=request_id)


class _ActivationWaitError(PublicationError):
    def __init__(
        self,
        code: PublicationErrorCode,
        *,
        status: ActivationStatus,
        request_id: str,
        retryable: bool,
    ) -> None:
        self.status = status
        super().__init__(code, request_id=request_id, retryable=retryable)

    def to_dict(self) -> dict[str, JsonValue]:
        document = super().to_dict()
        document["activation"] = self.status.explain(request_id=self.request_id)
        return document


class ActivationTerminalError(_ActivationWaitError):
    """The requested phase cannot follow the observed terminal phase."""

    def __init__(self, *, status: ActivationStatus, request_id: str) -> None:
        super().__init__(
            PublicationErrorCode.ACTIVATION_FAILED,
            status=status,
            request_id=request_id,
            retryable=False,
        )


class ActivationTimeoutError(_ActivationWaitError):
    """A bounded wait expired and retains only its safe final projection."""

    def __init__(self, *, status: ActivationStatus, request_id: str) -> None:
        super().__init__(
            PublicationErrorCode.ACTIVATION_TIMEOUT,
            status=status,
            request_id=request_id,
            retryable=True,
        )


_PROGRESS_RANK = {
    ActivationPhase.DRAFT: 0,
    ActivationPhase.PUBLISHED: 1,
    ActivationPhase.DEPLOYED: 2,
    ActivationPhase.PROBED: 3,
    ActivationPhase.ACTIVE: 4,
}


class ActivationWaiter:
    """Poll exact activation status under one monotonic deadline."""

    def __init__(
        self,
        *,
        client: ActivationClient,
        clock: ActivationClock | None = None,
    ) -> None:
        if not _is_runtime_instance(client, ActivationClient):
            raise TypeError("client must implement ActivationClient")
        resolved_clock = SystemActivationClock() if clock is None else clock
        if not _is_runtime_instance(resolved_clock, ActivationClock):
            raise TypeError("clock must implement ActivationClock")
        self._client = client
        self._clock = resolved_clock

    @staticmethod
    def _validate_identity(
        *,
        target: ActivationTarget,
        request_id: str,
    ) -> None:
        if (
            not _is_runtime_instance(target, ActivationTarget)
            or not _is_runtime_instance(request_id, str)
            or _REQUEST_ID.fullmatch(request_id) is None
        ):
            raise PublicationError(
                PublicationErrorCode.INVALID_ARGUMENT,
                request_id=(
                    request_id
                    if _is_runtime_instance(request_id, str) and _REQUEST_ID.fullmatch(request_id)
                    else "activation-validation"
                ),
            )

    @staticmethod
    def _validate_parameters(
        *,
        target: ActivationTarget,
        target_phase: ActivationPhase,
        timeout_seconds: float,
        poll_interval_seconds: float,
        request_id: str,
    ) -> None:
        ActivationWaiter._validate_identity(target=target, request_id=request_id)
        if (
            not _is_runtime_instance(target_phase, ActivationPhase)
            or _is_runtime_instance(timeout_seconds, bool)
            or not _is_runtime_instance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0.1 <= timeout_seconds <= 900.0
            or _is_runtime_instance(poll_interval_seconds, bool)
            or not _is_runtime_instance(poll_interval_seconds, (int, float))
            or not math.isfinite(poll_interval_seconds)
            or not 0.1 <= poll_interval_seconds <= 30.0
            or poll_interval_seconds > timeout_seconds
        ):
            raise PublicationError(
                PublicationErrorCode.INVALID_ARGUMENT,
                request_id=request_id,
            )

    @staticmethod
    def _matches_target(
        status: ActivationStatus,
        target: ActivationTarget,
        *,
        generation: int,
    ) -> bool:
        return (
            status.ref == target.ref
            and status.registry_digest == target.registry_digest
            and status.artifact_digest == target.artifact_digest
            and status.generation == generation
        )

    @staticmethod
    def _reached(actual: ActivationPhase, target: ActivationPhase) -> bool:
        if actual is target:
            return True
        if actual not in _PROGRESS_RANK or target not in _PROGRESS_RANK:
            return False
        return _PROGRESS_RANK[actual] >= _PROGRESS_RANK[target]

    async def observe(
        self,
        target: ActivationTarget,
        *,
        request_id: str,
    ) -> ActivationStatus:
        """Read and verify one exact activation projection without polling."""
        self._validate_identity(target=target, request_id=request_id)
        status = await self._client.fetch_activation(target, request_id=request_id)
        generation = target.generation if target.generation is not None else status.generation
        if not self._matches_target(status, target, generation=generation):
            raise ActivationSupersededError(request_id=request_id)
        return status

    async def wait(
        self,
        target: ActivationTarget,
        *,
        target_phase: ActivationPhase,
        timeout_seconds: float,
        poll_interval_seconds: float,
        request_id: str,
    ) -> ActivationStatus:
        self._validate_parameters(
            target=target,
            target_phase=target_phase,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
            request_id=request_id,
        )
        deadline = self._clock.monotonic() + timeout_seconds
        generation = target.generation
        last_status: ActivationStatus | None = None
        last_observed_at: datetime | None = None
        while True:
            remaining = deadline - self._clock.monotonic()
            if remaining <= 0:
                if last_status is not None:
                    raise ActivationTimeoutError(
                        status=last_status,
                        request_id=request_id,
                    )
                raise PublicationError(
                    PublicationErrorCode.ACTIVATION_TIMEOUT,
                    request_id=request_id,
                    retryable=True,
                )
            try:
                async with asyncio.timeout(remaining):
                    status = await self._client.fetch_activation(
                        target,
                        request_id=request_id,
                    )
            except TimeoutError as error:
                if last_status is not None:
                    raise ActivationTimeoutError(
                        status=last_status,
                        request_id=request_id,
                    ) from error
                raise PublicationError(
                    PublicationErrorCode.ACTIVATION_TIMEOUT,
                    request_id=request_id,
                    retryable=True,
                ) from error
            except PublicationError as error:
                if not error.retryable:
                    raise
                remaining = deadline - self._clock.monotonic()
                if remaining <= 0:
                    if last_status is not None:
                        raise ActivationTimeoutError(
                            status=last_status,
                            request_id=request_id,
                        ) from error
                    raise PublicationError(
                        PublicationErrorCode.ACTIVATION_TIMEOUT,
                        request_id=request_id,
                        retryable=True,
                    ) from error
                await self._clock.sleep(min(poll_interval_seconds, remaining))
                continue
            last_status = status
            if deadline - self._clock.monotonic() <= 0:
                raise ActivationTimeoutError(status=status, request_id=request_id)
            if last_observed_at is not None and status.observed_at < last_observed_at:
                raise ActivationContractError(request_id=request_id)
            last_observed_at = status.observed_at
            if generation is None:
                generation = status.generation
            if not self._matches_target(status, target, generation=generation):
                raise ActivationSupersededError(request_id=request_id)
            if self._reached(status.phase, target_phase):
                return status
            if status.phase in {
                ActivationPhase.DEPRECATED,
                ActivationPhase.RETIRED,
                ActivationPhase.FAILED,
            }:
                raise ActivationTerminalError(status=status, request_id=request_id)
            remaining = deadline - self._clock.monotonic()
            if remaining <= 0:
                raise ActivationTimeoutError(status=status, request_id=request_id)
            await self._clock.sleep(min(poll_interval_seconds, remaining))
