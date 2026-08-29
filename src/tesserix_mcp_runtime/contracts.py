"""Dependency-free contracts shared by runtime composition and adapters."""

from __future__ import annotations

import asyncio
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

type JsonValue = str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None


@runtime_checkable
class Cancellation(Protocol):
    """Expose cancellation without coupling handlers to an async framework."""

    @property
    def cancelled(self) -> bool: ...

    async def wait(self) -> None: ...


class _NeverCancelled:
    @property
    def cancelled(self) -> bool:
        return False

    async def wait(self) -> None:
        await asyncio.Future()


_NEVER_CANCELLED = _NeverCancelled()
_TOOL_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")
_SCOPE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}\Z")
_TRACEPARENT_V00 = re.compile(r"00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}\Z")
_TRACESTATE_KEY = re.compile(
    r"(?:[a-z][a-z0-9_*/-]{0,255}|"
    r"[a-z][a-z0-9_*/-]{0,240}@[a-z][a-z0-9_*/-]{0,13})\Z"
)


def _require_text(name: str, value: object, *, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{name} must be bounded, non-empty text")


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


def validate_deadline(value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError("deadline must be a finite monotonic timestamp")


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthenticatedIdentity:
    """Identity values produced by a trusted transport adapter."""

    tenant: str
    subject: str
    issuer: str
    scopes: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text("tenant", self.tenant, maximum=256)
        _require_text("subject", self.subject, maximum=512)
        _require_text("issuer", self.issuer, maximum=2048)
        if not _is_runtime_instance(self.scopes, tuple):
            raise ValueError("scopes must be an immutable tuple")
        for scope in self.scopes:
            _require_text("scope", scope, maximum=256)
        if len(set(self.scopes)) != len(self.scopes):
            raise ValueError("scopes must not contain duplicates")


@dataclass(frozen=True, slots=True, kw_only=True)
class TraceContext:
    """Immutable W3C trace propagation fields for one call."""

    traceparent: str | None = None
    tracestate: str | None = None

    def __post_init__(self) -> None:
        if self.traceparent is None:
            if self.tracestate is not None:
                raise ValueError("tracestate requires traceparent")
            return
        _require_text("traceparent", self.traceparent, maximum=55)
        matched = _TRACEPARENT_V00.fullmatch(self.traceparent)
        if matched is None:
            raise ValueError("traceparent must be a valid W3C version 00 value")
        if matched.group(1) == "0" * 32 or matched.group(2) == "0" * 16:
            raise ValueError("traceparent identifiers must be non-zero")
        if self.tracestate is not None:
            self._validate_tracestate()

    def _validate_tracestate(self) -> None:
        tracestate = self.tracestate
        if tracestate is None:
            return
        _require_text("tracestate", tracestate, maximum=512)
        members = tracestate.split(",")
        if len(members) > 32:
            raise ValueError("tracestate must contain at most 32 members")
        keys: set[str] = set()
        for member in members:
            key, separator, value = member.strip(" ").partition("=")
            if (
                separator != "="
                or _TRACESTATE_KEY.fullmatch(key) is None
                or not 1 <= len(value) <= 256
                or value[-1] == " "
                or any(
                    character in {",", "="} or not 0x20 <= ord(character) <= 0x7E
                    for character in value
                )
                or key in keys
            ):
                raise ValueError("tracestate must contain valid unique members")
            keys.add(key)

    def as_mapping(self) -> Mapping[str, str]:
        values = {
            name: value
            for name, value in (
                ("traceparent", self.traceparent),
                ("tracestate", self.tracestate),
            )
            if value is not None
        }
        return MappingProxyType(values)


@dataclass(frozen=True, slots=True, kw_only=True)
class CallContext:
    """Authenticated, immutable authority carried with one tool call."""

    identity: AuthenticatedIdentity
    request_id: str
    run_id: str
    trace_context: TraceContext = TraceContext()
    deadline: float | None = None
    cancellation: Cancellation = _NEVER_CANCELLED
    idempotency_key: str | None = None

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.identity, AuthenticatedIdentity):
            raise ValueError("identity must come from the authenticated boundary")
        _require_text("request_id", self.request_id, maximum=256)
        _require_text("run_id", self.run_id, maximum=256)
        if not _is_runtime_instance(self.trace_context, TraceContext):
            raise ValueError("trace_context must be immutable")
        if self.deadline is not None:
            validate_deadline(self.deadline)
        if not _is_runtime_instance(self.cancellation, Cancellation):
            raise ValueError("cancellation must implement the cancellation contract")
        if self.idempotency_key is not None:
            _require_text("idempotency_key", self.idempotency_key, maximum=512)

    @property
    def tenant(self) -> str:
        return self.identity.tenant

    @property
    def subject(self) -> str:
        return self.identity.subject

    @property
    def issuer(self) -> str:
        return self.identity.issuer

    @property
    def scopes(self) -> tuple[str, ...]:
        return self.identity.scopes

    @property
    def trace(self) -> Mapping[str, str]:
        return self.trace_context.as_mapping()

    @property
    def cancelled(self) -> bool:
        return self.cancellation.cancelled


class ToolEffect(StrEnum):
    READ = "read"
    WRITE = "write"
    EXTERNAL_EFFECT = "external_effect"


class ApprovalRequirement(StrEnum):
    NOT_REQUIRED = "not_required"
    REQUIRED = "required"


class IdempotencyRequirement(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    REQUIRED = "required"


class ErrorCode(StrEnum):
    INVALID_INPUT = "invalid_input"
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    APPROVAL_REQUIRED = "approval_required"
    CONFLICT = "conflict"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNAVAILABLE = "unavailable"
    INTERNAL_FAILURE = "internal_failure"


class Retryability(StrEnum):
    NEVER = "never"
    SAFE_OR_IDEMPOTENT = "safe_or_idempotent"


class InvocationStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class LifecycleState(StrEnum):
    STARTUP = "startup"
    READY = "ready"
    DRAINING = "draining"
    STOPPED = "stopped"


_ERROR_MESSAGES = {
    ErrorCode.INVALID_INPUT: "The request is invalid.",
    ErrorCode.UNAUTHENTICATED: "Authentication is required.",
    ErrorCode.FORBIDDEN: "The operation is not permitted.",
    ErrorCode.APPROVAL_REQUIRED: "Approval is required.",
    ErrorCode.CONFLICT: "The operation conflicts with current state.",
    ErrorCode.TIMEOUT: "The operation timed out.",
    ErrorCode.CANCELLED: "The operation was cancelled.",
    ErrorCode.UNAVAILABLE: "A required dependency is unavailable.",
    ErrorCode.INTERNAL_FAILURE: "The operation failed.",
}
_ERROR_RETRYABILITY = {
    code: (
        Retryability.SAFE_OR_IDEMPOTENT
        if code in {ErrorCode.TIMEOUT, ErrorCode.UNAVAILABLE}
        else Retryability.NEVER
    )
    for code in ErrorCode
}


@dataclass(frozen=True, slots=True, kw_only=True)
class ErrorResponse:
    """Stable, payload-free error data safe to serialize to a caller."""

    code: ErrorCode
    message: str
    request_id: str
    retryability: Retryability

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.code, ErrorCode):
            raise ValueError("code must be a stable ErrorCode")
        if self.message != _ERROR_MESSAGES[self.code]:
            raise ValueError("message must use the stable public text")
        _require_text("request_id", self.request_id, maximum=256)
        if self.retryability is not _ERROR_RETRYABILITY[self.code]:
            raise ValueError("retryability must match the stable error policy")

    @classmethod
    def from_code(cls, code: ErrorCode, *, request_id: str) -> ErrorResponse:
        if not _is_runtime_instance(code, ErrorCode):
            raise ValueError("code must be a stable ErrorCode")
        _require_text("request_id", request_id, maximum=256)
        return cls(
            code=code,
            message=_ERROR_MESSAGES[code],
            request_id=request_id,
            retryability=_ERROR_RETRYABILITY[code],
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "code": self.code.value,
            "message": self.message,
            "request_id": self.request_id,
            "retryability": self.retryability.value,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class InvocationResult:
    """Exactly one terminal success value or stable public failure."""

    status: InvocationStatus
    value: JsonValue
    error: ErrorResponse | None

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.status, InvocationStatus):
            raise ValueError("status must be a stable InvocationStatus")
        if self.status is InvocationStatus.SUCCESS and self.error is not None:
            raise ValueError("a successful result cannot contain an error")
        if self.status is InvocationStatus.FAILURE and (
            not isinstance(self.error, ErrorResponse) or self.value is not None
        ):
            raise ValueError("a failed result must contain only one public error")

    @classmethod
    def success(cls, value: JsonValue) -> InvocationResult:
        return cls(status=InvocationStatus.SUCCESS, value=value, error=None)

    @classmethod
    def failure(cls, error: ErrorResponse) -> InvocationResult:
        return cls(status=InvocationStatus.FAILURE, value=None, error=error)


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolMetadata:
    """Bounded policy metadata reviewed with one tool definition."""

    name: str
    title: str
    description: str
    effect: ToolEffect
    approval: ApprovalRequirement
    idempotency: IdempotencyRequirement
    required_scopes: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text("name", self.name, maximum=128)
        if _TOOL_NAME.fullmatch(self.name) is None:
            raise ValueError("name contains unsupported characters")
        _require_text("title", self.title, maximum=128)
        _require_text("description", self.description, maximum=2048)
        if not _is_runtime_instance(self.effect, ToolEffect):
            raise ValueError("effect must be a supported ToolEffect")
        if not _is_runtime_instance(self.approval, ApprovalRequirement):
            raise ValueError("approval must be explicit")
        if not _is_runtime_instance(self.idempotency, IdempotencyRequirement):
            raise ValueError("idempotency must be explicit")
        if not _is_runtime_instance(self.required_scopes, tuple):
            raise ValueError("required_scopes must be an immutable tuple")
        for scope in self.required_scopes:
            _require_text("scope", scope, maximum=256)
            if _SCOPE_NAME.fullmatch(scope) is None:
                raise ValueError("scope contains unsupported characters")
        if len(set(self.required_scopes)) != len(self.required_scopes):
            raise ValueError("required_scopes must not contain duplicates")
        if (
            self.effect is not ToolEffect.READ
            and self.idempotency is not IdempotencyRequirement.REQUIRED
        ):
            raise ValueError("write and external effects require idempotency")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "effect": self.effect.value,
            "approval": self.approval.value,
            "idempotency": self.idempotency.value,
            "required_scopes": list(self.required_scopes),
        }


@runtime_checkable
class ToolHandler[InputT, OutputT](Protocol):
    """Invoke one typed tool without transport-specific values."""

    async def __call__(
        self,
        input_model: InputT,
        *,
        context: CallContext,
    ) -> OutputT: ...


@runtime_checkable
class ToolDefinition[InputT, OutputT](Protocol):
    """Describe typed conversion and behavior for one exposed tool."""

    @property
    def metadata(self) -> ToolMetadata: ...

    @property
    def input_schema(self) -> Mapping[str, JsonValue]: ...

    @property
    def output_schema(self) -> Mapping[str, JsonValue]: ...

    @property
    def handler(self) -> ToolHandler[InputT, OutputT]: ...

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> InputT: ...

    def serialize_output(self, output_model: OutputT) -> JsonValue: ...


@runtime_checkable
class Authorizer(Protocol):
    """Default-deny decision made immediately before one tool invocation."""

    async def authorize(
        self,
        *,
        tool: ToolDefinition[Any, Any],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None: ...


@runtime_checkable
class CredentialProvider[CredentialT](Protocol):
    """Issue a narrowly scoped downstream credential for one call."""

    async def issue(
        self,
        *,
        audience: str,
        scopes: tuple[str, ...],
        context: CallContext,
    ) -> CredentialT: ...


@runtime_checkable
class Telemetry[EventT](Protocol):
    """Accept a safe event without coupling core to an exporter."""

    def emit(self, event: EventT) -> None: ...


@runtime_checkable
class Clock(Protocol):
    """Provide monotonic time and cancellable sleeps."""

    def now(self) -> float: ...

    async def sleep(self, seconds: float) -> None: ...


@runtime_checkable
class Lifecycle(Protocol):
    """Own startup, traffic drain, and resource shutdown."""

    @property
    def name(self) -> str: ...

    async def start(self) -> None: ...

    async def drain(self, *, deadline: float) -> None: ...

    async def stop(self) -> None: ...


__all__ = [
    "ApprovalRequirement",
    "AuthenticatedIdentity",
    "Authorizer",
    "CallContext",
    "Cancellation",
    "Clock",
    "CredentialProvider",
    "ErrorCode",
    "ErrorResponse",
    "IdempotencyRequirement",
    "InvocationResult",
    "InvocationStatus",
    "JsonValue",
    "Lifecycle",
    "LifecycleState",
    "Retryability",
    "Telemetry",
    "ToolDefinition",
    "ToolEffect",
    "ToolHandler",
    "ToolMetadata",
    "TraceContext",
]
