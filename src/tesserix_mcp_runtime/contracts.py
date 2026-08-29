"""Dependency-free contracts shared by runtime composition and adapters."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

type JsonValue = (
    str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
)


@runtime_checkable
class CallContext(Protocol):
    """Authenticated, immutable authority carried with one tool call."""

    @property
    def request_id(self) -> str: ...

    @property
    def run_id(self) -> str: ...

    @property
    def tenant(self) -> str: ...

    @property
    def subject(self) -> str | None: ...

    @property
    def issuer(self) -> str: ...

    @property
    def scopes(self) -> tuple[str, ...]: ...

    @property
    def trace(self) -> Mapping[str, str]: ...

    @property
    def deadline(self) -> float | None: ...

    @property
    def idempotency_key(self) -> str | None: ...

    @property
    def cancelled(self) -> bool: ...


@runtime_checkable
class Tool(Protocol):
    """One named capability invoked with model-visible JSON arguments."""

    @property
    def name(self) -> str: ...

    @property
    def input_schema(self) -> Mapping[str, JsonValue]: ...

    @property
    def output_schema(self) -> Mapping[str, JsonValue] | None: ...

    async def invoke(
        self,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> JsonValue: ...


@runtime_checkable
class Authorizer(Protocol):
    """Default-deny decision made immediately before one tool invocation."""

    async def authorize(
        self,
        *,
        tool: Tool,
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

    async def start(self) -> None: ...

    async def drain(self, *, deadline: float) -> None: ...

    async def stop(self) -> None: ...


__all__ = [
    "Authorizer",
    "CallContext",
    "Clock",
    "CredentialProvider",
    "JsonValue",
    "Lifecycle",
    "Telemetry",
    "Tool",
]
