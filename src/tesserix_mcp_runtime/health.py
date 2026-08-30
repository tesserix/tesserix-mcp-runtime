"""Operational health and metrics contracts shared by runtime transports."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ReadinessCheck(Protocol):
    @property
    def name(self) -> str: ...

    async def ready(self) -> bool: ...


@runtime_checkable
class RuntimeOperationsEndpoint(Protocol):
    def startup_status(self) -> bool: ...

    def liveness_status(self) -> bool: ...

    async def readiness_status(self) -> bool: ...

    def render_metrics(self) -> str: ...


__all__ = ["ReadinessCheck", "RuntimeOperationsEndpoint"]
