"""Replaceable publication side-effect contracts."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import PreparedPublication, PublishedArtifact, PublishReceipt


@runtime_checkable
class TesserixPublicationClient(Protocol):
    """Delegated Agentic Registry operations owned by the `agentic` interface."""

    async def remote_validate(
        self,
        prepared: PreparedPublication,
        *,
        idempotency_key: str,
        request_id: str,
    ) -> None: ...

    async def publish(
        self,
        prepared: PreparedPublication,
        *,
        idempotency_key: str,
        request_id: str,
    ) -> PublishReceipt: ...

    async def fetch(
        self,
        prepared: PreparedPublication,
        *,
        request_id: str,
    ) -> PublishedArtifact: ...

    async def verify(
        self,
        artifact: PublishedArtifact,
        *,
        request_id: str,
    ) -> None: ...


@runtime_checkable
class OfficialPublicationClient(Protocol):
    """Explicit optional official MCP Registry publisher operations."""

    async def validate(self, prepared: PreparedPublication, *, request_id: str) -> None: ...

    async def publish(self, prepared: PreparedPublication, *, request_id: str) -> None: ...
