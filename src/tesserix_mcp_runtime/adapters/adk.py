"""Optional binding from an ADK exported session to Streamable HTTP."""

from __future__ import annotations

import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from importlib import import_module
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from typing import Protocol, cast

from mcp import types
from mcp.shared.exceptions import MCPError
from mcp_types.version import SUPPORTED_PROTOCOL_VERSIONS

from tesserix_mcp_runtime.adapters.streamable_http import (
    ProtocolCallResult,
    ProtocolToolDescriptor,
    StreamableHTTPProtocolSession,
)
from tesserix_mcp_runtime.contracts import CallContext, JsonValue

ADK_DISTRIBUTION = "tesserix-adk"
ADK_RELEASE = "0.53.1"


class ADKBridgeDependencyError(RuntimeError):
    """The optional bridge dependency is missing or is not the verified release."""


class _ADKView(Protocol):
    def resolve(self, name: str) -> object: ...


class _ADKDescriptor(Protocol):
    name: str
    description: str
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue] | None


class _ADKResult(Protocol):
    content: tuple[dict[str, JsonValue], ...]
    structured_content: dict[str, JsonValue] | None
    is_error: bool


class _ADKSession(Protocol):
    async def initialize(self) -> object: ...

    async def list_tools(self) -> tuple[_ADKDescriptor, ...]: ...

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        meta: Mapping[str, str],
        timeout_seconds: float,
    ) -> _ADKResult: ...

    async def close(self) -> None: ...


class _ADKServer(Protocol):
    @property
    def exports(self) -> tuple[str, ...]: ...

    def connect(
        self,
        *,
        headers: Mapping[str, str] | None = None,
        meta: Mapping[str, str] | None = None,
        authenticated: str | None = None,
        protocol_version: str,
    ) -> _ADKSession: ...


class _ADKServerFactory(Protocol):
    def __call__(
        self,
        view: object,
        *,
        exports: Sequence[str],
        name: str,
        version: str,
        per_tenant_calls: int,
        secrets: Sequence[str],
        protocol_versions: Collection[str],
        require_authenticated_tenant: bool,
    ) -> _ADKServer: ...


@dataclass(frozen=True, slots=True)
class _ADKBindings:
    view_type: type[object]
    auth_error_type: type[Exception]
    export_error_type: type[Exception]
    server: _ADKServerFactory
    published: Callable[[object], _ADKDescriptor]
    fingerprint: Callable[[_ADKDescriptor], str]
    meta_prefix: str


def _attribute(module_name: str, name: str) -> object:
    try:
        module = import_module(module_name)
    except ImportError as error:
        raise ADKBridgeDependencyError(
            f"{ADK_DISTRIBUTION} {ADK_RELEASE} cannot load the required bridge API"
        ) from error
    try:
        return getattr(module, name)
    except AttributeError as error:
        raise ADKBridgeDependencyError(
            f"{ADK_DISTRIBUTION} {ADK_RELEASE} does not expose the required bridge API"
        ) from error


def _load_adk() -> _ADKBindings:
    try:
        installed = distribution_version(ADK_DISTRIBUTION)
    except PackageNotFoundError as error:
        raise ADKBridgeDependencyError(
            "install tesserix-mcp-runtime[adk] to use the ADK bridge"
        ) from error
    if installed != ADK_RELEASE:
        raise ADKBridgeDependencyError(
            f"the ADK bridge requires {ADK_DISTRIBUTION}=={ADK_RELEASE}; found {installed}"
        )
    return _ADKBindings(
        view_type=cast(type[object], _attribute("tesserix_adk.tools", "AgentToolView")),
        auth_error_type=cast(
            type[Exception],
            _attribute("tesserix_adk.core", "McpAuthError"),
        ),
        export_error_type=cast(
            type[Exception],
            _attribute("tesserix_adk.adapters.mcp_server", "McpExportError"),
        ),
        server=cast(
            _ADKServerFactory,
            _attribute("tesserix_adk.adapters.mcp_server", "McpServer"),
        ),
        published=cast(
            Callable[[object], _ADKDescriptor],
            _attribute("tesserix_adk.adapters.mcp_server", "published"),
        ),
        fingerprint=cast(
            Callable[[_ADKDescriptor], str],
            _attribute("tesserix_adk.adapters.mcp_surface", "fingerprint"),
        ),
        meta_prefix=cast(str, _attribute("tesserix_adk.mcp", "META_PREFIX")),
    )


def _descriptor(
    descriptor: _ADKDescriptor,
    *,
    fingerprint: Callable[[_ADKDescriptor], str],
) -> ProtocolToolDescriptor:
    return ProtocolToolDescriptor(
        name=descriptor.name,
        description=descriptor.description,
        input_schema=descriptor.input_schema,
        output_schema=descriptor.output_schema,
        fingerprint=fingerprint(descriptor),
    )


def _trusted_meta(context: CallContext, *, prefix: str) -> dict[str, str]:
    meta = {
        f"{prefix}/tenant": context.tenant,
        f"{prefix}/subject": context.subject,
        f"{prefix}/run": context.run_id,
        f"{prefix}/scopes": " ".join(sorted(context.scopes)),
    }
    meta.update({f"{prefix}/{name}": value for name, value in context.trace.items()})
    if context.idempotency_key is not None:
        meta[f"{prefix}/idempotency-key"] = context.idempotency_key
    return meta


class _ADKStreamableHTTPSession:
    __slots__ = (
        "_auth_error_type",
        "_context",
        "_export_error_type",
        "_fingerprint",
        "_meta_prefix",
        "_session",
    )

    def __init__(
        self,
        session: _ADKSession,
        *,
        context: CallContext,
        auth_error_type: type[Exception],
        export_error_type: type[Exception],
        fingerprint: Callable[[_ADKDescriptor], str],
        meta_prefix: str,
    ) -> None:
        self._session = session
        self._context = context
        self._auth_error_type = auth_error_type
        self._export_error_type = export_error_type
        self._fingerprint = fingerprint
        self._meta_prefix = meta_prefix

    async def initialize(self) -> None:
        await self._session.initialize()

    async def list_tools(self) -> tuple[ProtocolToolDescriptor, ...]:
        return tuple(
            _descriptor(item, fingerprint=self._fingerprint)
            for item in await self._session.list_tools()
        )

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        meta: Mapping[str, JsonValue],
    ) -> ProtocolCallResult:
        tenant_key = f"{self._meta_prefix}/tenant"
        claimed_tenant = meta.get(tenant_key)
        remote_meta = {tenant_key: claimed_tenant} if isinstance(claimed_tenant, str) else {}
        deadline = self._context.deadline
        timeout_seconds = 300.0 if deadline is None else max(0.0, deadline - time.monotonic())
        try:
            result = await self._session.call_tool(
                name,
                arguments,
                meta=remote_meta,
                timeout_seconds=timeout_seconds,
            )
        except self._export_error_type as error:
            reason = getattr(getattr(error, "reason", None), "value", None)
            code = reason if isinstance(reason, str) else "export_refused"
            raise MCPError(
                types.INVALID_PARAMS,
                "Tool request refused",
                {"code": code},
            ) from None
        except self._auth_error_type as error:
            reason = getattr(getattr(error, "reason", None), "value", None)
            code = reason if isinstance(reason, str) else "unauthenticated"
            raise MCPError(
                types.INVALID_REQUEST,
                "Unauthorized",
                {"code": code},
            ) from None
        return ProtocolCallResult(
            content=tuple(result.content),
            structured_content=result.structured_content,
            is_error=result.is_error,
        )

    async def close(self) -> None:
        await self._session.close()


class ADKStreamableHTTPBridge:
    """Expose one immutable ADK tool view through the runtime's HTTP transport."""

    __slots__ = ("_bindings", "_server", "_tools")

    def __init__(
        self,
        view: object,
        *,
        exports: Sequence[str],
        name: str = "",
        version: str = "0",
        per_tenant_calls: int = 8,
        secrets: Sequence[str] = (),
    ) -> None:
        bindings = _load_adk()
        if not isinstance(view, bindings.view_type):
            raise TypeError("view must be an ADK AgentToolView")
        typed_view = cast(_ADKView, view)
        server = bindings.server(
            view,
            exports=exports,
            name=name,
            version=version,
            per_tenant_calls=per_tenant_calls,
            secrets=secrets,
            protocol_versions=SUPPORTED_PROTOCOL_VERSIONS,
            require_authenticated_tenant=True,
        )
        self._bindings = bindings
        self._server = server
        self._tools = tuple(
            _descriptor(
                bindings.published(typed_view.resolve(export)),
                fingerprint=bindings.fingerprint,
            )
            for export in server.exports
        )

    def protocol_tools(self) -> tuple[ProtocolToolDescriptor, ...]:
        return self._tools

    def connect(
        self,
        *,
        context: CallContext,
        protocol_version: str,
    ) -> StreamableHTTPProtocolSession:
        prefix = self._bindings.meta_prefix
        session = self._server.connect(
            meta=_trusted_meta(context, prefix=prefix),
            authenticated=context.tenant,
            protocol_version=protocol_version,
        )
        return _ADKStreamableHTTPSession(
            session,
            context=context,
            auth_error_type=self._bindings.auth_error_type,
            export_error_type=self._bindings.export_error_type,
            fingerprint=self._bindings.fingerprint,
            meta_prefix=prefix,
        )


__all__ = [
    "ADK_DISTRIBUTION",
    "ADK_RELEASE",
    "ADKBridgeDependencyError",
    "ADKStreamableHTTPBridge",
]
