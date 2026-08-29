from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from types import SimpleNamespace

import pytest
from mcp.shared.exceptions import MCPError
from mcp_types.version import SUPPORTED_PROTOCOL_VERSIONS

from tesserix_mcp_runtime import AuthenticatedIdentity, CallContext, JsonValue, TraceContext
from tesserix_mcp_runtime.adapters import adk


@dataclass(frozen=True)
class _Tool:
    name: str
    mode: str = "success"


@dataclass(frozen=True)
class _Descriptor:
    name: str
    description: str
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue] | None


@dataclass(frozen=True)
class _Result:
    content: tuple[dict[str, JsonValue], ...]
    structured_content: dict[str, JsonValue] | None
    is_error: bool


class _Reason:
    def __init__(self, value: str) -> None:
        self.value = value


class _ExportError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = _Reason(reason)
        super().__init__("private export detail")


class _AuthError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = _Reason(reason)
        super().__init__("private auth detail")


class _View:
    def __init__(self, tools: tuple[_Tool, ...]) -> None:
        self._tools = {tool.name: tool for tool in tools}

    def resolve(self, name: str) -> _Tool:
        try:
            return self._tools[name]
        except KeyError:
            raise _ExportError("not_found") from None


def _published(tool: object) -> _Descriptor:
    assert isinstance(tool, _Tool)
    return _Descriptor(
        name=tool.name,
        description=f"Tool {tool.name}",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
    )


def _fingerprint(descriptor: _Descriptor) -> str:
    return f"fingerprint:{descriptor.name}"


class _Session:
    def __init__(self, server: _Server, protocol_version: str) -> None:
        self._server = server
        self._protocol_version = protocol_version
        self.closed = False
        self.calls: list[tuple[str, MappingSnapshot, float]] = []

    async def initialize(self) -> object:
        return {"protocol_version": self._protocol_version}

    async def list_tools(self) -> tuple[_Descriptor, ...]:
        return tuple(_published(self._server.view.resolve(name)) for name in self._server.exports)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, JsonValue],
        *,
        meta: dict[str, str],
        timeout_seconds: float,
    ) -> _Result:
        tool = self._server.view.resolve(name)
        self.calls.append((name, MappingSnapshot(arguments, meta), timeout_seconds))
        if tool.mode == "export_error":
            raise _ExportError("not_found")
        if tool.mode == "auth_error":
            raise _AuthError("unauthenticated")
        return _Result(
            content=({"type": "text", "text": "ok"},),
            structured_content={"ok": True},
            is_error=False,
        )

    async def close(self) -> None:
        self.closed = True


@dataclass(frozen=True)
class MappingSnapshot:
    arguments: dict[str, JsonValue]
    meta: dict[str, str]


class _Server:
    latest: _Server | None = None

    def __init__(
        self,
        view: object,
        *,
        exports: tuple[str, ...],
        name: str,
        version: str,
        per_tenant_calls: int,
        secrets: tuple[str, ...],
        protocol_versions: tuple[str, ...],
        require_authenticated_tenant: bool,
    ) -> None:
        assert isinstance(view, _View)
        for exported in exports:
            view.resolve(exported)
        self.view = view
        self.exports = tuple(dict.fromkeys(exports))
        self.name = name
        self.version = version
        self.per_tenant_calls = per_tenant_calls
        self.secrets = secrets
        self.protocol_versions = protocol_versions
        self.require_authenticated_tenant = require_authenticated_tenant
        self.connected: list[dict[str, object]] = []
        self.sessions: list[_Session] = []
        type(self).latest = self

    def connect(
        self,
        *,
        headers: dict[str, str] | None = None,
        meta: dict[str, str] | None = None,
        authenticated: str | None = None,
        protocol_version: str,
    ) -> _Session:
        self.connected.append(
            {
                "headers": headers,
                "meta": meta,
                "authenticated": authenticated,
                "protocol_version": protocol_version,
            }
        )
        session = _Session(self, protocol_version)
        self.sessions.append(session)
        return session


def _fake_adk(monkeypatch: pytest.MonkeyPatch) -> None:
    modules = {
        "tesserix_adk.tools": SimpleNamespace(AgentToolView=_View),
        "tesserix_adk.core": SimpleNamespace(McpAuthError=_AuthError),
        "tesserix_adk.adapters.mcp_server": SimpleNamespace(
            McpExportError=_ExportError,
            McpServer=_Server,
            published=_published,
        ),
        "tesserix_adk.adapters.mcp_surface": SimpleNamespace(fingerprint=_fingerprint),
        "tesserix_adk.mcp": SimpleNamespace(META_PREFIX="tesserix/adk"),
    }

    def exact_release(distribution: str) -> str:
        del distribution
        return adk.ADK_RELEASE

    monkeypatch.setattr(adk, "distribution_version", exact_release)
    monkeypatch.setattr(adk, "import_module", modules.__getitem__)


def _context() -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant="acme",
            subject="ada",
            issuer="https://gateway.internal.example",
            scopes=("fares:read",),
        ),
        request_id="request-1",
        run_id="run-1",
        trace_context=TraceContext(
            traceparent="00-11111111111111111111111111111111-1111111111111111-01"
        ),
        idempotency_key="idempotency-example",
    )


def test_bridge_delegates_to_the_exact_adk_session_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_adk(monkeypatch)
    bridge = adk.ADKStreamableHTTPBridge(
        _View((_Tool("fare_for"),)),
        exports=("fare_for",),
        name="fares",
        version="1.2.0",
        per_tenant_calls=3,
        secrets=("secret-value",),
    )
    descriptor = bridge.protocol_tools()[0]
    assert descriptor.name == "fare_for"
    assert descriptor.fingerprint == "fingerprint:fare_for"
    server = _Server.latest
    assert server is not None
    assert server.protocol_versions == SUPPORTED_PROTOCOL_VERSIONS
    assert server.require_authenticated_tenant is True

    async def exercise() -> None:
        session = bridge.connect(context=_context(), protocol_version="2025-11-25")
        await session.initialize()
        assert await session.list_tools() == bridge.protocol_tools()
        result = await session.call_tool(
            "fare_for",
            {"leg": "Osaka"},
            meta={
                "tesserix/adk/tenant": "acme",
                "tesserix/adk/subject": "untrusted",
            },
        )
        assert result.structured_content == {"ok": True}
        await session.close()

    asyncio.run(exercise())
    assert server.connected == [
        {
            "headers": None,
            "meta": {
                "tesserix/adk/tenant": "acme",
                "tesserix/adk/subject": "ada",
                "tesserix/adk/run": "run-1",
                "tesserix/adk/scopes": "fares:read",
                "tesserix/adk/traceparent": (
                    "00-11111111111111111111111111111111-1111111111111111-01"
                ),
                "tesserix/adk/idempotency-key": "idempotency-example",
            },
            "authenticated": "acme",
            "protocol_version": "2025-11-25",
        }
    ]
    session = server.sessions[0]
    assert session.calls[0][1].meta == {"tesserix/adk/tenant": "acme"}
    assert session.closed is True


@pytest.mark.parametrize(
    ("mode", "expected_code", "expected_message"),
    [
        ("export_error", "not_found", "Tool request refused"),
        ("auth_error", "unauthenticated", "Unauthorized"),
    ],
)
def test_bridge_maps_adk_boundary_errors_without_private_text(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_code: str,
    expected_message: str,
) -> None:
    _fake_adk(monkeypatch)
    bridge = adk.ADKStreamableHTTPBridge(
        _View((_Tool("guarded", mode=mode),)),
        exports=("guarded",),
    )

    async def exercise() -> None:
        session = bridge.connect(context=_context(), protocol_version="2025-11-25")
        with pytest.raises(MCPError) as raised:
            await session.call_tool("guarded", {}, meta={})
        assert str(raised.value) == expected_message
        assert raised.value.error.data == {"code": expected_code}

    asyncio.run(exercise())


def test_bridge_fails_only_when_the_optional_adk_release_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(distribution: str) -> str:
        raise PackageNotFoundError(distribution)

    monkeypatch.setattr(adk, "distribution_version", missing)

    with pytest.raises(adk.ADKBridgeDependencyError, match=r"runtime\[adk\]"):
        adk.ADKStreamableHTTPBridge(object(), exports=())


def test_bridge_rejects_an_unverified_adk_release(monkeypatch: pytest.MonkeyPatch) -> None:
    def unverified_release(distribution: str) -> str:
        del distribution
        return "0.54.0"

    monkeypatch.setattr(adk, "distribution_version", unverified_release)

    with pytest.raises(adk.ADKBridgeDependencyError, match=r"found 0\.54\.0"):
        adk.ADKStreamableHTTPBridge(object(), exports=())


def test_bridge_rejects_a_non_adk_view(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_adk(monkeypatch)

    with pytest.raises(TypeError, match="AgentToolView"):
        adk.ADKStreamableHTTPBridge(object(), exports=())


def test_bridge_reports_a_missing_required_adk_api(monkeypatch: pytest.MonkeyPatch) -> None:
    def exact_release(distribution: str) -> str:
        del distribution
        return adk.ADK_RELEASE

    def empty_module(module: str) -> SimpleNamespace:
        del module
        return SimpleNamespace()

    monkeypatch.setattr(adk, "distribution_version", exact_release)
    monkeypatch.setattr(adk, "import_module", empty_module)

    with pytest.raises(adk.ADKBridgeDependencyError, match="required bridge API"):
        adk.ADKStreamableHTTPBridge(object(), exports=())


def test_bridge_reports_an_unloadable_exact_adk_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exact_release(distribution: str) -> str:
        del distribution
        return adk.ADK_RELEASE

    def unloadable(module: str) -> SimpleNamespace:
        del module
        raise ImportError("private import detail")

    monkeypatch.setattr(adk, "distribution_version", exact_release)
    monkeypatch.setattr(adk, "import_module", unloadable)

    with pytest.raises(adk.ADKBridgeDependencyError, match="cannot load the required bridge API"):
        adk.ADKStreamableHTTPBridge(object(), exports=())
