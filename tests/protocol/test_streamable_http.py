from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any, ClassVar, cast

import httpx2 as httpx
import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from jwt.algorithms import RSAAlgorithm
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.types import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    UNSUPPORTED_PROTOCOL_VERSION,
    PaginatedRequestParams,
    RequestParamsMeta,
)

from tesserix_mcp_runtime import (
    ApprovalRequirement,
    AuthenticatedIdentity,
    CallContext,
    Cancellation,
    IdempotencyRequirement,
    InvocationResult,
    JsonValue,
    ToolEffect,
    ToolManifest,
    ToolMetadata,
    TraceContext,
)
from tesserix_mcp_runtime.adapters.gateway_identity import (
    GatewayIdentityConfig,
    GatewayJWTContextProvider,
)
from tesserix_mcp_runtime.adapters.streamable_http import (
    HTTPCallContextProvider,
    HTTPRequestAuthenticationError,
    HTTPRequestMetadata,
    ProtocolCallResult,
    ProtocolTelemetryEvent,
    ProtocolToolDescriptor,
    StreamableHTTPConfig,
    StreamableHTTPConfigurationError,
    StreamableHTTPLimits,
    StreamableHTTPListener,
    StreamableHTTPTransport,
    UvicornStreamableHTTPListener,
)
from tesserix_mcp_runtime.redaction import SecretRedactor, SecretValue

_ROUTING_HEADER_MISMATCH = -32020


def manifest(name: str) -> ToolManifest:
    return ToolManifest(
        metadata=ToolMetadata(
            name=name,
            title=f"Tool {name}",
            description="Return one bounded result.",
            effect=ToolEffect.READ,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=IdempotencyRequirement.NOT_APPLICABLE,
            required_scopes=("examples:read",),
        ),
        normalized_name=name.casefold(),
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string", "maxLength": 64}},
            "required": ["text"],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {"text": {"type": "string", "maxLength": 64}},
            "required": ["text"],
            "additionalProperties": False,
        },
    )


class FakeEndpoint:
    def __init__(self, manifests: tuple[ToolManifest, ...]) -> None:
        self._manifests = manifests
        self.contexts: list[CallContext] = []

    def list_tools(self) -> tuple[str, ...]:
        return tuple(item.metadata.name for item in self._manifests)

    def list_tool_manifests(self) -> tuple[ToolManifest, ...]:
        return self._manifests

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> InvocationResult:
        self.contexts.append(context)
        if name not in self.list_tools():
            raise AssertionError("transport invoked an unknown fixture tool")
        return InvocationResult.success({"text": str(arguments.get("text", ""))})


class OperationalFakeEndpoint(FakeEndpoint):
    def __init__(self, manifests: tuple[ToolManifest, ...]) -> None:
        super().__init__(manifests)
        self.started = False
        self.ready = False
        self.readiness_calls = 0

    def startup_status(self) -> bool:
        return self.started

    def liveness_status(self) -> bool:
        return True

    async def readiness_status(self) -> bool:
        self.readiness_calls += 1
        return self.ready

    def render_metrics(self) -> str:
        return '# TYPE mcp_fixture gauge\nmcp_fixture{server="fixture"} 1\n'


class FakeProtocolSession:
    def __init__(
        self,
        endpoint: FakeProtocolEndpoint,
        protocol_version: str,
    ) -> None:
        self._endpoint = endpoint
        self._protocol_version = protocol_version

    async def initialize(self) -> None:
        self._endpoint.events.append(f"initialize:{self._protocol_version}")

    async def list_tools(self) -> tuple[ProtocolToolDescriptor, ...]:
        self._endpoint.events.append("list_tools")
        return self._endpoint.protocol_tools()

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        meta: Mapping[str, JsonValue],
    ) -> ProtocolCallResult:
        self._endpoint.metas.append(dict(meta))
        self._endpoint.events.append(f"call_tool:{name}")
        if self._endpoint.call_error is not None:
            raise self._endpoint.call_error
        return ProtocolCallResult(
            content=(
                self._endpoint.content
                if self._endpoint.content is not None
                else ({"type": "text", "text": str(arguments.get("text", ""))},)
            ),
            structured_content={"text": str(arguments.get("text", ""))},
            is_error=False,
        )

    async def close(self) -> None:
        self._endpoint.events.append("close")


class FakeProtocolEndpoint:
    def __init__(
        self,
        *,
        call_error: Exception | None = None,
        content: tuple[Mapping[str, JsonValue], ...] | None = None,
    ) -> None:
        self.events: list[str] = []
        self.contexts: list[CallContext] = []
        self.metas: list[dict[str, JsonValue]] = []
        self.call_error = call_error
        self.content = content
        self._tools: tuple[ProtocolToolDescriptor, ...] = (
            ProtocolToolDescriptor(
                name="native_echo",
                description="Return one native result.",
                input_schema={
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                    "additionalProperties": False,
                },
                fingerprint="native-fingerprint",
            ),
        )

    def protocol_tools(self) -> tuple[ProtocolToolDescriptor, ...]:
        return self._tools

    def widen(self) -> None:
        self._tools = (
            *self._tools,
            ProtocolToolDescriptor(
                name="unexpected",
                description="A tool added after startup.",
                input_schema={"type": "object"},
                output_schema=None,
                fingerprint="unexpected-fingerprint",
            ),
        )

    def replace_tools(self, tools: tuple[ProtocolToolDescriptor, ...]) -> None:
        self._tools = tools

    def connect(
        self,
        *,
        context: CallContext,
        protocol_version: str,
    ) -> FakeProtocolSession:
        self.contexts.append(context)
        self.events.append("connect")
        return FakeProtocolSession(self, protocol_version)


class LargeEndpoint(FakeEndpoint):
    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> InvocationResult:
        del name, arguments
        self.contexts.append(context)
        return InvocationResult.success({"text": "private-result-" + "x" * 1_024})


class NearEnvelopeEndpoint(FakeEndpoint):
    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> InvocationResult:
        del name, arguments
        self.contexts.append(context)
        chunks: list[JsonValue] = ["s" * 62_500 for _ in range(8)]
        result: dict[str, JsonValue] = {
            "request_bytes": 60_000,
            "response_bytes": 500_000,
            "chunks": chunks,
        }
        return InvocationResult.success(result)


class UnserializableEndpoint(FakeEndpoint):
    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> InvocationResult:
        del name, arguments
        self.contexts.append(context)

        class UnsafeResult:
            def __repr__(self) -> str:
                return "private-result-representation"

        return InvocationResult.success(UnsafeResult())  # type: ignore[arg-type]


class DisconnectingEndpoint(FakeEndpoint):
    def __init__(self, manifests: tuple[ToolManifest, ...]) -> None:
        super().__init__(manifests)
        self.started = asyncio.Event()
        self.released = asyncio.Event()
        self.observed_cancellation = False

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> InvocationResult:
        del name, arguments
        self.contexts.append(context)
        self.started.set()
        try:
            await context.cancellation.wait()
            return InvocationResult.success({"text": "cancelled"})
        finally:
            self.observed_cancellation = context.cancelled
            self.released.set()


class StaticContextProvider:
    def __init__(self) -> None:
        self.requests: list[HTTPRequestMetadata] = []
        self.cancellations: list[Cancellation] = []

    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        self.requests.append(request)
        self.cancellations.append(cancellation)
        return CallContext(
            identity=AuthenticatedIdentity(
                tenant="tenant-example",
                subject="subject-example",
                issuer="https://identity.example.invalid",
                scopes=("examples:read",),
            ),
            request_id="request-example",
            run_id="run-example",
            trace_context=TraceContext(
                traceparent="00-11111111111111111111111111111111-1111111111111111-01"
            ),
            deadline=321.5,
            cancellation=cancellation,
            idempotency_key="idempotency-example",
        )


class FailingContextProvider(StaticContextProvider):
    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        del request, cancellation
        raise RuntimeError("private-authentication-detail")


class RequestIDFailingContextProvider:
    def __init__(self) -> None:
        self.peers: list[str | None] = []

    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        del cancellation
        self.peers.append(request.peer_host)
        raise HTTPRequestAuthenticationError(request_id="authentication-request")


class HeaderTenantContextProvider(StaticContextProvider):
    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        self.requests.append(request)
        self.cancellations.append(cancellation)
        tenants = request.header_values("x-fixture-tenant")
        if len(tenants) != 1:
            raise ValueError("fixture tenant is required")
        return CallContext(
            identity=AuthenticatedIdentity(
                tenant=tenants[0],
                subject="subject-example",
                issuer="https://identity.example.invalid",
                scopes=("examples:read",),
            ),
            request_id="request-example",
            run_id="run-example",
            cancellation=cancellation,
        )


class RecordingProtocolTelemetry:
    def __init__(self) -> None:
        self.events: list[ProtocolTelemetryEvent] = []

    def emit(self, event: ProtocolTelemetryEvent) -> None:
        self.events.append(event)


class FailingProtocolTelemetry:
    def emit(self, event: ProtocolTelemetryEvent) -> None:
        del event
        raise RuntimeError("telemetry unavailable")


class FakeListener:
    def __init__(self) -> None:
        self.app: Any | None = None
        self.startup_timeout: float | None = None
        self.stopped: bool = False

    @property
    def bound_port(self) -> int:
        return 8_000

    async def start(self, app: Any, *, startup_timeout: float) -> None:
        self.app = app
        self.startup_timeout = startup_timeout

    async def stop(self) -> None:
        self.stopped = True


class LifespanListener(FakeListener):
    def __init__(self) -> None:
        super().__init__()
        self._receive: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self._send: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None

    async def start(self, app: Any, *, startup_timeout: float) -> None:
        await super().start(app, startup_timeout=startup_timeout)

        async def receive() -> dict[str, object]:
            return await self._receive.get()

        async def send(message: dict[str, object]) -> None:
            await self._send.put(message)

        self._task = asyncio.create_task(
            app(
                {
                    "type": "lifespan",
                    "asgi": {"version": "3.0", "spec_version": "2.0"},
                    "state": {},
                },
                receive,
                send,
            )
        )
        await self._receive.put({"type": "lifespan.startup"})
        message = await asyncio.wait_for(self._send.get(), timeout=startup_timeout)
        if message.get("type") != "lifespan.startup.complete":
            raise RuntimeError(f"fixture lifespan failed: {message.get('type')}")

    async def stop(self) -> None:
        task = self._task
        if task is not None:
            await self._receive.put({"type": "lifespan.shutdown"})
            message = await asyncio.wait_for(self._send.get(), timeout=2)
            if message.get("type") != "lifespan.shutdown.complete":
                raise RuntimeError(f"fixture lifespan failed: {message.get('type')}")
            await task
            self._task = None
        await super().stop()


def request_headers(*additional: tuple[bytes, bytes]) -> list[tuple[bytes, bytes]]:
    return [
        (b"host", b"127.0.0.1:8000"),
        (b"content-type", b"application/json"),
        (b"accept", b"application/json, text/event-stream"),
        *additional,
    ]


async def call_asgi(
    app: Any,
    *,
    method: str = "POST",
    path: str = "/mcp",
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"",
    body_chunks: tuple[bytes, ...] | None = None,
    allow_no_response: bool = False,
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    pending_chunks = list(body_chunks) if body_chunks is not None else [body]
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if pending_chunks:
            chunk = pending_chunks.pop(0)
            return {
                "type": "http.request",
                "body": chunk,
                "more_body": bool(pending_chunks),
            }
        return await asyncio.Future[dict[str, Any]]()

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "root_path": "",
            "headers": headers or request_headers(),
            "client": ("127.0.0.1", 50_000),
            "server": ("127.0.0.1", 8_000),
            "state": {},
        },
        receive,
        send,
    )
    starts = [message for message in sent if message.get("type") == "http.response.start"]
    if allow_no_response and not starts:
        return 0, [], b""
    assert len(starts) == 1
    response_headers_value: object = starts[0].get("headers", [])
    assert isinstance(response_headers_value, list)
    response_headers = cast(list[tuple[bytes, bytes]], response_headers_value)
    chunks: list[bytes] = []
    for message in sent:
        if message.get("type") != "http.response.body":
            continue
        chunk: object = message.get("body", b"")
        assert isinstance(chunk, bytes)
        chunks.append(chunk)
    return int(starts[0]["status"]), response_headers, b"".join(chunks)


def jsonrpc_code(body: bytes) -> int:
    document_value: object = json.loads(body)
    assert isinstance(document_value, dict)
    document = cast(dict[object, object], document_value)
    error_value = document.get("error")
    assert isinstance(error_value, dict)
    error = cast(dict[object, object], error_value)
    code = error.get("code")
    assert isinstance(code, int)
    return code


def modern_request(
    method: str,
    *,
    request_id: object = 1,
    params: dict[str, object] | None = None,
    protocol_version: str = "2026-07-28",
) -> bytes:
    request_params = dict(params or {})
    request_params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": protocol_version,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": request_params,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def modern_headers(
    method: str,
    *,
    name: str | None = None,
    protocol_version: str = "2026-07-28",
) -> list[tuple[bytes, bytes]]:
    routing_headers = [
        (b"mcp-protocol-version", protocol_version.encode("ascii")),
        (b"mcp-method", method.encode("ascii")),
    ]
    if name is not None:
        routing_headers.append((b"mcp-name", name.encode("ascii")))
    return request_headers(*routing_headers)


def legacy_initialize() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "fixture-client", "version": "1.0.0"},
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")


def legacy_headers(
    tenant: str,
    *,
    session_id: str | None = None,
) -> list[tuple[bytes, bytes]]:
    additional = [
        (b"x-fixture-tenant", tenant.encode("ascii")),
        (b"mcp-protocol-version", b"2025-11-25"),
    ]
    if session_id is not None:
        additional.append((b"mcp-session-id", session_id.encode("ascii")))
    return request_headers(*additional)


def response_session_id(headers: list[tuple[bytes, bytes]]) -> str:
    values = [value.decode("ascii") for name, value in headers if name.lower() == b"mcp-session-id"]
    assert len(values) == 1
    return values[0]


def test_streamable_http_defaults_are_private_stateless_and_bounded() -> None:
    config = StreamableHTTPConfig()
    limits = StreamableHTTPLimits()

    assert config.host == "127.0.0.1"
    assert config.port == 8000
    assert config.path == "/mcp"
    assert config.startup_path == "/startupz"
    assert config.liveness_path == "/livez"
    assert config.readiness_path == "/readyz"
    assert config.metrics_path == "/metrics"
    assert config.stateless is True
    assert config.allowed_hosts == ()
    assert config.allowed_origins == ()
    assert limits.max_request_headers == 128
    assert limits.max_request_header_bytes == 32_768
    assert limits.max_request_body_bytes == 65_536
    assert limits.max_response_body_bytes == 524_288
    assert limits.max_schema_bytes == 262_144
    assert limits.max_tools == 128
    assert limits.tool_page_size == 32
    assert limits.max_tool_pages == 4
    assert limits.max_sessions == 128
    assert limits.session_lifetime_seconds == 1_800.0
    assert limits.startup_timeout_seconds == 2.0
    assert limits.max_stream_seconds == 300.0


@pytest.mark.parametrize(
    ("configured", "normalized"),
    [
        ("mcp", "/mcp"),
        ("/mcp/", "/mcp"),
        ("//gateway//runtime//mcp//", "/gateway/runtime/mcp"),
    ],
    ids=["missing-leading-slash", "trailing-slash", "repeated-slashes"],
)
def test_streamable_http_path_is_normalized_once(configured: str, normalized: str) -> None:
    assert StreamableHTTPConfig(path=configured).path == normalized


@pytest.mark.parametrize(
    "path",
    ["", "/", "/mcp/../admin", "/mcp?query=true", "/mcp#fragment"],
    ids=["empty", "root", "parent-segment", "query", "fragment"],
)
def test_streamable_http_path_rejects_ambiguous_routes(path: str) -> None:
    with pytest.raises(ValueError, match="path"):
        StreamableHTTPConfig(path=path)


def test_operational_paths_must_be_distinct_from_each_other_and_mcp() -> None:
    with pytest.raises(ValueError, match="distinct"):
        StreamableHTTPConfig(readiness_path="/mcp")

    with pytest.raises(ValueError, match="distinct"):
        StreamableHTTPConfig(startup_path="/health", liveness_path="/health")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_request_body_bytes", 0),
        ("max_response_body_bytes", -1),
        ("max_schema_bytes", 0),
        ("max_tools", True),
        ("tool_page_size", 0),
        ("max_tool_pages", 0),
        ("max_sessions", 0),
        ("session_lifetime_seconds", math.inf),
        ("startup_timeout_seconds", math.nan),
        ("max_stream_seconds", math.inf),
    ],
    ids=[
        "request-bytes",
        "response-bytes",
        "schema-bytes",
        "tool-count",
        "page-size",
        "page-count",
        "session-count",
        "session-lifetime",
        "startup-timeout",
        "stream-timeout",
    ],
)
def test_streamable_http_limits_reject_non_positive_or_non_finite_values(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match=field):
        StreamableHTTPLimits(**{field: value})  # type: ignore[arg-type]


def test_streamable_http_limits_require_pages_to_cover_the_tool_ceiling() -> None:
    with pytest.raises(ValueError, match="tool_page_size"):
        StreamableHTTPLimits(max_tools=65, tool_page_size=16, max_tool_pages=4)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_request_body_bytes", 65_537),
        ("max_request_headers", 257),
        ("max_request_header_bytes", 65_537),
        ("max_response_body_bytes", 524_289),
        ("max_schema_bytes", 262_145),
        ("max_tools", 129),
        ("tool_page_size", 129),
        ("max_tool_pages", 129),
        ("max_sessions", 257),
        ("session_lifetime_seconds", 3_600.001),
        ("startup_timeout_seconds", 30.001),
        ("max_stream_seconds", 300.001),
    ],
)
def test_streamable_http_limits_reject_values_above_hard_maxima(
    field: str,
    value: int | float,
) -> None:
    with pytest.raises(ValueError, match=field):
        StreamableHTTPLimits(**{field: value})  # type: ignore[arg-type]


def test_non_loopback_listener_requires_explicit_host_and_origin_allowlists() -> None:
    with pytest.raises(ValueError, match="allowed_hosts"):
        StreamableHTTPConfig(host="0.0.0.0")

    configured = StreamableHTTPConfig(
        host="0.0.0.0",
        allowed_hosts=("runtime.internal.example:8443",),
        allowed_origins=("https://gateway.internal.example",),
    )

    assert configured.allowed_hosts == ("runtime.internal.example:8443",)
    assert configured.allowed_origins == ("https://gateway.internal.example",)


@pytest.mark.parametrize(
    "configuration",
    [
        {"host": ""},
        {"host": " loopback"},
        {"port": 0},
        {"port": True},
        {"stateless": 1},
        {"allowed_hosts": ("duplicate", "duplicate")},
        {
            "host": "0.0.0.0",
            "allowed_hosts": ("runtime.internal.example",),
            "allowed_origins": (),
        },
    ],
    ids=[
        "empty-host",
        "host-whitespace",
        "zero-port",
        "boolean-port",
        "non-boolean-stateless",
        "duplicate-host-allowlist",
        "missing-origin-allowlist",
    ],
)
def test_streamable_http_config_rejects_invalid_listener_values(
    configuration: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        StreamableHTTPConfig(**configuration)  # type: ignore[arg-type]


def test_non_loopback_listener_enforces_host_and_origin_allowlists() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(
                host="0.0.0.0",
                allowed_hosts=("runtime.internal.example:8443",),
                allowed_origins=("https://gateway.internal.example",),
            ),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None

        def headers(host: bytes, origin: bytes) -> list[tuple[bytes, bytes]]:
            return [
                (b"host", host),
                (b"origin", origin),
                (b"content-type", b"application/json"),
                (b"accept", b"application/json, text/event-stream"),
                (b"mcp-protocol-version", b"2026-07-28"),
                (b"mcp-method", b"server/discover"),
            ]

        allowed, _, _ = await call_asgi(
            listener.app,
            headers=headers(
                b"runtime.internal.example:8443",
                b"https://gateway.internal.example",
            ),
            body=modern_request("server/discover"),
        )
        bad_host, _, bad_host_body = await call_asgi(
            listener.app,
            headers=headers(
                b"attacker.invalid",
                b"https://gateway.internal.example",
            ),
            body=modern_request("server/discover"),
        )
        bad_origin, _, bad_origin_body = await call_asgi(
            listener.app,
            headers=headers(
                b"runtime.internal.example:8443",
                b"https://attacker.invalid",
            ),
            body=modern_request("server/discover"),
        )

        assert allowed == 200
        assert bad_host in {403, 421}
        assert bad_origin in {403, 421}
        assert len(bad_host_body) < 512
        assert len(bad_origin_body) < 512
        assert b"attacker.invalid" not in bad_host_body
        assert b"attacker.invalid" not in bad_origin_body
        await transport.stop()

    asyncio.run(exercise())


def test_http_request_metadata_never_represents_header_values() -> None:
    request = HTTPRequestMetadata(
        method="POST",
        path="/mcp",
        headers=(("authorization", "Bearer fixture-secret"),),
    )

    assert request.header_values("authorization") == ("Bearer fixture-secret",)
    assert "fixture-secret" not in repr(request)
    assert repr(request) == "HTTPRequestMetadata(method='POST', path='/mcp', headers=[redacted])"


def test_streamable_http_public_protocols_are_runtime_checkable() -> None:
    assert isinstance(StaticContextProvider(), HTTPCallContextProvider)
    assert isinstance(FakeListener(), StreamableHTTPListener)


class FakeBoundSocket:
    def __init__(self, port: int) -> None:
        self._port = port

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", self._port)


class FakeUvicornConfig:
    def __init__(self, app: Any, **settings: object) -> None:
        self.app = app
        self.settings = settings


class FakeUvicornServer:
    instances: ClassVar[list[FakeUvicornServer]] = []

    def __init__(self, config: FakeUvicornConfig) -> None:
        self.config = config
        self.started = False
        self.force_exit = False
        self.servers: list[SimpleNamespace] = []
        self._should_exit = False
        self._exit = asyncio.Event()
        self.__class__.instances.append(self)

    @property
    def should_exit(self) -> bool:
        return self._should_exit

    @should_exit.setter
    def should_exit(self, value: bool) -> None:
        self._should_exit = value
        if value:
            self._exit.set()

    async def serve(self) -> None:
        self.servers = [SimpleNamespace(sockets=[FakeBoundSocket(43_210)])]
        self.started = True
        await self._exit.wait()


def test_uvicorn_listener_waits_for_readiness_and_has_hardened_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        FakeUvicornServer.instances.clear()
        monkeypatch.setattr(uvicorn, "Config", FakeUvicornConfig)
        monkeypatch.setattr(uvicorn, "Server", FakeUvicornServer)
        listener = UvicornStreamableHTTPListener(host="127.0.0.1", port=8_000)

        async def app(scope: Any, receive: Any, send: Any) -> None:
            del scope, receive, send

        await listener.start(app, startup_timeout=0.5)

        server = FakeUvicornServer.instances[0]
        assert listener.bound_port == 43_210
        assert server.config.settings == {
            "host": "127.0.0.1",
            "port": 8_000,
            "access_log": False,
            "date_header": False,
            "lifespan": "on",
            "log_level": "warning",
            "proxy_headers": False,
            "server_header": False,
        }
        with pytest.raises(StreamableHTTPConfigurationError) as raised:
            await listener.start(app, startup_timeout=0.5)
        assert raised.value.code == "listener_already_started"
        await listener.stop()
        await listener.stop()
        assert server.should_exit is True

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("host", "port"),
    [("", 8_000), ("127.0.0.1", 0), ("127.0.0.1", True)],
    ids=["empty-host", "zero-port", "boolean-port"],
)
def test_uvicorn_listener_rejects_invalid_bind_values(host: str, port: int) -> None:
    with pytest.raises(ValueError):
        UvicornStreamableHTTPListener(host=host, port=port)


def test_uvicorn_listener_bounds_startup_failure_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NeverReadyServer(FakeUvicornServer):
        async def serve(self) -> None:
            await self._exit.wait()

    async def exercise() -> None:
        NeverReadyServer.instances.clear()
        monkeypatch.setattr(uvicorn, "Config", FakeUvicornConfig)
        monkeypatch.setattr(uvicorn, "Server", NeverReadyServer)
        listener = UvicornStreamableHTTPListener(host="127.0.0.1", port=8_000)

        async def app(scope: Any, receive: Any, send: Any) -> None:
            del scope, receive, send

        with pytest.raises(StreamableHTTPConfigurationError) as raised:
            await listener.start(app, startup_timeout=0.01)

        assert raised.value.code == "listener_start_timeout"
        assert raised.value.path == "listener"
        assert NeverReadyServer.instances[0].should_exit is True
        await listener.stop()

    asyncio.run(exercise())


def test_uvicorn_listener_force_cancels_a_stubborn_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StubbornServer(FakeUvicornServer):
        async def serve(self) -> None:
            await asyncio.Future[None]()

    async def exercise() -> None:
        StubbornServer.instances.clear()
        monkeypatch.setattr(uvicorn, "Config", FakeUvicornConfig)
        monkeypatch.setattr(uvicorn, "Server", StubbornServer)
        listener = UvicornStreamableHTTPListener(host="127.0.0.1", port=8_000)

        async def app(scope: Any, receive: Any, send: Any) -> None:
            del scope, receive, send

        with pytest.raises(StreamableHTTPConfigurationError) as raised:
            await listener.start(app, startup_timeout=0.01)

        assert raised.value.code == "listener_start_timeout"
        assert StubbornServer.instances[0].force_exit is True
        await listener.stop()

    asyncio.run(exercise())


def test_uvicorn_listener_normalizes_early_exit_and_invalid_bound_sockets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EarlyExitServer(FakeUvicornServer):
        async def serve(self) -> None:
            raise RuntimeError("private-listener-detail")

    class NormalEarlyExitServer(FakeUvicornServer):
        async def serve(self) -> None:
            return

    class NoServersServer(FakeUvicornServer):
        async def serve(self) -> None:
            self.started = True
            await self._exit.wait()

    class NoSocketsServer(FakeUvicornServer):
        async def serve(self) -> None:
            self.servers = [SimpleNamespace(sockets=[])]
            self.started = True
            await self._exit.wait()

    class InvalidBoundSocket(FakeBoundSocket):
        def getsockname(self) -> Any:
            return "invalid-address"

    class InvalidAddressServer(FakeUvicornServer):
        async def serve(self) -> None:
            self.servers = [SimpleNamespace(sockets=[InvalidBoundSocket(8_000)])]
            self.started = True
            await self._exit.wait()

    class ShortAddressSocket(FakeBoundSocket):
        def getsockname(self) -> Any:
            return ("127.0.0.1",)

    class ShortAddressServer(FakeUvicornServer):
        async def serve(self) -> None:
            self.servers = [SimpleNamespace(sockets=[ShortAddressSocket(8_000)])]
            self.started = True
            await self._exit.wait()

    class TextPortSocket(FakeBoundSocket):
        def getsockname(self) -> Any:
            return ("127.0.0.1", "8000")

    class TextPortServer(FakeUvicornServer):
        async def serve(self) -> None:
            self.servers = [SimpleNamespace(sockets=[TextPortSocket(8_000)])]
            self.started = True
            await self._exit.wait()

    async def exercise() -> None:
        monkeypatch.setattr(uvicorn, "Config", FakeUvicornConfig)
        for server_type in (
            EarlyExitServer,
            NormalEarlyExitServer,
            NoServersServer,
            NoSocketsServer,
            InvalidAddressServer,
            ShortAddressServer,
            TextPortServer,
        ):
            server_type.instances.clear()
            monkeypatch.setattr(uvicorn, "Server", server_type)
            listener = UvicornStreamableHTTPListener(host="127.0.0.1", port=8_000)

            async def app(scope: Any, receive: Any, send: Any) -> None:
                del scope, receive, send

            with pytest.raises(StreamableHTTPConfigurationError) as raised:
                await listener.start(app, startup_timeout=0.1)

            assert raised.value.code == "listener_start_failed"
            assert "private-listener-detail" not in str(raised.value)
            await listener.stop()

    asyncio.run(exercise())


def test_uvicorn_listener_cleans_up_when_startup_caller_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NeverReadyServer(FakeUvicornServer):
        async def serve(self) -> None:
            await self._exit.wait()

    async def exercise() -> None:
        NeverReadyServer.instances.clear()
        monkeypatch.setattr(uvicorn, "Config", FakeUvicornConfig)
        monkeypatch.setattr(uvicorn, "Server", NeverReadyServer)
        listener = UvicornStreamableHTTPListener(host="127.0.0.1", port=8_000)

        async def app(scope: Any, receive: Any, send: Any) -> None:
            del scope, receive, send

        startup = asyncio.create_task(listener.start(app, startup_timeout=1.0))
        await asyncio.sleep(0)
        startup.cancel()

        with pytest.raises(asyncio.CancelledError):
            await startup

        assert NeverReadyServer.instances[0].should_exit is True
        await listener.stop()

    asyncio.run(exercise())


def test_streamable_http_transport_uses_default_listener_when_omitted() -> None:
    transport = StreamableHTTPTransport(
        config=StreamableHTTPConfig(port=8_123),
        limits=StreamableHTTPLimits(),
        context_provider=StaticContextProvider(),
        telemetry=RecordingProtocolTelemetry(),
    )

    assert transport.bound_port == 8_123


def test_streamable_http_transport_binds_manifests_and_drains_before_stop() -> None:
    async def exercise() -> None:
        listener = FakeListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )

        await transport.start(FakeEndpoint((manifest("examples.echo"),)))

        assert transport.name == "mcp_streamable_http_transport"
        assert transport.bound_port == 8_000
        assert transport.sdk_version == "2.1.1"
        assert listener.app is not None
        assert listener.startup_timeout == 2.0

        await transport.drain(deadline=100.0)
        assert not transport.accepting
        assert listener.stopped is False

        await transport.stop()
        assert listener.stopped is True

    asyncio.run(exercise())


def test_streamable_http_transport_rejects_tool_catalog_over_limit_before_binding() -> None:
    async def exercise() -> None:
        listener = FakeListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(max_tools=1, tool_page_size=1, max_tool_pages=1),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )

        with pytest.raises(StreamableHTTPConfigurationError) as captured:
            await transport.start(
                FakeEndpoint((manifest("examples.first"), manifest("examples.second")))
            )

        assert captured.value.code == "tool_limit_exceeded"
        assert captured.value.path == "endpoint.manifests"
        assert listener.app is None

    asyncio.run(exercise())


def test_streamable_http_transport_rejects_schema_bytes_over_limit_before_binding() -> None:
    async def exercise() -> None:
        listener = FakeListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(max_schema_bytes=1),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )

        with pytest.raises(StreamableHTTPConfigurationError) as raised:
            await transport.start(FakeEndpoint((manifest("examples.echo"),)))

        assert raised.value.code == "schema_limit_exceeded"
        assert raised.value.path == "endpoint.manifests"
        assert listener.app is None

    asyncio.run(exercise())


def test_official_client_initializes_lists_pings_and_calls_without_a_socket() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        provider = StaticContextProvider()
        telemetry = RecordingProtocolTelemetry()
        endpoint = FakeEndpoint((manifest("examples.echo"),))
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=provider,
            telemetry=telemetry,
            listener=listener,
        )
        await transport.start(endpoint)
        assert listener.app is not None

        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=listener.app),
                base_url="http://127.0.0.1:8000",
                headers={"authorization": "Bearer fixture-value"},
            ) as http_client,
            streamable_http_client(
                "http://127.0.0.1:8000/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as streams,
            ClientSession(streams[0], streams[1]) as session,
        ):
            initialized = await session.initialize()
            listed = await session.list_tools()
            await session.send_ping()
            called = await session.call_tool("examples.echo", {"text": "hello"})

        assert str(initialized.protocol_version) == "2025-11-25"
        assert [tool.name for tool in listed.tools] == ["examples.echo"]
        assert listed.tools[0].input_schema == endpoint.list_tool_manifests()[0].input_schema
        assert called.is_error is False
        assert called.structured_content == {"text": "hello"}
        assert endpoint.contexts
        assert endpoint.contexts[0].tenant == "tenant-example"
        assert endpoint.contexts[0].request_id == "request-example"
        assert endpoint.contexts[0].run_id == "run-example"
        assert endpoint.contexts[0].deadline == 321.5
        assert endpoint.contexts[0].trace == {
            "traceparent": "00-11111111111111111111111111111111-1111111111111111-01"
        }
        assert endpoint.contexts[0].idempotency_key == "idempotency-example"
        assert endpoint.contexts[0].cancellation in provider.cancellations
        assert "fixture-value" not in repr(provider.requests[0])
        assert {event.method for event in telemetry.events} >= {
            "initialize",
            "ping",
            "tools/call",
            "tools/list",
        }
        assert all(event.sdk_version == "2.1.1" for event in telemetry.events)

        await transport.drain(deadline=100.0)
        await transport.stop()

    asyncio.run(exercise())


def test_stateless_asgi_calls_alternate_replicas_with_one_external_idempotent_effect() -> None:
    class ExternalIdempotencyAuthority:
        def __init__(self) -> None:
            self.records: dict[tuple[str, str, str], tuple[str, InvocationResult]] = {}
            self.effects = 0

        def apply(
            self,
            arguments: Mapping[str, JsonValue],
            *,
            context: CallContext,
        ) -> InvocationResult:
            assert context.idempotency_key is not None
            key = (
                context.tenant,
                "capability:orders.create@1",
                context.idempotency_key,
            )
            request_digest = hashlib.sha256(
                json.dumps(arguments, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).hexdigest()
            existing = self.records.get(key)
            if existing is not None:
                assert existing[0] == request_digest
                return existing[1]
            self.effects += 1
            result = InvocationResult.success(
                {
                    "effect_number": self.effects,
                    "workflow_id": "workflow-order-shared",
                }
            )
            self.records[key] = (request_digest, result)
            return result

    class StatelessReplicaEndpoint(FakeEndpoint):
        def __init__(self, authority: ExternalIdempotencyAuthority) -> None:
            super().__init__(
                (
                    ToolManifest(
                        metadata=ToolMetadata(
                            name="orders.create",
                            title="Create order",
                            description="Create one idempotent synthetic order.",
                            effect=ToolEffect.WRITE,
                            approval=ApprovalRequirement.NOT_REQUIRED,
                            idempotency=IdempotencyRequirement.REQUIRED,
                            required_scopes=("examples:read",),
                        ),
                        normalized_name="orders.create",
                        input_schema={
                            "type": "object",
                            "properties": {"customer": {"type": "string", "maxLength": 64}},
                            "required": ["customer"],
                            "additionalProperties": False,
                        },
                        output_schema={
                            "type": "object",
                            "properties": {
                                "effect_number": {"type": "integer"},
                                "workflow_id": {"type": "string", "maxLength": 64},
                            },
                            "required": ["effect_number", "workflow_id"],
                            "additionalProperties": False,
                        },
                    ),
                )
            )
            self._authority = authority

        async def invoke(
            self,
            name: str,
            arguments: Mapping[str, JsonValue],
            *,
            context: CallContext,
        ) -> InvocationResult:
            assert name == "orders.create"
            self.contexts.append(context)
            return self._authority.apply(arguments, context=context)

    async def exercise() -> None:
        authority = ExternalIdempotencyAuthority()
        listeners = (LifespanListener(), LifespanListener())
        endpoints = (
            StatelessReplicaEndpoint(authority),
            StatelessReplicaEndpoint(authority),
        )
        providers = (StaticContextProvider(), StaticContextProvider())
        transports = tuple(
            StreamableHTTPTransport(
                config=StreamableHTTPConfig(stateless=True),
                limits=StreamableHTTPLimits(),
                context_provider=provider,
                telemetry=RecordingProtocolTelemetry(),
                listener=listener,
            )
            for listener, provider in zip(listeners, providers, strict=True)
        )
        for transport, endpoint in zip(transports, endpoints, strict=True):
            await transport.start(endpoint)
        assert all(listener.app is not None for listener in listeners)

        async def invoke(app: Any) -> object:
            async with (
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="http://127.0.0.1:8000",
                ) as http_client,
                streamable_http_client(
                    "http://127.0.0.1:8000/mcp",
                    http_client=http_client,
                    terminate_on_close=False,
                ) as streams,
                ClientSession(streams[0], streams[1]) as session,
            ):
                await session.initialize()
                result = await session.call_tool(
                    "orders.create",
                    {"customer": "customer-shared"},
                )
            assert result.is_error is False
            return result.structured_content

        try:
            results = [
                await invoke(listeners[delivery % len(listeners)].app) for delivery in range(4)
            ]
        finally:
            for transport in transports:
                await transport.stop()

        assert results == [{"effect_number": 1, "workflow_id": "workflow-order-shared"}] * 4
        assert authority.effects == 1
        assert len(authority.records) == 1
        assert [len(endpoint.contexts) for endpoint in endpoints] == [2, 2]
        assert all(
            context.idempotency_key == "idempotency-example"
            for endpoint in endpoints
            for context in endpoint.contexts
        )
        assert all(
            not request.header_values("mcp-session-id")
            for provider in providers
            for request in provider.requests
        )

    asyncio.run(exercise())


def test_protocol_endpoint_translates_initialize_list_call_and_close() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        endpoint = FakeProtocolEndpoint()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(endpoint)
        assert listener.app is not None

        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=listener.app),
                base_url="http://127.0.0.1:8000",
            ) as http_client,
            streamable_http_client(
                "http://127.0.0.1:8000/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as streams,
            ClientSession(streams[0], streams[1]) as session,
        ):
            initialized = await session.initialize()
            listed = await session.list_tools()
            called = await session.call_tool(
                "native_echo",
                {"text": "hello"},
                meta=cast(RequestParamsMeta, {"fixture": "value"}),
            )

        assert str(initialized.protocol_version) == "2025-11-25"
        assert [tool.name for tool in listed.tools] == ["native_echo"]
        assert called.is_error is False
        assert called.structured_content == {"text": "hello"}
        assert endpoint.events == [
            "connect",
            "initialize:2025-03-26",
            "close",
            "connect",
            "initialize:2025-11-25",
            "list_tools",
            "close",
            "connect",
            "initialize:2025-11-25",
            "call_tool:native_echo",
            "close",
        ]
        assert len(endpoint.contexts) == 3
        assert endpoint.metas == [{"fixture": "value"}]
        await transport.stop()

    asyncio.run(exercise())


def test_mcp_authority_metadata_cannot_switch_the_verified_call_context() -> None:
    async def exercise() -> None:
        endpoint = FakeEndpoint((manifest("examples.echo"),))
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(endpoint)
        assert listener.app is not None

        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=listener.app),
                base_url="http://127.0.0.1:8000",
            ) as http_client,
            streamable_http_client(
                "http://127.0.0.1:8000/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as streams,
            ClientSession(streams[0], streams[1]) as session,
        ):
            await session.initialize()
            for prefix in ("tesserix/runtime", "tesserix/adk"):
                for field in (
                    "tenant",
                    "subject",
                    "run",
                    "scopes",
                    "traceparent",
                    "tracestate",
                    "idempotency-key",
                    "approval-id",
                ):
                    forged = f"forged-{field}"
                    with pytest.raises(MCPError) as raised:
                        await session.call_tool(
                            "examples.echo",
                            {"text": "hello"},
                            meta=cast(
                                RequestParamsMeta,
                                {f"{prefix}/{field}": forged},
                            ),
                        )

                    assert raised.value.error.data == {
                        "code": "authority_mismatch",
                        "request_id": "request-example",
                    }
                    assert forged not in str(raised.value)

        assert endpoint.contexts == []
        await transport.stop()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("name", "", "name"),
        ("description", " leading", "description"),
        ("fingerprint", "bad\nvalue", "fingerprint"),
        ("input_schema", [], "input_schema"),
        ("output_schema", [], "output_schema"),
    ],
)
def test_protocol_tool_descriptor_rejects_invalid_boundaries(
    field: str,
    value: object,
    message: str,
) -> None:
    values: dict[str, object] = {
        "name": "native_echo",
        "description": "Return one value.",
        "input_schema": {"type": "object"},
        "output_schema": None,
        "fingerprint": "fingerprint",
    }
    values[field] = value

    with pytest.raises(ValueError, match=message):
        ProtocolToolDescriptor(
            name=cast(str, values["name"]),
            description=cast(str, values["description"]),
            input_schema=cast(Mapping[str, JsonValue], values["input_schema"]),
            output_schema=cast(Mapping[str, JsonValue] | None, values["output_schema"]),
            fingerprint=cast(str, values["fingerprint"]),
        )


_INVALID_PROTOCOL_RESULTS: tuple[tuple[object, object, object, str], ...] = (
    (list[object](), None, False, "content"),
    ((list[object](),), None, False, "content items"),
    ((), list[object](), False, "structured_content"),
    ((), None, "false", "is_error"),
)


@pytest.mark.parametrize(
    ("content", "structured_content", "is_error", "message"),
    _INVALID_PROTOCOL_RESULTS,
)
def test_protocol_call_result_rejects_invalid_boundaries(
    content: object,
    structured_content: object,
    is_error: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ProtocolCallResult(
            content=cast(tuple[Mapping[str, JsonValue], ...], content),
            structured_content=cast(dict[str, JsonValue] | None, structured_content),
            is_error=cast(bool, is_error),
        )


def test_protocol_endpoint_rejects_non_json_schema_before_binding() -> None:
    async def exercise() -> None:
        listener = FakeListener()
        endpoint = FakeProtocolEndpoint()
        endpoint.replace_tools(
            (
                ProtocolToolDescriptor(
                    name="native_echo",
                    description="Return one value.",
                    input_schema={"invalid": cast(Any, {"not-json"})},
                    output_schema=None,
                    fingerprint="fingerprint",
                ),
            )
        )
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )

        with pytest.raises(StreamableHTTPConfigurationError) as raised:
            await transport.start(endpoint)

        assert raised.value.code == "invalid_protocol_tools"
        assert listener.app is None

    asyncio.run(exercise())


def test_protocol_session_failure_is_closed_and_returned_without_private_text() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        endpoint = FakeProtocolEndpoint(
            call_error=RuntimeError("private-session-failure"),
        )
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(endpoint)
        assert listener.app is not None

        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=listener.app),
                base_url="http://127.0.0.1:8000",
            ) as http_client,
            streamable_http_client(
                "http://127.0.0.1:8000/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as streams,
            ClientSession(streams[0], streams[1]) as session,
        ):
            await session.initialize()
            with pytest.raises(MCPError) as raised:
                await session.call_tool("native_echo", {"text": "hello"})

        assert "private-session-failure" not in str(raised.value)
        assert endpoint.events[-3:] == [
            "initialize:2025-11-25",
            "call_tool:native_echo",
            "close",
        ]
        await transport.stop()

    asyncio.run(exercise())


def test_protocol_session_rejects_descriptor_widening_after_startup() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        endpoint = FakeProtocolEndpoint()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(endpoint)
        endpoint.widen()
        assert listener.app is not None

        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=listener.app),
                base_url="http://127.0.0.1:8000",
            ) as http_client,
            streamable_http_client(
                "http://127.0.0.1:8000/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as streams,
            ClientSession(streams[0], streams[1]) as session,
        ):
            await session.initialize()
            with pytest.raises(MCPError, match="Internal error"):
                await session.list_tools()

        assert endpoint.events[-2:] == ["list_tools", "close"]
        await transport.stop()

    asyncio.run(exercise())


def test_protocol_session_rejects_invalid_content_after_closing() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        endpoint = FakeProtocolEndpoint(content=({"type": "text"},))
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(endpoint)
        assert listener.app is not None

        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=listener.app),
                base_url="http://127.0.0.1:8000",
            ) as http_client,
            streamable_http_client(
                "http://127.0.0.1:8000/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as streams,
            ClientSession(streams[0], streams[1]) as session,
        ):
            await session.initialize()
            with pytest.raises(MCPError, match="Internal error"):
                await session.call_tool("native_echo", {"text": "hello"})

        assert endpoint.events[-1] == "close"
        await transport.stop()

    asyncio.run(exercise())


def test_telemetry_failure_does_not_fail_a_protocol_request() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=FailingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None

        status, _, body = await call_asgi(
            listener.app,
            headers=modern_headers("server/discover"),
            body=modern_request("server/discover"),
        )

        assert status == 200
        response = json.loads(body)
        assert response["id"] == 1
        assert isinstance(response["result"], dict)
        assert transport.telemetry_failures == 1
        await transport.stop()

    asyncio.run(exercise())


def test_protocol_telemetry_redacts_exact_known_values() -> None:
    canary = "SyntheticProtocolCanary3Hp6"
    telemetry = RecordingProtocolTelemetry()
    transport = StreamableHTTPTransport(
        config=StreamableHTTPConfig(),
        limits=StreamableHTTPLimits(),
        context_provider=StaticContextProvider(),
        telemetry=telemetry,
        listener=FakeListener(),
        redactor=SecretRedactor(known_secrets=(SecretValue(canary),)),
    )

    transport.emit_protocol_event(
        cast(Any, SimpleNamespace(method=canary, protocol_version=f"version-{canary}")),
        outcome="failure",
    )

    assert len(telemetry.events) == 1
    assert canary not in repr(telemetry.events[0])


def test_tool_listing_uses_bounded_opaque_progressing_cursors() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(
                max_tools=2,
                tool_page_size=1,
                max_tool_pages=2,
            ),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(
            FakeEndpoint((manifest("examples.first"), manifest("examples.second")))
        )
        assert listener.app is not None

        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=listener.app),
                base_url="http://127.0.0.1:8000",
            ) as http_client,
            streamable_http_client(
                "http://127.0.0.1:8000/mcp",
                http_client=http_client,
                terminate_on_close=False,
            ) as streams,
            ClientSession(streams[0], streams[1]) as session,
        ):
            await session.initialize()
            first = await session.list_tools()
            assert first.next_cursor is not None
            second = await session.list_tools(
                params=PaginatedRequestParams(cursor=first.next_cursor)
            )
            with pytest.raises(MCPError) as captured:
                await session.list_tools(params=PaginatedRequestParams(cursor="forged"))

        assert [tool.name for tool in first.tools] == ["examples.first"]
        assert [tool.name for tool in second.tools] == ["examples.second"]
        assert second.next_cursor is None
        assert captured.value.code == INVALID_PARAMS
        await transport.stop()

    asyncio.run(exercise())


def test_stateless_mode_rejects_session_headers_and_stops_admission_on_drain() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        provider = StaticContextProvider()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=provider,
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None
        ping = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'

        forged_status, _, forged_body = await call_asgi(
            listener.app,
            headers=request_headers(
                (b"mcp-protocol-version", b"2026-07-28"),
                (b"mcp-session-id", b"forged-session"),
            ),
            body=ping,
        )
        assert forged_status == 404
        assert jsonrpc_code(forged_body) == INVALID_REQUEST
        assert b"forged-session" not in forged_body

        await transport.drain(deadline=100.0)
        drained_status, _, drained_body = await call_asgi(
            listener.app,
            headers=request_headers((b"mcp-protocol-version", b"2026-07-28")),
            body=ping,
        )
        assert drained_status == 503
        assert jsonrpc_code(drained_body) == INTERNAL_ERROR
        await transport.stop()

    asyncio.run(exercise())


def test_stateful_sessions_are_bounded_tenant_bound_and_released_on_close() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(stateless=False),
            limits=StreamableHTTPLimits(max_sessions=1),
            context_provider=HeaderTenantContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None

        initialized, initialized_headers, _ = await call_asgi(
            listener.app,
            headers=request_headers((b"x-fixture-tenant", b"tenant-a")),
            body=legacy_initialize(),
        )
        assert initialized == 200
        session_id = response_session_id(initialized_headers)
        assert len(session_id) == 32

        ping = b'{"jsonrpc":"2.0","id":2,"method":"ping"}'
        missing, _, missing_body = await call_asgi(
            listener.app,
            headers=legacy_headers("tenant-a"),
            body=ping,
        )
        forged, _, forged_body = await call_asgi(
            listener.app,
            headers=legacy_headers("tenant-a", session_id="0" * 32),
            body=ping,
        )
        cross_tenant, _, cross_tenant_body = await call_asgi(
            listener.app,
            headers=legacy_headers("tenant-b", session_id=session_id),
            body=ping,
        )
        at_capacity, _, at_capacity_body = await call_asgi(
            listener.app,
            headers=request_headers((b"x-fixture-tenant", b"tenant-b")),
            body=legacy_initialize(),
        )
        modern, _, modern_body = await call_asgi(
            listener.app,
            headers=[
                *modern_headers("server/discover"),
                (b"x-fixture-tenant", b"tenant-a"),
            ],
            body=modern_request("server/discover"),
        )
        same_tenant, _, _ = await call_asgi(
            listener.app,
            headers=legacy_headers("tenant-a", session_id=session_id),
            body=ping,
        )

        assert missing == 404
        assert forged == 404
        assert cross_tenant == 404
        assert at_capacity == 429
        assert modern == 200, modern_body
        assert same_tenant == 200
        for body in (missing_body, forged_body, cross_tenant_body):
            assert jsonrpc_code(body) == INVALID_REQUEST
            assert session_id.encode("ascii") not in body
        assert jsonrpc_code(at_capacity_body) == INTERNAL_ERROR

        closed, _, _ = await call_asgi(
            listener.app,
            method="DELETE",
            headers=legacy_headers("tenant-a", session_id=session_id),
        )
        after_close, _, _ = await call_asgi(
            listener.app,
            headers=legacy_headers("tenant-a", session_id=session_id),
            body=ping,
        )
        replacement, replacement_headers, _ = await call_asgi(
            listener.app,
            headers=request_headers((b"x-fixture-tenant", b"tenant-b")),
            body=legacy_initialize(),
        )

        assert closed == 200
        assert after_close == 404
        assert replacement == 200
        assert response_session_id(replacement_headers) != session_id
        await transport.stop()

    asyncio.run(exercise())


def test_stateful_session_absolute_expiry_releases_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 100.0

    async def exercise() -> None:
        nonlocal now
        monkeypatch.setattr(time, "monotonic", lambda: now)
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(stateless=False),
            limits=StreamableHTTPLimits(
                max_sessions=1,
                session_lifetime_seconds=10.0,
            ),
            context_provider=HeaderTenantContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None

        initialized, initialized_headers, _ = await call_asgi(
            listener.app,
            headers=request_headers((b"x-fixture-tenant", b"tenant-a")),
            body=legacy_initialize(),
        )
        assert initialized == 200
        expired_session = response_session_id(initialized_headers)

        now = 111.0
        expired, _, expired_body = await call_asgi(
            listener.app,
            headers=legacy_headers("tenant-a", session_id=expired_session),
            body=b'{"jsonrpc":"2.0","id":2,"method":"ping"}',
        )
        replacement, replacement_headers, _ = await call_asgi(
            listener.app,
            headers=request_headers((b"x-fixture-tenant", b"tenant-b")),
            body=legacy_initialize(),
        )

        assert expired == 404
        assert jsonrpc_code(expired_body) == INVALID_REQUEST
        assert replacement == 200
        assert response_session_id(replacement_headers) != expired_session
        await transport.stop()

    asyncio.run(exercise())


def test_stateful_session_reservations_enforce_capacity_under_concurrency() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(stateless=False),
            limits=StreamableHTTPLimits(max_sessions=1),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None

        responses = await asyncio.gather(
            call_asgi(listener.app, body=legacy_initialize()),
            call_asgi(listener.app, body=legacy_initialize()),
        )

        assert sorted(status for status, _, _ in responses) == [200, 429]
        accepted_headers = next(headers for status, headers, _ in responses if status == 200)
        session_id = response_session_id(accepted_headers)
        closed, _, _ = await call_asgi(
            listener.app,
            method="DELETE",
            headers=legacy_headers("tenant-example", session_id=session_id),
        )
        assert closed == 200
        await transport.stop()

    asyncio.run(exercise())


def test_client_disconnect_cancels_long_running_tool_and_releases_handler() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        provider = StaticContextProvider()
        endpoint = DisconnectingEndpoint((manifest("examples.echo"),))
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=provider,
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(endpoint)
        assert listener.app is not None

        incoming: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        sent: list[dict[str, Any]] = []
        received_body = False
        body = modern_request(
            "tools/call",
            params={"name": "examples.echo", "arguments": {"text": "hello"}},
        )

        async def receive() -> dict[str, Any]:
            nonlocal received_body
            if not received_body:
                received_body = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await incoming.get()

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        request_task = asyncio.create_task(
            listener.app(
                {
                    "type": "http",
                    "asgi": {"version": "3.0", "spec_version": "2.3"},
                    "http_version": "1.1",
                    "method": "POST",
                    "scheme": "http",
                    "path": "/mcp",
                    "raw_path": b"/mcp",
                    "query_string": b"",
                    "root_path": "",
                    "headers": modern_headers(
                        "tools/call",
                        name="examples.echo",
                    ),
                    "client": ("127.0.0.1", 50_000),
                    "server": ("127.0.0.1", 8_000),
                    "state": {},
                },
                receive,
                send,
            )
        )
        await asyncio.wait_for(endpoint.started.wait(), timeout=1.0)
        await incoming.put({"type": "http.disconnect"})
        await asyncio.wait_for(endpoint.released.wait(), timeout=1.0)
        await asyncio.wait_for(request_task, timeout=1.0)

        assert endpoint.observed_cancellation is True
        assert len(provider.cancellations) == 1
        assert provider.cancellations[0].cancelled is True
        await transport.stop()

    asyncio.run(exercise())


def test_stream_duration_cancels_work_and_returns_a_bounded_timeout() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        provider = StaticContextProvider()
        endpoint = DisconnectingEndpoint((manifest("examples.echo"),))
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(max_stream_seconds=0.01),
            context_provider=provider,
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(endpoint)
        assert listener.app is not None

        request = asyncio.create_task(
            call_asgi(
                listener.app,
                headers=modern_headers("tools/call", name="examples.echo"),
                body=modern_request(
                    "tools/call",
                    params={"name": "examples.echo", "arguments": {"text": "hello"}},
                ),
            )
        )
        await asyncio.wait_for(endpoint.started.wait(), timeout=1.0)
        status, _, response = await asyncio.wait_for(request, timeout=1.0)
        await asyncio.wait_for(endpoint.released.wait(), timeout=1.0)

        assert status == 504
        assert jsonrpc_code(response) == INTERNAL_ERROR
        document = json.loads(response)
        assert document["error"]["data"] == {
            "code": "timeout",
            "request_id": "request-example",
            "retryable": True,
        }
        assert len(response) < 512
        assert endpoint.observed_cancellation is True
        assert provider.cancellations[0].cancelled is True
        await transport.stop()

    asyncio.run(exercise())


def test_legacy_cancel_notification_reaches_long_running_tool() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        provider = StaticContextProvider()
        endpoint = DisconnectingEndpoint((manifest("examples.echo"),))
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(stateless=False),
            limits=StreamableHTTPLimits(),
            context_provider=provider,
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(endpoint)
        assert listener.app is not None

        initialized, initialized_headers, _ = await call_asgi(
            listener.app,
            body=legacy_initialize(),
        )
        assert initialized == 200
        session_id = response_session_id(initialized_headers)
        headers = legacy_headers("tenant-example", session_id=session_id)
        tool_call = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "examples.echo",
                    "arguments": {"text": "hello"},
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        call_task = asyncio.create_task(
            call_asgi(
                listener.app,
                headers=headers,
                body=tool_call,
                allow_no_response=True,
            )
        )
        await asyncio.wait_for(endpoint.started.wait(), timeout=1.0)

        cancelled_status, _, _ = await call_asgi(
            listener.app,
            headers=headers,
            body=b'{"jsonrpc":"2.0","method":"notifications/cancelled",'
            b'"params":{"requestId":7,"reason":"fixture cancellation"}}',
        )
        await asyncio.wait_for(endpoint.released.wait(), timeout=1.0)
        call_status, _, _ = await asyncio.wait_for(call_task, timeout=1.0)

        assert cancelled_status in {200, 202}
        assert call_status in {0, 200, 499}
        assert endpoint.observed_cancellation is True
        assert endpoint.contexts[0].cancellation.cancelled is True
        await transport.stop()

    asyncio.run(exercise())


def test_route_normalization_accepts_one_trailing_slash_and_hides_other_paths() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        provider = StaticContextProvider()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(path="//gateway//runtime//mcp//"),
            limits=StreamableHTTPLimits(),
            context_provider=provider,
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None
        discover = modern_request("server/discover")
        headers = modern_headers("server/discover")

        accepted, _, _ = await call_asgi(
            listener.app,
            path="/gateway/runtime/mcp/",
            headers=headers,
            body=discover,
        )
        missing, _, missing_body = await call_asgi(
            listener.app,
            path="/mcp",
            headers=headers,
            body=discover,
        )

        assert accepted == 200
        assert missing == 404
        assert b"tesserix" not in missing_body.lower()
        assert len(provider.requests) == 1
        await transport.stop()

    asyncio.run(exercise())


def test_same_listener_operational_routes_remain_available_during_drain() -> None:
    async def exercise() -> None:
        listener = FakeListener()
        provider = StaticContextProvider()
        endpoint = OperationalFakeEndpoint((manifest("examples.echo"),))
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=provider,
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(endpoint)
        assert listener.app is not None

        startup, startup_headers, startup_body = await call_asgi(
            listener.app,
            method="GET",
            path="/startupz",
        )
        liveness, _, liveness_body = await call_asgi(
            listener.app,
            method="GET",
            path="/livez",
        )
        readiness, _, readiness_body = await call_asgi(
            listener.app,
            method="GET",
            path="/readyz",
        )
        metrics, metrics_headers, metrics_body = await call_asgi(
            listener.app,
            method="GET",
            path="/metrics",
        )

        assert startup == 503
        assert json.loads(startup_body) == {"status": "starting"}
        assert (b"cache-control", b"no-store") in startup_headers
        assert liveness == 200
        assert json.loads(liveness_body) == {"status": "live"}
        assert readiness == 503
        assert json.loads(readiness_body) == {"status": "not_ready"}
        assert metrics == 200
        assert metrics_body == b'# TYPE mcp_fixture gauge\nmcp_fixture{server="fixture"} 1\n'
        assert any(
            name == b"content-type" and value.startswith(b"text/plain")
            for name, value in metrics_headers
        )
        assert provider.requests == []

        endpoint.started = True
        endpoint.ready = True
        assert (await call_asgi(listener.app, method="GET", path="/startupz"))[0] == 200
        assert (await call_asgi(listener.app, method="GET", path="/readyz"))[0] == 200

        await transport.drain(deadline=10.0)

        assert (await call_asgi(listener.app, method="GET", path="/readyz"))[0] == 503
        assert (await call_asgi(listener.app, method="GET", path="/livez"))[0] == 200
        assert (await call_asgi(listener.app, method="GET", path="/metrics"))[0] == 200
        assert endpoint.readiness_calls == 2
        await transport.stop()

    asyncio.run(exercise())


def test_context_and_header_failures_return_generic_bounded_responses() -> None:
    async def exercise() -> None:
        for provider, limits, extra_headers, expected_status in (
            (
                FailingContextProvider(),
                StreamableHTTPLimits(),
                (),
                401,
            ),
            (
                StaticContextProvider(),
                StreamableHTTPLimits(max_request_headers=3),
                ((b"authorization", b"Bearer fixture-value"),),
                431,
            ),
        ):
            listener = LifespanListener()
            transport = StreamableHTTPTransport(
                config=StreamableHTTPConfig(),
                limits=limits,
                context_provider=provider,
                telemetry=RecordingProtocolTelemetry(),
                listener=listener,
            )
            await transport.start(FakeEndpoint((manifest("examples.echo"),)))
            assert listener.app is not None
            status, _, body = await call_asgi(
                listener.app,
                headers=request_headers(*extra_headers),
                body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
            )
            assert status == expected_status
            assert len(body) < 256
            assert b"private" not in body
            assert b"fixture-value" not in body
            await transport.stop()

    asyncio.run(exercise())


def test_authentication_failure_carries_only_request_id_and_direct_peer() -> None:
    async def exercise() -> None:
        provider = RequestIDFailingContextProvider()
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=provider,
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None

        status, _, body = await call_asgi(
            listener.app,
            body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
        )

        document = json.loads(body)
        assert status == 401
        assert document["error"]["data"] == {"request_id": "authentication-request"}
        assert provider.peers == ["127.0.0.1"]
        assert b"authentication failed" not in body
        await transport.stop()

    asyncio.run(exercise())


def test_gateway_jwt_authenticates_before_parsing_and_isolates_tenants() -> None:
    now = 1_800_000_000
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    raw_public_key: object = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    assert isinstance(raw_public_key, dict)
    public_key = cast(dict[str, JsonValue], raw_public_key)
    public_key.update({"kid": "transport-key", "alg": "RS256", "use": "sig"})

    class CountingJWKSFetcher:
        def __init__(self) -> None:
            self.calls = 0

        async def fetch(self) -> dict[str, JsonValue]:
            self.calls += 1
            return {"keys": [public_key]}

    class TenantEchoEndpoint(FakeEndpoint):
        async def invoke(
            self,
            name: str,
            arguments: Mapping[str, JsonValue],
            *,
            context: CallContext,
        ) -> InvocationResult:
            self.contexts.append(context)
            if name not in self.list_tools():
                raise AssertionError("transport invoked an unknown fixture tool")
            return InvocationResult.success(
                {"text": f"{context.tenant}:{arguments.get('text', '')}"}
            )

    def token(*, subject: str, tenant: str, expires_at: int) -> str:
        encoded = jwt.encode(
            {
                "iss": "https://identity.example.invalid",
                "aud": "tesserix-mcp-runtime",
                "sub": subject,
                "tenant_id": tenant,
                "scope": "examples:read",
                "run_id": f"run-{tenant}",
                "iat": now - 10,
                "nbf": now - 10,
                "exp": expires_at,
            },
            private_key,
            algorithm="RS256",
            headers={"kid": "transport-key"},
        )
        assert isinstance(encoded, str)
        return encoded

    def headers(encoded: str, *, subject: str, tenant: str) -> list[tuple[bytes, bytes]]:
        return [
            *modern_headers("tools/call", name="examples.echo"),
            (b"authorization", f"Bearer {encoded}".encode("ascii")),
            (b"x-request-id", f"request-{tenant}".encode("ascii")),
            (b"x-jwt-claim-sub", subject.encode("ascii")),
            (b"x-jwt-claim-tenant-id", tenant.encode("ascii")),
            (b"x-jwt-claim-scope", b"examples:read"),
        ]

    async def exercise() -> None:
        fetcher = CountingJWKSFetcher()
        provider = GatewayJWTContextProvider(
            GatewayIdentityConfig(
                issuer="https://identity.example.invalid",
                audience="tesserix-mcp-runtime",
                jwks_url="https://identity.example.invalid/.well-known/jwks.json",
                jwks_allowed_hosts=("identity.example.invalid",),
                trusted_proxy_cidrs=("127.0.0.1/32",),
                clock_skew_seconds=0,
            ),
            jwks_fetcher=fetcher,
            wall_clock=lambda: float(now),
            request_id_factory=lambda: "generated-request",
        )
        endpoint = TenantEchoEndpoint((manifest("examples.echo"),))
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=provider,
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(endpoint)
        assert listener.app is not None

        expired_status, _, expired_body = await call_asgi(
            listener.app,
            headers=headers(
                token(subject="expired-subject", tenant="expired-tenant", expires_at=now - 1),
                subject="expired-subject",
                tenant="expired-tenant",
            ),
            body=b"{",
        )

        requests = (
            (
                token(subject="subject-a", tenant="tenant-a", expires_at=now + 300),
                "subject-a",
                "tenant-a",
                "first",
            ),
            (
                token(subject="subject-b", tenant="tenant-b", expires_at=now + 300),
                "subject-b",
                "tenant-b",
                "second",
            ),
        )
        responses = await asyncio.gather(
            *(
                call_asgi(
                    listener.app,
                    headers=headers(encoded, subject=subject, tenant=tenant),
                    body=modern_request(
                        "tools/call",
                        params={"name": "examples.echo", "arguments": {"text": text}},
                    ),
                )
                for encoded, subject, tenant, text in requests
            )
        )

        assert expired_status == 401
        assert jsonrpc_code(expired_body) != PARSE_ERROR
        assert [status for status, _, _ in responses] == [200, 200]
        assert [json.loads(body)["result"]["structuredContent"] for _, _, body in responses] == [
            {"text": "tenant-a:first"},
            {"text": "tenant-b:second"},
        ]
        assert [(context.tenant, context.subject) for context in endpoint.contexts] == [
            ("tenant-a", "subject-a"),
            ("tenant-b", "subject-b"),
        ]
        assert fetcher.calls == 1
        await transport.stop()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("body", "method", "expected_code"),
    [
        (b"{", "ping", PARSE_ERROR),
        (modern_request("unknown/method"), "unknown/method", METHOD_NOT_FOUND),
        (modern_request("ping", request_id={"bad": True}), "ping", INVALID_REQUEST),
        (
            b"[" + modern_request("ping") + b"," + modern_request("ping") + b"]",
            "ping",
            INVALID_REQUEST,
        ),
    ],
    ids=["malformed-json", "unknown-method", "invalid-id", "duplicate-id-batch"],
)
def test_malformed_protocol_messages_return_bounded_standard_errors(
    body: bytes,
    method: str,
    expected_code: int,
) -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None
        status, _, response = await call_asgi(
            listener.app,
            headers=modern_headers(method),
            body=body,
        )

        assert status in {200, 400, 404}
        assert jsonrpc_code(response) == expected_code
        assert len(response) < 512
        assert b"pydantic" not in response.lower()
        await transport.stop()

    asyncio.run(exercise())


def test_unsupported_protocol_revision_fails_with_standard_error() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None
        status, _, body = await call_asgi(
            listener.app,
            headers=modern_headers("server/discover", protocol_version="1900-01-01"),
            body=modern_request("server/discover", protocol_version="1900-01-01"),
        )

        assert status == 400
        assert jsonrpc_code(body) == UNSUPPORTED_PROTOCOL_VERSION
        assert b"2.1.1" not in body
        await transport.stop()

    asyncio.run(exercise())


def test_modern_protocol_rejects_removed_get_and_undeclared_subscriptions() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None

        get_status, _, _ = await call_asgi(
            listener.app,
            method="GET",
            headers=modern_headers("server/discover"),
        )
        subscription_status, _, subscription_body = await call_asgi(
            listener.app,
            headers=modern_headers("subscriptions/listen"),
            body=modern_request(
                "subscriptions/listen",
                params={"notifications": {"tools/list_changed": True}},
            ),
        )

        assert get_status == 405
        assert subscription_status == 404
        assert jsonrpc_code(subscription_body) == METHOD_NOT_FOUND
        await transport.stop()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("headers", "body"),
    [
        (
            modern_headers("server/discover", protocol_version="2026-07-28"),
            modern_request("server/discover", protocol_version="2025-11-25"),
        ),
        (
            modern_headers("tools/list"),
            modern_request("server/discover"),
        ),
    ],
)
def test_modern_protocol_rejects_routing_header_payload_mismatches(
    headers: list[tuple[bytes, bytes]],
    body: bytes,
) -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None

        status, _, response = await call_asgi(
            listener.app,
            headers=headers,
            body=body,
        )

        assert status == 400
        assert jsonrpc_code(response) == _ROUTING_HEADER_MISMATCH
        await transport.stop()

    asyncio.run(exercise())


def test_request_and_response_limits_fail_without_returning_tool_output() -> None:
    async def exercise() -> None:
        request_listener = LifespanListener()
        request_transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(max_request_body_bytes=128),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=request_listener,
        )
        await request_transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert request_listener.app is not None
        request_status, _, request_body = await call_asgi(
            request_listener.app,
            body=b"{" + b"x" * 256,
        )
        assert request_status == 413
        assert len(request_body) < 512
        await request_transport.stop()

        for endpoint, expected_status in (
            (LargeEndpoint((manifest("examples.echo"),)), 500),
            (UnserializableEndpoint((manifest("examples.echo"),)), 200),
        ):
            response_listener = LifespanListener()
            response_transport = StreamableHTTPTransport(
                config=StreamableHTTPConfig(),
                limits=StreamableHTTPLimits(max_response_body_bytes=300),
                context_provider=StaticContextProvider(),
                telemetry=RecordingProtocolTelemetry(),
                listener=response_listener,
            )
            await response_transport.start(endpoint)
            assert response_listener.app is not None
            response_status, _, response_body = await call_asgi(
                response_listener.app,
                headers=modern_headers("tools/call", name="examples.echo"),
                body=modern_request(
                    "tools/call",
                    params={"name": "examples.echo", "arguments": {"text": "hello"}},
                ),
            )
            assert response_status == expected_status
            assert len(response_body) <= 300
            assert b"private-result" not in response_body
            assert jsonrpc_code(response_body) == INTERNAL_ERROR
            await response_transport.stop()

    asyncio.run(exercise())


def test_near_limit_structured_result_is_not_duplicated_into_text_content() -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=StreamableHTTPLimits(),
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(NearEnvelopeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None

        status, _, body = await call_asgi(
            listener.app,
            headers=modern_headers("tools/call", name="examples.echo"),
            body=modern_request(
                "tools/call",
                params={"name": "examples.echo", "arguments": {"text": "hello"}},
            ),
        )

        assert status == 200
        assert len(body) <= 524_288
        document = json.loads(body)
        result = document["result"]
        assert result["content"] == []
        structured = result["structuredContent"]
        assert structured["request_bytes"] == 60_000
        assert structured["response_bytes"] == 500_000
        assert sum(len(chunk) for chunk in structured["chunks"]) == 500_000
        await transport.stop()

    asyncio.run(exercise())


_HEADER_TOKEN_BYTES = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz")


def _valid_asgi_header(name: bytes, value: bytes) -> bool:
    return (
        bool(name)
        and all(byte in _HEADER_TOKEN_BYTES for byte in name)
        and all(byte == 9 or byte >= 32 for byte in value)
        and 127 not in value
    )


@settings(
    max_examples=80,
    deadline=500,
    suppress_health_check=(HealthCheck.too_slow,),
)
@given(
    additional=st.lists(
        st.tuples(
            st.one_of(
                st.sampled_from(
                    [
                        b"mcp-method",
                        b"mcp-name",
                        b"mcp-protocol-version",
                        b"mcp-session-id",
                    ]
                ),
                st.binary(max_size=16),
            ),
            st.binary(max_size=48),
        ),
        max_size=20,
    )
)
def test_request_header_fuzz_is_bounded_and_rejects_invalid_octets(
    additional: list[tuple[bytes, bytes]],
) -> None:
    async def exercise() -> None:
        limits = StreamableHTTPLimits(
            max_request_headers=16,
            max_request_header_bytes=512,
            max_response_body_bytes=4_096,
        )
        listener = LifespanListener()
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=limits,
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None
        headers = request_headers(*additional)

        status, _, response = await call_asgi(
            listener.app,
            headers=headers,
            body=modern_request("ping"),
        )

        total_bytes = sum(len(name) + len(value) for name, value in headers)
        invalid = any(not _valid_asgi_header(name, value) for name, value in headers)
        if len(headers) > limits.max_request_headers or total_bytes > 512 or invalid:
            assert status == 431
        else:
            assert 200 <= status <= 499
        assert len(response) <= limits.max_response_body_bytes
        await transport.stop()

    asyncio.run(exercise())


@settings(
    max_examples=80,
    deadline=500,
    suppress_health_check=(HealthCheck.too_slow,),
)
@given(
    chunks=st.lists(
        st.binary(max_size=64),
        min_size=1,
        max_size=8,
    ).map(tuple)
)
def test_chunked_json_framing_fuzz_completes_with_atomic_bounded_responses(
    chunks: tuple[bytes, ...],
) -> None:
    async def exercise() -> None:
        listener = LifespanListener()
        limits = StreamableHTTPLimits(
            max_request_body_bytes=512,
            max_response_body_bytes=2_048,
        )
        transport = StreamableHTTPTransport(
            config=StreamableHTTPConfig(),
            limits=limits,
            context_provider=StaticContextProvider(),
            telemetry=RecordingProtocolTelemetry(),
            listener=listener,
        )
        await transport.start(FakeEndpoint((manifest("examples.echo"),)))
        assert listener.app is not None

        status, response_headers, response = await call_asgi(
            listener.app,
            headers=modern_headers("ping"),
            body_chunks=chunks,
        )

        assert 200 <= status <= 499
        assert len(response) <= limits.max_response_body_bytes
        content_lengths = [
            int(value.decode("ascii"))
            for name, value in response_headers
            if name.lower() == b"content-length"
        ]
        assert content_lengths == [len(response)]
        assert b"pydantic" not in response.lower()
        await transport.stop()

    asyncio.run(exercise())
