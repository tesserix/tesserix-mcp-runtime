"""Official MCP SDK v2 Streamable HTTP transport adapter."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import math
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from importlib.metadata import version as distribution_version
from typing import Any, Protocol, cast, runtime_checkable

import uvicorn
from mcp import types
from mcp.server import Server
from mcp.server.context import CallNext, HandlerResult, ServerMiddleware, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS

from tesserix_mcp_runtime.application import ApplicationEndpoint
from tesserix_mcp_runtime.contracts import (
    CallContext,
    Cancellation,
    InvocationStatus,
    JsonValue,
    Telemetry,
    ToolEffect,
)
from tesserix_mcp_runtime.tool_manifest import ToolManifest

type ASGIScope = dict[str, Any]
type ASGIMessage = dict[str, Any]
type ASGIReceive = Callable[[], Awaitable[ASGIMessage]]
type ASGISend = Callable[[ASGIMessage], Awaitable[None]]

_CALL_CONTEXT_SCOPE_KEY = "tesserix_mcp_runtime.call_context"
_MCP_PROTOCOL_VERSION_HEADER = "mcp-protocol-version"
_MCP_SESSION_ID_HEADER = "mcp-session-id"
_HTTP_HEADER_NAME_BYTES = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz")


@runtime_checkable
class ASGIApplication(Protocol):
    async def __call__(
        self,
        scope: ASGIScope,
        receive: ASGIReceive,
        send: ASGISend,
    ) -> None: ...


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


def _normalize_path(value: str) -> str:
    if not _is_runtime_instance(value, str) or not value or "?" in value or "#" in value:
        raise ValueError("path must be an absolute route without query or fragment")
    segments = tuple(segment for segment in value.split("/") if segment)
    if not segments or any(segment in {".", ".."} for segment in segments):
        raise ValueError("path must contain safe non-root segments")
    return "/" + "/".join(segments)


def _positive_integer(name: str, value: object) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{name} must be a positive integer")


def _positive_finite(name: str, value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{name} must be a positive finite number")


def _bounded_text_tuple(name: str, value: object) -> None:
    if not _is_runtime_instance(value, tuple):
        raise ValueError(f"{name} must be a bounded immutable tuple")
    items = cast(tuple[object, ...], value)
    if len(items) > 32:
        raise ValueError(f"{name} must be a bounded immutable tuple")
    for item in items:
        if (
            not isinstance(item, str)
            or not item
            or item != item.strip()
            or len(item) > 512
            or any(ord(character) < 32 for character in item)
        ):
            raise ValueError(f"{name} must contain bounded visible text")
    if len(set(items)) != len(items):
        raise ValueError(f"{name} must not contain duplicates")


@dataclass(frozen=True, slots=True, repr=False)
class HTTPRequestMetadata:
    """Bounded request metadata whose representation always redacts headers."""

    method: str
    path: str
    headers: tuple[tuple[str, str], ...]

    def header_values(self, name: str) -> tuple[str, ...]:
        normalized = name.casefold()
        return tuple(value for key, value in self.headers if key.casefold() == normalized)

    def __repr__(self) -> str:
        return (
            f"HTTPRequestMetadata(method={self.method!r}, path={self.path!r}, headers=[redacted])"
        )


@runtime_checkable
class HTTPCallContextProvider(Protocol):
    """Authenticate request metadata and produce one trusted core context."""

    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class ProtocolTelemetryEvent:
    """Payload-free protocol observation safe for metrics and traces."""

    method: str
    protocol_version: str
    sdk_version: str
    outcome: str

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("method", self.method, 128),
            ("protocol_version", self.protocol_version, 64),
            ("sdk_version", self.sdk_version, 64),
            ("outcome", self.outcome, 32),
        ):
            if (
                not _is_runtime_instance(value, str)
                or not value
                or value != value.strip()
                or len(value) > maximum
                or any(ord(character) < 32 for character in value)
            ):
                raise ValueError(f"{name} must be bounded visible text")


@runtime_checkable
class StreamableHTTPListener(Protocol):
    """Run one ASGI app behind a bounded private listener."""

    @property
    def bound_port(self) -> int: ...

    async def start(
        self,
        app: ASGIApplication,
        *,
        startup_timeout: float,
    ) -> None: ...

    async def stop(self) -> None: ...


class StreamableHTTPConfigurationError(RuntimeError):
    """Report a stable transport configuration failure without its value."""

    def __init__(self, code: str, path: str) -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code} at {path}")


@dataclass(frozen=True, slots=True, kw_only=True)
class StreamableHTTPConfig:
    """Listener and route configuration with private stateless defaults."""

    host: str = "127.0.0.1"
    port: int = 8_000
    path: str = "/mcp"
    stateless: bool = True
    allowed_hosts: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.host, str)
            or not self.host
            or self.host != self.host.strip()
            or len(self.host) > 253
            or any(ord(character) < 33 for character in self.host)
        ):
            raise ValueError("host must be a bounded listener name or address")
        if (
            not _is_runtime_instance(self.port, int)
            or _is_runtime_instance(self.port, bool)
            or not 1 <= self.port <= 65_535
        ):
            raise ValueError("port must be between 1 and 65535")
        if not _is_runtime_instance(self.stateless, bool):
            raise ValueError("stateless must be a boolean")
        _bounded_text_tuple("allowed_hosts", self.allowed_hosts)
        _bounded_text_tuple("allowed_origins", self.allowed_origins)
        if self.host not in {"127.0.0.1", "localhost", "::1"}:
            if not self.allowed_hosts:
                raise ValueError("allowed_hosts must be explicit for non-loopback listeners")
            if not self.allowed_origins:
                raise ValueError("allowed_origins must be explicit for non-loopback listeners")
        object.__setattr__(self, "path", _normalize_path(self.path))


@dataclass(frozen=True, slots=True, kw_only=True)
class StreamableHTTPLimits:
    """Finite protocol, discovery, session, and listener budgets."""

    max_request_body_bytes: int = 65_536
    max_request_headers: int = 128
    max_request_header_bytes: int = 32_768
    max_response_body_bytes: int = 524_288
    max_schema_bytes: int = 262_144
    max_tools: int = 128
    tool_page_size: int = 32
    max_tool_pages: int = 4
    max_sessions: int = 128
    session_lifetime_seconds: float = 1_800.0
    startup_timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        for name in (
            "max_request_body_bytes",
            "max_request_headers",
            "max_request_header_bytes",
            "max_response_body_bytes",
            "max_schema_bytes",
            "max_tools",
            "tool_page_size",
            "max_tool_pages",
            "max_sessions",
        ):
            _positive_integer(name, getattr(self, name))
        for name in ("session_lifetime_seconds", "startup_timeout_seconds"):
            _positive_finite(name, getattr(self, name))
        if self.tool_page_size * self.max_tool_pages < self.max_tools:
            raise ValueError("tool_page_size and max_tool_pages must cover max_tools")


class UvicornStreamableHTTPListener:
    """Run the transport with a hardened, readiness-aware Uvicorn server."""

    def __init__(self, *, host: str, port: int) -> None:
        if not _is_runtime_instance(host, str) or not host:
            raise ValueError("host must be a non-empty string")
        if (
            not _is_runtime_instance(port, int)
            or _is_runtime_instance(port, bool)
            or not 1 <= port <= 65_535
        ):
            raise ValueError("port must be between 1 and 65535")
        self._host = host
        self._port = port
        self._bound_port = port
        self._shutdown_timeout = 2.0
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task[None] | None = None

    @property
    def bound_port(self) -> int:
        return self._bound_port

    @staticmethod
    async def _wait_until_ready(
        server: uvicorn.Server,
        task: asyncio.Task[None],
    ) -> None:
        while not server.started:
            if task.done():
                await task
                raise RuntimeError("listener exited before startup")
            await asyncio.sleep(0)

    @staticmethod
    async def _terminate(
        server: uvicorn.Server,
        task: asyncio.Task[None],
        *,
        grace_period: float,
    ) -> None:
        server.should_exit = True
        done, _ = await asyncio.wait((task,), timeout=grace_period)
        if not done:
            server.force_exit = True
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    @staticmethod
    def _resolved_port(server: uvicorn.Server) -> int:
        if not server.servers:
            raise RuntimeError("listener has no bound server")
        sockets = server.servers[0].sockets
        if not sockets:
            raise RuntimeError("listener has no bound socket")
        address: object = sockets[0].getsockname()
        if not _is_runtime_instance(address, tuple):
            raise RuntimeError("listener has an invalid bound address")
        address_parts = cast(tuple[object, ...], address)
        if len(address_parts) < 2 or not _is_runtime_instance(address_parts[1], int):
            raise RuntimeError("listener has an invalid bound address")
        return cast(int, address_parts[1])

    async def start(
        self,
        app: ASGIApplication,
        *,
        startup_timeout: float,
    ) -> None:
        if self._task is not None:
            raise StreamableHTTPConfigurationError("listener_already_started", "listener")
        _positive_finite("startup_timeout", startup_timeout)
        config = uvicorn.Config(
            app=app,
            host=self._host,
            port=self._port,
            access_log=False,
            date_header=False,
            lifespan="on",
            log_level="warning",
            proxy_headers=False,
            server_header=False,
        )
        server = uvicorn.Server(config)
        mutable_server = cast(Any, server)
        mutable_server.capture_signals = contextlib.nullcontext
        task = asyncio.create_task(server.serve(), name="tesserix-mcp-http-listener")
        self._server = server
        self._task = task
        self._shutdown_timeout = startup_timeout
        try:
            await asyncio.wait_for(
                self._wait_until_ready(server, task),
                timeout=startup_timeout,
            )
            self._bound_port = self._resolved_port(server)
        except TimeoutError:
            await self._terminate(server, task, grace_period=startup_timeout)
            self._server = None
            self._task = None
            raise StreamableHTTPConfigurationError(
                "listener_start_timeout",
                "listener",
            ) from None
        except asyncio.CancelledError:
            await self._terminate(server, task, grace_period=startup_timeout)
            self._server = None
            self._task = None
            raise
        except Exception:
            await self._terminate(server, task, grace_period=startup_timeout)
            self._server = None
            self._task = None
            raise StreamableHTTPConfigurationError(
                "listener_start_failed",
                "listener",
            ) from None

    async def stop(self) -> None:
        server = self._server
        task = self._task
        if server is None or task is None:
            return
        self._server = None
        self._task = None
        await self._terminate(server, task, grace_period=self._shutdown_timeout)


class _RequestCancellation:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()

    def cancel(self) -> None:
        self._event.set()


@dataclass(slots=True)
class _SessionRecord:
    owner: tuple[str, str, str]
    expires_at: float
    in_flight: int = 0
    expired: bool = False


@dataclass(frozen=True, slots=True)
class _SessionLease:
    session_id: str | None = None
    reserved: bool = False
    owner: tuple[str, str, str] | None = None


class _SessionAdmissionError(Exception):
    def __init__(self, *, status: int, code: int, message: str) -> None:
        self.status = status
        self.code = code
        self.message = message
        super().__init__(message)


def _safe_observation(value: object, *, maximum: int, fallback: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        return fallback
    return value


def _headers(scope: ASGIScope, limits: StreamableHTTPLimits) -> tuple[tuple[str, str], ...]:
    raw_headers_value: object = scope.get("headers")
    if not _is_runtime_instance(raw_headers_value, list):
        raise ValueError("request headers exceed configured limit")
    raw_headers = cast(list[object], raw_headers_value)
    if len(raw_headers) > limits.max_request_headers:
        raise ValueError("request headers exceed configured limit")
    parsed: list[tuple[str, str]] = []
    total = 0
    for item in raw_headers:
        if not _is_runtime_instance(item, tuple):
            raise ValueError("request headers are malformed")
        pair = cast(tuple[object, ...], item)
        if (
            len(pair) != 2
            or not _is_runtime_instance(pair[0], bytes)
            or not _is_runtime_instance(pair[1], bytes)
        ):
            raise ValueError("request headers are malformed")
        raw_name = cast(bytes, pair[0])
        raw_value = cast(bytes, pair[1])
        if (
            not raw_name
            or any(byte not in _HTTP_HEADER_NAME_BYTES for byte in raw_name)
            or any(byte != 9 and (byte < 32 or byte == 127) for byte in raw_value)
        ):
            raise ValueError("request headers are malformed")
        total += len(raw_name) + len(raw_value)
        if total > limits.max_request_header_bytes:
            raise ValueError("request headers exceed configured limit")
        name = raw_name.decode("ascii")
        value = raw_value.decode("latin-1")
        parsed.append((name, value))
    return tuple(parsed)


def _response_header_pairs(value: object) -> list[tuple[bytes, bytes]]:
    if value is None:
        return []
    if not _is_runtime_instance(value, list):
        raise TypeError("ASGI response headers must be a list")
    result: list[tuple[bytes, bytes]] = []
    for item in cast(list[object], value):
        if not _is_runtime_instance(item, tuple):
            raise TypeError("ASGI response header must be a pair")
        pair = cast(tuple[object, ...], item)
        if (
            len(pair) != 2
            or not _is_runtime_instance(pair[0], bytes)
            or not _is_runtime_instance(pair[1], bytes)
        ):
            raise TypeError("ASGI response header must contain bytes")
        result.append((cast(bytes, pair[0]), cast(bytes, pair[1])))
    return result


async def _send_json(
    send: ASGISend,
    *,
    status: int,
    body: bytes,
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _protocol_error_body(*, code: int, message: str) -> bytes:
    return (
        types.JSONRPCError(
            jsonrpc="2.0",
            id=None,
            error=types.ErrorData(code=code, message=message),
        )
        .model_dump_json(by_alias=True, exclude_unset=True)
        .encode("utf-8")
    )


class _AtomicResponseLimiter:
    def __init__(self, send: ASGISend, *, maximum: int) -> None:
        self._send = send
        self._maximum = maximum
        self._start: ASGIMessage | None = None
        self._body = bytearray()
        self.ready = False
        self.committed = False
        self.completed = False

    async def __call__(self, message: ASGIMessage) -> None:
        message_type = message.get("type")
        if message_type == "http.response.start":
            self._start = dict(message)
            return
        if message_type != "http.response.body":
            await self._send(message)
            return
        body_value: object = message.get("body", b"")
        if not _is_runtime_instance(body_value, bytes):
            raise TypeError("ASGI response body must be bytes")
        body = cast(bytes, body_value)
        if len(self._body) + len(body) > self._maximum:
            raise OverflowError("response exceeds configured limit")
        self._body.extend(body)
        if message.get("more_body", False):
            return
        start = self._start
        if start is None:
            raise RuntimeError("ASGI response did not start")
        self.ready = True

    @property
    def status(self) -> int:
        start = self._start
        status: object = None if start is None else start.get("status")
        if not self.ready or not _is_runtime_instance(status, int):
            raise RuntimeError("ASGI response is not ready")
        return cast(int, status)

    def header_values(self, name: bytes) -> tuple[bytes, ...]:
        start = self._start
        if not self.ready or start is None:
            raise RuntimeError("ASGI response is not ready")
        normalized = name.lower()
        values: list[bytes] = []
        for header_name, value in _response_header_pairs(start.get("headers")):
            if header_name.lower() == normalized:
                values.append(value)
        return tuple(values)

    async def flush(self) -> None:
        start = self._start
        if not self.ready or start is None:
            raise RuntimeError("ASGI response did not complete")
        headers = [
            item
            for item in _response_header_pairs(start.get("headers"))
            if item[0].lower() != b"content-length"
        ]
        headers.append((b"content-length", str(len(self._body)).encode("ascii")))
        start["headers"] = headers
        self.committed = True
        await self._send(start)
        await self._send(
            {
                "type": "http.response.body",
                "body": bytes(self._body),
                "more_body": False,
            }
        )
        self.completed = True


class _ProtocolTelemetryMiddleware:
    def __init__(self, transport: StreamableHTTPTransport) -> None:
        self._transport = transport

    async def __call__(
        self,
        context: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        if context.method == "notifications/cancelled":
            self._transport.cancel_protocol_request(context)
        try:
            result = await call_next(context)
        except BaseException:
            self._transport.emit_protocol_event(context, outcome="failed")
            raise
        self._transport.emit_protocol_event(context, outcome="completed")
        return result


class _ProtocolASGIApp:
    def __init__(self, transport: StreamableHTTPTransport, sdk_app: ASGIApplication) -> None:
        self._transport = transport
        self._sdk_app = sdk_app

    async def __call__(
        self,
        scope: ASGIScope,
        receive: ASGIReceive,
        send: ASGISend,
    ) -> None:
        if scope.get("type") != "http":
            await self._sdk_app(scope, receive, send)
            return
        configured_path = self._transport.config.path
        request_path = scope.get("path")
        if request_path not in {configured_path, f"{configured_path}/"}:
            await _send_json(
                send,
                status=404,
                body=_protocol_error_body(code=types.INVALID_REQUEST, message="Not found"),
            )
            return
        if not self._transport.accepting:
            await _send_json(
                send,
                status=503,
                body=_protocol_error_body(code=types.INTERNAL_ERROR, message="Unavailable"),
            )
            return
        try:
            headers = _headers(scope, self._transport.limits)
        except ValueError:
            await _send_json(
                send,
                status=431,
                body=_protocol_error_body(code=types.INVALID_REQUEST, message="Invalid headers"),
            )
            return
        session_ids = tuple(value for name, value in headers if name == _MCP_SESSION_ID_HEADER)
        if self._transport.config.stateless and session_ids:
            await _send_json(
                send,
                status=404,
                body=_protocol_error_body(code=types.INVALID_REQUEST, message="Invalid session"),
            )
            return
        try:
            request = HTTPRequestMetadata(
                method=_safe_observation(scope.get("method"), maximum=16, fallback="UNKNOWN"),
                path=configured_path,
                headers=headers,
            )
            cancellation = _RequestCancellation()
            context = await self._transport.context_provider.create(
                request,
                cancellation=cancellation,
            )
            if (
                not _is_runtime_instance(context, CallContext)
                or context.cancellation is not cancellation
            ):
                raise ValueError("context provider returned an invalid context")
        except Exception:
            await _send_json(
                send,
                status=401,
                body=_protocol_error_body(code=types.INVALID_REQUEST, message="Unauthorized"),
            )
            return
        try:
            lease = await self._transport.admit_session(headers, context)
        except _SessionAdmissionError as error:
            await _send_json(
                send,
                status=error.status,
                body=_protocol_error_body(code=error.code, message=error.message),
            )
            return
        except Exception:
            await _send_json(
                send,
                status=500,
                body=_protocol_error_body(code=types.INTERNAL_ERROR, message="Internal error"),
            )
            return

        adapted_scope = dict(scope)
        adapted_scope["path"] = configured_path
        adapted_scope[_CALL_CONTEXT_SCOPE_KEY] = context
        limiter = _AtomicResponseLimiter(
            send,
            maximum=self._transport.limits.max_response_body_bytes,
        )
        cancellation_body = bytearray()
        cancellation_body_bounded = True
        cancellation_body_complete = False
        request_session_id = session_ids[0] if len(session_ids) == 1 else None

        async def receive_with_cancellation() -> ASGIMessage:
            nonlocal cancellation_body_bounded, cancellation_body_complete
            message = await receive()
            if message.get("type") == "http.disconnect":
                cancellation.cancel()
            elif message.get("type") == "http.request" and not cancellation_body_complete:
                chunk = message.get("body", b"")
                if isinstance(chunk, bytes) and cancellation_body_bounded:
                    if (
                        len(cancellation_body) + len(chunk)
                        <= self._transport.limits.max_request_body_bytes
                    ):
                        cancellation_body.extend(chunk)
                    else:
                        cancellation_body.clear()
                        cancellation_body_bounded = False
                if not message.get("more_body", False):
                    cancellation_body_complete = True
                    if cancellation_body_bounded:
                        self._transport.cancel_protocol_request_body(
                            request_session_id,
                            bytes(cancellation_body),
                        )
            return message

        lease_completed = False
        try:
            await self._sdk_app(adapted_scope, receive_with_cancellation, limiter)
            if cancellation.cancelled:
                await self._transport.abort_session(lease)
                lease_completed = True
                return
            try:
                await self._transport.complete_session(
                    lease,
                    limiter,
                    request_method=request.method.upper(),
                )
            finally:
                lease_completed = True
            await limiter.flush()
        except asyncio.CancelledError:
            cancellation.cancel()
            if not lease_completed:
                await self._transport.abort_session(lease)
            raise
        except Exception:
            if not lease_completed:
                with contextlib.suppress(Exception):
                    await self._transport.abort_session(lease)
            if not limiter.committed:
                await _send_json(
                    send,
                    status=500,
                    body=_protocol_error_body(code=types.INTERNAL_ERROR, message="Internal error"),
                )


def _mcp_tool(manifest: ToolManifest) -> types.Tool:
    metadata = manifest.metadata
    return types.Tool(
        name=metadata.name,
        title=metadata.title,
        description=metadata.description,
        input_schema=manifest.input_schema,
        output_schema=manifest.output_schema,
        annotations=types.ToolAnnotations(
            title=metadata.title,
            read_only_hint=metadata.effect is ToolEffect.READ,
            idempotent_hint=metadata.idempotency.value == "required",
            open_world_hint=metadata.effect is ToolEffect.EXTERNAL_EFFECT,
        ),
        _meta={"com.tesserix/runtime": metadata.to_dict()},
    )


class StreamableHTTPTransport:
    """Bind core application behavior to the official MCP HTTP server surface."""

    name = "mcp_streamable_http_transport"

    def __init__(
        self,
        *,
        config: StreamableHTTPConfig,
        limits: StreamableHTTPLimits,
        context_provider: HTTPCallContextProvider,
        telemetry: Telemetry[ProtocolTelemetryEvent],
        listener: StreamableHTTPListener | None = None,
    ) -> None:
        resolved_listener = listener
        if resolved_listener is None:
            resolved_listener = UvicornStreamableHTTPListener(
                host=config.host,
                port=config.port,
            )
        dependencies: tuple[tuple[str, object, type[Any]], ...] = (
            ("config", config, StreamableHTTPConfig),
            ("limits", limits, StreamableHTTPLimits),
            ("context_provider", context_provider, HTTPCallContextProvider),
            ("telemetry", telemetry, Telemetry),
            ("listener", resolved_listener, StreamableHTTPListener),
        )
        for path, dependency, expected in dependencies:
            if not _is_runtime_instance(dependency, expected):
                raise StreamableHTTPConfigurationError("invalid_dependency", path)
        self._config = config
        self._limits = limits
        self._context_provider = context_provider
        self._telemetry = telemetry
        self._listener = resolved_listener
        self._endpoint: ApplicationEndpoint | None = None
        self._manifests: tuple[ToolManifest, ...] = ()
        self._catalog_token = ""
        self._accepting = False
        self._session_lock = asyncio.Lock()
        self._sessions: dict[str, _SessionRecord] = {}
        self._pending_sessions = 0
        self._active_protocol_requests: dict[
            tuple[str | None, str, int | str],
            _RequestCancellation,
        ] = {}
        self.sdk_version = distribution_version("mcp")
        self._telemetry_failures = 0
        self._server = Server(
            "tesserix-mcp-runtime",
            version=distribution_version("tesserix-mcp-runtime"),
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )
        middleware = cast(ServerMiddleware[Any], _ProtocolTelemetryMiddleware(self))
        self._server.middleware.append(middleware)
        security_settings = self._security_settings()
        sdk_app = self._server.streamable_http_app(
            streamable_http_path=config.path,
            json_response=False,
            stateless_http=config.stateless,
            max_request_body_size=limits.max_request_body_bytes,
            transport_security=security_settings,
            host=config.host,
        )
        self._app: ASGIApplication = _ProtocolASGIApp(
            self,
            cast(ASGIApplication, cast(Any, sdk_app)),
        )

    @property
    def accepting(self) -> bool:
        return self._accepting

    @property
    def bound_port(self) -> int:
        return self._listener.bound_port

    @property
    def telemetry_failures(self) -> int:
        return self._telemetry_failures

    @property
    def config(self) -> StreamableHTTPConfig:
        return self._config

    @property
    def limits(self) -> StreamableHTTPLimits:
        return self._limits

    @property
    def context_provider(self) -> HTTPCallContextProvider:
        return self._context_provider

    @staticmethod
    def _session_owner(context: CallContext) -> tuple[str, str, str]:
        identity = context.identity
        return (identity.tenant, identity.issuer, identity.subject)

    @staticmethod
    def _valid_session_id(value: str) -> bool:
        return len(value) == 32 and all(character in "0123456789abcdef" for character in value)

    def _expired_sessions_locked(self, now: float) -> list[str]:
        expired: list[str] = []
        for session_id, record in tuple(self._sessions.items()):
            if now < record.expires_at:
                continue
            record.expired = True
            if record.in_flight == 0:
                del self._sessions[session_id]
                expired.append(session_id)
        return expired

    async def _remove_sdk_session(self, session_id: str, *, terminate: bool) -> None:
        manager = self._server.session_manager
        instances_value: object = getattr(manager, "_server_instances", None)
        owners_value: object = getattr(manager, "_session_owners", None)
        if not _is_runtime_instance(instances_value, dict) or not _is_runtime_instance(
            owners_value, dict
        ):
            raise RuntimeError("SDK session registry is unavailable")
        instances = cast(dict[str, object], instances_value)
        owners = cast(dict[str, object], owners_value)
        sdk_transport = instances.pop(session_id, None)
        owners.pop(session_id, None)
        if not terminate or sdk_transport is None:
            return
        terminate_session: object = getattr(sdk_transport, "terminate", None)
        if not callable(terminate_session):
            raise RuntimeError("SDK session cannot be terminated")
        completion: object = terminate_session()
        if not _is_runtime_instance(completion, Awaitable):
            raise RuntimeError("SDK session termination is not awaitable")
        await cast(Awaitable[object], completion)

    async def _remove_sdk_sessions(self, session_ids: list[str]) -> None:
        for session_id in session_ids:
            await self._remove_sdk_session(session_id, terminate=True)

    async def admit_session(
        self,
        headers: tuple[tuple[str, str], ...],
        context: CallContext,
    ) -> _SessionLease:
        if self._config.stateless:
            return _SessionLease()
        session_ids = tuple(value for name, value in headers if name == _MCP_SESSION_ID_HEADER)
        protocol_versions = tuple(
            value for name, value in headers if name == _MCP_PROTOCOL_VERSION_HEADER
        )
        if len(session_ids) > 1 or len(protocol_versions) > 1:
            raise _SessionAdmissionError(
                status=400,
                code=types.INVALID_REQUEST,
                message="Invalid session",
            )

        owner = self._session_owner(context)
        now = time.monotonic()
        expired: list[str]
        rejection: _SessionAdmissionError | None = None
        lease = _SessionLease()
        async with self._session_lock:
            expired = self._expired_sessions_locked(now)
            if session_ids:
                session_id = session_ids[0]
                record = self._sessions.get(session_id)
                if (
                    not self._valid_session_id(session_id)
                    or record is None
                    or record.expired
                    or record.owner != owner
                ):
                    rejection = _SessionAdmissionError(
                        status=404,
                        code=types.INVALID_REQUEST,
                        message="Invalid session",
                    )
                else:
                    record.in_flight += 1
                    lease = _SessionLease(session_id=session_id)
            elif protocol_versions and protocol_versions[0] in HANDSHAKE_PROTOCOL_VERSIONS:
                rejection = _SessionAdmissionError(
                    status=404,
                    code=types.INVALID_REQUEST,
                    message="Invalid session",
                )
            elif protocol_versions:
                lease = _SessionLease()
            elif len(self._sessions) + self._pending_sessions >= self._limits.max_sessions:
                rejection = _SessionAdmissionError(
                    status=429,
                    code=types.INTERNAL_ERROR,
                    message="Session limit reached",
                )
            else:
                self._pending_sessions += 1
                lease = _SessionLease(reserved=True, owner=owner)
        await self._remove_sdk_sessions(expired)
        if rejection is not None:
            raise rejection
        return lease

    async def _release_session(
        self,
        session_id: str,
        *,
        remove: bool,
        terminate: bool,
    ) -> None:
        should_remove = False
        should_terminate = terminate
        async with self._session_lock:
            record = self._sessions.get(session_id)
            if record is None:
                return
            if record.in_flight > 0:
                record.in_flight -= 1
            if remove:
                del self._sessions[session_id]
                should_remove = True
            elif record.expired and record.in_flight == 0:
                del self._sessions[session_id]
                should_remove = True
                should_terminate = True
        if should_remove:
            await self._remove_sdk_session(session_id, terminate=should_terminate)

    async def abort_session(self, lease: _SessionLease) -> None:
        if lease.reserved:
            async with self._session_lock:
                if self._pending_sessions < 1:
                    raise RuntimeError("session reservation underflow")
                self._pending_sessions -= 1
            return
        if lease.session_id is not None:
            await self._release_session(
                lease.session_id,
                remove=False,
                terminate=False,
            )

    async def complete_session(
        self,
        lease: _SessionLease,
        response: _AtomicResponseLimiter,
        *,
        request_method: str,
    ) -> None:
        if lease.reserved:
            response_session_ids = response.header_values(b"mcp-session-id")
            session_id: str | None = None
            if len(response_session_ids) == 1:
                try:
                    session_id = response_session_ids[0].decode("ascii")
                except UnicodeError:
                    session_id = None
            successful = 200 <= response.status < 300
            registered = False
            async with self._session_lock:
                if self._pending_sessions < 1:
                    raise RuntimeError("session reservation underflow")
                self._pending_sessions -= 1
                if (
                    successful
                    and session_id is not None
                    and self._valid_session_id(session_id)
                    and session_id not in self._sessions
                    and lease.owner is not None
                ):
                    self._sessions[session_id] = _SessionRecord(
                        owner=lease.owner,
                        expires_at=time.monotonic() + self._limits.session_lifetime_seconds,
                    )
                    registered = True
            if session_id is not None and not registered:
                await self._remove_sdk_session(session_id, terminate=True)
            if successful and not registered:
                raise RuntimeError("SDK returned an invalid session")
            return
        if lease.session_id is not None:
            closed = request_method == "DELETE" and 200 <= response.status < 300
            await self._release_session(
                lease.session_id,
                remove=closed,
                terminate=False,
            )

    def _security_settings(self) -> TransportSecuritySettings | None:
        if not self._config.allowed_hosts:
            return None
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(self._config.allowed_hosts),
            allowed_origins=list(self._config.allowed_origins),
        )

    @staticmethod
    def _protocol_session_id(context: ServerRequestContext[Any, Any]) -> str | None:
        request = context.request
        scope_value: object = getattr(request, "scope", None)
        if not _is_runtime_instance(scope_value, dict):
            return None
        scope = cast(dict[str, object], scope_value)
        raw_headers_value: object = scope.get("headers")
        if not _is_runtime_instance(raw_headers_value, list):
            return None
        values: list[str] = []
        for item in cast(list[object], raw_headers_value):
            if not _is_runtime_instance(item, tuple):
                continue
            pair = cast(tuple[object, ...], item)
            if (
                len(pair) == 2
                and _is_runtime_instance(pair[0], bytes)
                and _is_runtime_instance(pair[1], bytes)
                and cast(bytes, pair[0]).lower() == b"mcp-session-id"
            ):
                values.append(cast(bytes, pair[1]).decode("latin-1"))
        return values[0] if len(values) == 1 else None

    @classmethod
    def _protocol_request_key(
        cls,
        context: ServerRequestContext[Any, Any],
        request_id: object,
    ) -> tuple[str | None, str, int | str] | None:
        return cls._protocol_request_key_for(
            cls._protocol_session_id(context),
            request_id,
        )

    @staticmethod
    def _protocol_request_key_for(
        session_id: str | None,
        request_id: object,
    ) -> tuple[str | None, str, int | str] | None:
        if isinstance(request_id, bool) or not isinstance(request_id, int | str):
            return None
        kind = "integer" if isinstance(request_id, int) else "string"
        return (session_id, kind, request_id)

    def _cancel_protocol_request_id(
        self,
        session_id: str | None,
        request_id: object,
    ) -> None:
        key = self._protocol_request_key_for(session_id, request_id)
        if key is None:
            return
        cancellation = self._active_protocol_requests.get(key)
        if cancellation is not None:
            cancellation.cancel()

    def cancel_protocol_request_body(
        self,
        session_id: str | None,
        body: bytes,
    ) -> None:
        try:
            document_value: object = json.loads(body)
        except (RecursionError, UnicodeError, ValueError):
            return
        if not _is_runtime_instance(document_value, dict):
            return
        document = cast(dict[object, object], document_value)
        if document.get("method") != "notifications/cancelled":
            return
        params_value = document.get("params")
        if not _is_runtime_instance(params_value, dict):
            return
        params = cast(dict[object, object], params_value)
        self._cancel_protocol_request_id(session_id, params.get("requestId"))

    def cancel_protocol_request(self, context: ServerRequestContext[Any, Any]) -> None:
        params_value: object = context.params
        if not _is_runtime_instance(params_value, Mapping):
            return
        params = cast(Mapping[str, object], params_value)
        request_id = params.get("requestId", params.get("request_id"))
        self._cancel_protocol_request_id(self._protocol_session_id(context), request_id)

    def emit_protocol_event(
        self,
        context: ServerRequestContext[Any, Any],
        *,
        outcome: str,
    ) -> None:
        event = ProtocolTelemetryEvent(
            method=_safe_observation(context.method, maximum=128, fallback="invalid"),
            protocol_version=_safe_observation(
                context.protocol_version,
                maximum=64,
                fallback="unknown",
            ),
            sdk_version=self.sdk_version,
            outcome=outcome,
        )
        try:
            self._telemetry.emit(event)
        except Exception:
            self._telemetry_failures += 1

    def _encode_cursor(self, page: int) -> str:
        payload = f"v1:{self._catalog_token}:{page}".encode("ascii")
        return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")

    def _decode_cursor(self, cursor: str) -> int:
        if not cursor or len(cursor) > 256:
            raise MCPError(types.INVALID_PARAMS, "Invalid cursor")
        try:
            padding = "=" * (-len(cursor) % 4)
            payload = base64.b64decode(
                f"{cursor}{padding}",
                altchars=b"-_",
                validate=True,
            ).decode("ascii")
            version, token, page_text = payload.split(":", maxsplit=2)
            page = int(page_text)
        except (UnicodeError, ValueError):
            raise MCPError(types.INVALID_PARAMS, "Invalid cursor") from None
        if (
            version != "v1"
            or token != self._catalog_token
            or page < 1
            or page >= self._limits.max_tool_pages
        ):
            raise MCPError(types.INVALID_PARAMS, "Invalid cursor")
        return page

    async def _list_tools(
        self,
        context: ServerRequestContext[Any, Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        del context
        page = 0 if params is None or params.cursor is None else self._decode_cursor(params.cursor)
        start = page * self._limits.tool_page_size
        if start >= len(self._manifests) and start != 0:
            raise MCPError(types.INVALID_PARAMS, "Invalid cursor")
        end = min(start + self._limits.tool_page_size, len(self._manifests))
        next_cursor = self._encode_cursor(page + 1) if end < len(self._manifests) else None
        return types.ListToolsResult(
            tools=[_mcp_tool(manifest) for manifest in self._manifests[start:end]],
            next_cursor=next_cursor,
        )

    @staticmethod
    def _call_context(context: ServerRequestContext[Any, Any]) -> CallContext:
        request = context.request
        scope_value: object = getattr(request, "scope", None)
        if not _is_runtime_instance(scope_value, dict):
            raise MCPError(types.INTERNAL_ERROR, "Internal error")
        scope = cast(dict[str, object], scope_value)
        call_context = scope.get(_CALL_CONTEXT_SCOPE_KEY)
        if not _is_runtime_instance(call_context, CallContext):
            raise MCPError(types.INTERNAL_ERROR, "Internal error")
        return cast(CallContext, call_context)

    async def _call_tool(
        self,
        request_context: ServerRequestContext[Any, Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        endpoint = self._endpoint
        if endpoint is None:
            raise MCPError(types.INTERNAL_ERROR, "Internal error")
        call_context = self._call_context(request_context)
        arguments: dict[str, JsonValue] = dict((params.arguments or {}).items())
        cancellation = call_context.cancellation
        request_key = self._protocol_request_key(
            request_context,
            request_context.request_id,
        )
        if isinstance(cancellation, _RequestCancellation) and request_key is not None:
            previous = self._active_protocol_requests.get(request_key)
            if previous is not None:
                previous.cancel()
            self._active_protocol_requests[request_key] = cancellation
        try:
            result = await endpoint.invoke(params.name, arguments, context=call_context)
        except asyncio.CancelledError:
            if isinstance(cancellation, _RequestCancellation):
                cancellation.cancel()
            raise
        finally:
            if (
                request_key is not None
                and self._active_protocol_requests.get(request_key) is cancellation
            ):
                del self._active_protocol_requests[request_key]
        task = asyncio.current_task()
        if (
            task is not None
            and task.cancelling()
            and isinstance(
                call_context.cancellation,
                _RequestCancellation,
            )
        ):
            call_context.cancellation.cancel()
        if result.status is InvocationStatus.FAILURE:
            error = result.error
            if error is None:
                raise MCPError(types.INTERNAL_ERROR, "Internal error")
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        text=json.dumps(
                            error.to_dict(),
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                    )
                ],
                is_error=True,
            )
        value = result.value
        return types.CallToolResult(
            content=[
                types.TextContent(
                    text=json.dumps(
                        value,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
            ],
            structured_content=value,
            is_error=False,
        )

    async def start(self, endpoint: ApplicationEndpoint) -> None:
        manifests = endpoint.list_tool_manifests()
        if len(manifests) > self._limits.max_tools:
            raise StreamableHTTPConfigurationError(
                "tool_limit_exceeded",
                "endpoint.manifests",
            )
        schema_bytes = sum(
            len(
                json.dumps(
                    [manifest.input_schema, manifest.output_schema],
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            )
            for manifest in manifests
        )
        if schema_bytes > self._limits.max_schema_bytes:
            raise StreamableHTTPConfigurationError(
                "schema_limit_exceeded",
                "endpoint.manifests",
            )
        self._endpoint = endpoint
        self._manifests = manifests
        self._catalog_token = hashlib.sha256(
            "\0".join(
                f"{manifest.normalized_name}:{manifest.contract_fingerprint}"
                for manifest in manifests
            ).encode("utf-8")
        ).hexdigest()[:24]
        await self._listener.start(
            self._app,
            startup_timeout=self._limits.startup_timeout_seconds,
        )
        self._accepting = True

    async def drain(self, *, deadline: float) -> None:
        del deadline
        self._accepting = False

    async def stop(self) -> None:
        self._accepting = False
        await self._listener.stop()
        async with self._session_lock:
            self._sessions.clear()
            self._pending_sessions = 0
        self._active_protocol_requests.clear()
        self._endpoint = None
        self._manifests = ()
        self._catalog_token = ""


__all__ = [
    "ASGIApplication",
    "HTTPCallContextProvider",
    "HTTPRequestMetadata",
    "ProtocolTelemetryEvent",
    "StreamableHTTPConfig",
    "StreamableHTTPConfigurationError",
    "StreamableHTTPLimits",
    "StreamableHTTPListener",
    "StreamableHTTPTransport",
    "UvicornStreamableHTTPListener",
]
