"""HTTPS egress with exact destinations, connect-time IP checks, and finite I/O."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import socket
import ssl
from collections.abc import AsyncIterable, AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast, runtime_checkable
from urllib.parse import parse_qsl, unquote, urlsplit

import httpcore
import httpx

from tesserix_mcp_runtime.contracts import ErrorCode, ErrorResponse, JsonValue
from tesserix_mcp_runtime.egress import (
    EgressDestination,
    EgressPolicy,
    EgressPolicyViolation,
)
from tesserix_mcp_runtime.errors import RuntimeFailure
from tesserix_mcp_runtime.redaction import (
    REDACTED_TEXT,
    RedactionError,
    RedactionPolicy,
    SecretValue,
    is_secret_key,
)

_METHOD = re.compile(r"[A-Z]{1,16}\Z")
_ALLOWED_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")
_INVALID_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "www-authenticate",
        "proxy-authenticate",
        "x-api-key",
    }
)
_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "accept-encoding",
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-http-method-override",
        "x-method-override",
    }
)
_MAX_REQUEST_BYTES = 1_048_576
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_REDIRECTS = 10
_MAX_TIMEOUT = 30.0
_MAX_CONNECTIONS = 256
_MAX_HEADERS = 128
_MAX_HEADER_BYTES = 65_536


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


@dataclass(frozen=True, slots=True, kw_only=True)
class OutboundHTTPLimits:
    max_request_bytes: int = 262_144
    max_response_bytes: int = _MAX_RESPONSE_BYTES
    max_redirects: int = 3
    request_timeout: float = 10.0
    max_connections: int = 32
    max_headers: int = 64
    max_header_bytes: int = 32_768

    def __post_init__(self) -> None:
        positive_integers = (
            (self.max_request_bytes, _MAX_REQUEST_BYTES),
            (self.max_response_bytes, _MAX_RESPONSE_BYTES),
            (self.max_connections, _MAX_CONNECTIONS),
            (self.max_headers, _MAX_HEADERS),
            (self.max_header_bytes, _MAX_HEADER_BYTES),
        )
        if any(
            _is_runtime_instance(value, bool)
            or not _is_runtime_instance(value, int)
            or not 1 <= value <= maximum
            for value, maximum in positive_integers
        ):
            raise ValueError("outbound HTTP limit must be within its hard maximum")
        if (
            _is_runtime_instance(self.max_redirects, bool)
            or not _is_runtime_instance(self.max_redirects, int)
            or not 0 <= self.max_redirects <= _MAX_REDIRECTS
            or _is_runtime_instance(self.request_timeout, bool)
            or not (
                _is_runtime_instance(self.request_timeout, int)
                or _is_runtime_instance(self.request_timeout, float)
            )
            or not 0 < self.request_timeout <= _MAX_TIMEOUT
        ):
            raise ValueError("outbound HTTP limit must be within its hard maximum")


_DEFAULT_OUTBOUND_LIMITS = OutboundHTTPLimits()


@runtime_checkable
class HostResolver(Protocol):
    async def resolve(self, host: str, port: int) -> tuple[str, ...]: ...


class SystemHostResolver:
    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        records = await asyncio.get_running_loop().getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        addresses: list[str] = []
        for record in records:
            value = str(record[4][0])
            if value not in addresses:
                addresses.append(value)
        return tuple(addresses)


@dataclass(frozen=True, slots=True, kw_only=True)
class OutboundHTTPAuditEvent:
    request_id: str
    method: str
    destination_fingerprint: str
    outcome: str
    status_code: int | None

    def __post_init__(self) -> None:
        ErrorResponse.from_code(ErrorCode.UNAVAILABLE, request_id=self.request_id)
        if self.method not in _ALLOWED_METHODS | {"INVALID"}:
            raise ValueError("method must be a bounded HTTP method")
        if re.fullmatch(r"[0-9a-f]{64}", self.destination_fingerprint) is None:
            raise ValueError("destination_fingerprint must be a SHA-256 digest")
        if re.fullmatch(r"[a-z_]{1,32}", self.outcome) is None:
            raise ValueError("outcome must be a stable bounded value")
        if self.status_code is not None and (
            _is_runtime_instance(self.status_code, bool)
            or not _is_runtime_instance(self.status_code, int)
            or not 100 <= self.status_code <= 599
        ):
            raise ValueError("status_code must be an HTTP status")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "request_id": self.request_id,
            "method": self.method,
            "destination_fingerprint": self.destination_fingerprint,
            "outcome": self.outcome,
            "status_code": self.status_code,
        }


@runtime_checkable
class OutboundHTTPAuditSink(Protocol):
    def append(self, event: OutboundHTTPAuditEvent) -> None: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class OutboundHTTPResponse:
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def __post_init__(self) -> None:
        if (
            _is_runtime_instance(self.status_code, bool)
            or not _is_runtime_instance(self.status_code, int)
            or not 100 <= self.status_code <= 599
            or not _is_runtime_instance(self.body, bytes)
        ):
            raise ValueError("response must contain a valid status and byte body")

    def __repr__(self) -> str:
        return (
            "OutboundHTTPResponse("
            f"status_code={self.status_code}, header_count={len(self.headers)}, "
            f"body_bytes={len(self.body)})"
        )


class OutboundHTTPError(RuntimeFailure):
    """One payload-free structured failure for every outbound client error."""

    def __init__(self, code: ErrorCode, *, request_id: str) -> None:
        self.error = ErrorResponse.from_code(code, request_id=request_id)
        super().__init__(code)

    def to_dict(self) -> dict[str, JsonValue]:
        return self.error.to_dict()

    def __repr__(self) -> str:
        return (
            "OutboundHTTPError("
            f"code={self.error.code.value!r}, request_id={self.error.request_id!r})"
        )


class _PolicyNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(
        self,
        *,
        policy: EgressPolicy,
        resolver: HostResolver,
        backend: httpcore.AsyncNetworkBackend,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._backend = backend

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        destination = EgressDestination(host=host, port=port)
        self._policy.authorize_destination(destination)
        addresses = await self._resolver.resolve(destination.host, destination.port)
        self._policy.authorize_connection(destination, addresses)
        selected = ipaddress.ip_address(addresses[0]).compressed
        stream = await self._backend.connect_tcp(
            selected,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        try:
            server_address = stream.get_extra_info("server_addr")
            if not isinstance(server_address, tuple):
                raise EgressPolicyViolation()
            address_parts = cast(tuple[object, ...], server_address)
            if len(address_parts) < 2 or not isinstance(address_parts[0], str):
                raise EgressPolicyViolation()
            actual = ipaddress.ip_address(address_parts[0]).compressed
            self._policy.authorize_connection(destination, (actual,))
            if actual != selected:
                raise EgressPolicyViolation()
        except Exception:
            await stream.aclose()
            raise
        return stream

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        raise EgressPolicyViolation()

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: AsyncIterable[bytes]) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for part in self._stream:
            yield part

    async def aclose(self) -> None:
        close = getattr(self._stream, "aclose", None)
        if close is not None:
            await close()


class _CoreTransport(httpx.AsyncBaseTransport):
    def __init__(self, pool: httpcore.AsyncConnectionPool) -> None:
        self._pool = pool

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not isinstance(request.stream, httpx.AsyncByteStream):
            raise RuntimeError("async request stream required")
        response = await self._pool.handle_async_request(
            httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=request.headers.raw,
                content=request.stream,
                extensions=request.extensions,
            )
        )
        if not isinstance(response.stream, AsyncIterable):
            raise RuntimeError("async response stream required")
        response_any: Any = response
        response_extensions: dict[str, Any] = response_any.extensions
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_ResponseStream(response.stream),
            extensions=response_extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


def _destination_fingerprint(destination: EgressDestination | None) -> str:
    authority = destination.authority if destination is not None else "invalid"
    return hashlib.sha256(authority.encode("ascii")).hexdigest()


def _safe_request_id(redactor: RedactionPolicy, request_id: str) -> str:
    if not _is_runtime_instance(request_id, str):
        return "redaction-failed-invalid"
    try:
        candidate = redactor.redact_text(request_id)
        ErrorResponse.from_code(ErrorCode.UNAVAILABLE, request_id=candidate)
        return candidate
    except Exception:
        digest = hashlib.sha256(str.encode(request_id, "utf-8", errors="replace")).hexdigest()[:16]
        return f"redaction-failed-{digest}"


def _require_public_text(value: str, *, redactor: RedactionPolicy) -> None:
    try:
        redacted = redactor.redact_text(value)
    except RedactionError:
        raise
    except Exception:
        raise RedactionError() from None
    if not _is_runtime_instance(redacted, str):
        raise RedactionError()
    if redacted != value:
        raise ValueError("text contains protected material")


def _contains_protected_text(value: str, protected_secrets: tuple[str, ...]) -> bool:
    if not protected_secrets:
        return False
    candidate = value
    for _ in range(4):
        if any(secret in candidate for secret in protected_secrets):
            return True
        decoded = unquote(candidate)
        if decoded == candidate:
            return False
        candidate = decoded
    return any(secret in candidate for secret in protected_secrets)


def _parse_url(
    value: str,
    *,
    redactor: RedactionPolicy,
) -> tuple[httpx.URL, EgressDestination]:
    if (
        not _is_runtime_instance(value, str)
        or not value
        or len(value) > 4096
        or _INVALID_PERCENT.search(value)
    ):
        raise ValueError("invalid URL")
    _require_public_text(value, redactor=redactor)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "%" in parsed.netloc
        or parsed.hostname is None
    ):
        raise ValueError("invalid URL")
    try:
        port = parsed.port if parsed.port is not None else 443
    except ValueError:
        raise ValueError("invalid URL") from None
    if any(is_secret_key(name) for name, _ in parse_qsl(parsed.query, keep_blank_values=True)):
        raise ValueError("invalid URL")
    destination = EgressDestination(host=parsed.hostname, port=port)
    return httpx.URL(value), destination


def _method(value: str) -> str:
    if not _is_runtime_instance(value, str):
        raise ValueError("invalid method")
    method = value.upper()
    if _METHOD.fullmatch(method) is None or method not in _ALLOWED_METHODS:
        raise ValueError("invalid method")
    return method


class OutboundHTTPClient:
    """A finite HTTPS client whose policy cannot be extended by request URLs."""

    def __init__(
        self,
        *,
        policy: EgressPolicy,
        redactor: RedactionPolicy,
        limits: OutboundHTTPLimits = _DEFAULT_OUTBOUND_LIMITS,
        resolver: HostResolver | None = None,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
        audit_sink: OutboundHTTPAuditSink | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        resolver = resolver or SystemHostResolver()
        network_backend = network_backend or cast(
            httpcore.AsyncNetworkBackend,
            httpcore.AnyIOBackend(),
        )
        if (
            not _is_runtime_instance(policy, EgressPolicy)
            or not _is_runtime_instance(redactor, RedactionPolicy)
            or not _is_runtime_instance(limits, OutboundHTTPLimits)
            or not _is_runtime_instance(resolver, HostResolver)
            or not _is_runtime_instance(network_backend, httpcore.AsyncNetworkBackend)
            or (
                audit_sink is not None
                and not _is_runtime_instance(audit_sink, OutboundHTTPAuditSink)
            )
            or (
                ssl_context is not None
                and (
                    not _is_runtime_instance(ssl_context, ssl.SSLContext)
                    or not ssl_context.check_hostname
                    or ssl_context.verify_mode != ssl.CERT_REQUIRED
                    or ssl_context.minimum_version < ssl.TLSVersion.TLSv1_2
                )
            )
        ):
            raise ValueError("outbound HTTP dependencies must satisfy their contracts")
        guarded_backend = _PolicyNetworkBackend(
            policy=policy,
            resolver=resolver,
            backend=network_backend,
        )
        pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_connections,
            http2=False,
            retries=0,
            network_backend=guarded_backend,
        )
        self._policy = policy
        self._redactor = redactor
        self._limits = limits
        self._audit_sink = audit_sink
        self._audit_failures = 0
        self._closed = False
        self._transport = _CoreTransport(pool)

    @property
    def audit_failures(self) -> int:
        return self._audit_failures

    async def request(
        self,
        method: str,
        url: str,
        *,
        request_id: str,
        headers: Mapping[str, str | SecretValue] | None = None,
        content: bytes = b"",
    ) -> OutboundHTTPResponse:
        safe_request_id = _safe_request_id(self._redactor, request_id)
        audit_method = "INVALID"
        audit_destination: EgressDestination | None = None
        try:
            audit_method = _method(method)
            current_url, audit_destination = _parse_url(url, redactor=self._redactor)
            self._policy.authorize_destination(audit_destination)
            request_headers, protected_secrets = self._request_headers(headers or {})
            if _contains_protected_text(url, protected_secrets):
                raise ValueError("URL contains protected material")
            if (
                not _is_runtime_instance(content, bytes)
                or len(content) > self._limits.max_request_bytes
            ):
                raise ValueError("invalid content")
            if self._closed:
                raise OutboundHTTPError(ErrorCode.UNAVAILABLE, request_id=safe_request_id)
        except OutboundHTTPError as caught_error:
            public_error = OutboundHTTPError(
                caught_error.error.code,
                request_id=safe_request_id,
            )
            self._emit_audit(
                request_id=safe_request_id,
                method=audit_method,
                destination=audit_destination,
                outcome=public_error.error.code.value,
                status_code=None,
            )
            raise public_error from None
        except EgressPolicyViolation:
            denied_error = OutboundHTTPError(ErrorCode.FORBIDDEN, request_id=safe_request_id)
            self._emit_audit(
                request_id=safe_request_id,
                method=audit_method,
                destination=audit_destination,
                outcome=denied_error.error.code.value,
                status_code=None,
            )
            raise denied_error from None
        except RedactionError:
            redaction_error = OutboundHTTPError(
                ErrorCode.INTERNAL_FAILURE,
                request_id=safe_request_id,
            )
            self._emit_audit(
                request_id=safe_request_id,
                method=audit_method,
                destination=audit_destination,
                outcome=redaction_error.error.code.value,
                status_code=None,
            )
            raise redaction_error from None
        except Exception:
            invalid_error = OutboundHTTPError(
                ErrorCode.INVALID_INPUT,
                request_id=safe_request_id,
            )
            self._emit_audit(
                request_id=safe_request_id,
                method=audit_method,
                destination=audit_destination,
                outcome=invalid_error.error.code.value,
                status_code=None,
            )
            raise invalid_error from None

        try:
            async with asyncio.timeout(self._limits.request_timeout):
                response = await self._follow_redirects(
                    method=audit_method,
                    url=current_url,
                    destination=audit_destination,
                    headers=request_headers,
                    content=content,
                    protected_secrets=protected_secrets,
                )
        except OutboundHTTPError as caught_error:
            public_error = OutboundHTTPError(
                caught_error.error.code,
                request_id=safe_request_id,
            )
            self._emit_audit(
                request_id=safe_request_id,
                method=audit_method,
                destination=audit_destination,
                outcome=public_error.error.code.value,
                status_code=None,
            )
            raise public_error from None
        except EgressPolicyViolation:
            denied_error = OutboundHTTPError(ErrorCode.FORBIDDEN, request_id=safe_request_id)
            self._emit_audit(
                request_id=safe_request_id,
                method=audit_method,
                destination=audit_destination,
                outcome=denied_error.error.code.value,
                status_code=None,
            )
            raise denied_error from None
        except (TimeoutError, httpcore.TimeoutException, httpx.TimeoutException):
            timeout_error = OutboundHTTPError(ErrorCode.TIMEOUT, request_id=safe_request_id)
            self._emit_audit(
                request_id=safe_request_id,
                method=audit_method,
                destination=audit_destination,
                outcome=timeout_error.error.code.value,
                status_code=None,
            )
            raise timeout_error from None
        except RedactionError:
            redaction_error = OutboundHTTPError(
                ErrorCode.INTERNAL_FAILURE,
                request_id=safe_request_id,
            )
            self._emit_audit(
                request_id=safe_request_id,
                method=audit_method,
                destination=audit_destination,
                outcome=redaction_error.error.code.value,
                status_code=None,
            )
            raise redaction_error from None
        except Exception:
            unavailable_error = OutboundHTTPError(
                ErrorCode.UNAVAILABLE,
                request_id=safe_request_id,
            )
            self._emit_audit(
                request_id=safe_request_id,
                method=audit_method,
                destination=audit_destination,
                outcome=unavailable_error.error.code.value,
                status_code=None,
            )
            raise unavailable_error from None

        self._emit_audit(
            request_id=safe_request_id,
            method=audit_method,
            destination=audit_destination,
            outcome="success",
            status_code=response.status_code,
        )
        return response

    def _request_headers(
        self,
        headers: Mapping[str, str | SecretValue],
    ) -> tuple[dict[str, str], tuple[str, ...]]:
        if len(headers) > self._limits.max_headers:
            raise ValueError("too many headers")
        output: dict[str, str] = {}
        protected_secrets: list[str] = []
        size = 0
        for name, value in headers.items():
            if not _is_runtime_instance(name, str) or _HEADER_NAME.fullmatch(name) is None:
                raise ValueError("invalid header")
            normalized = name.casefold()
            if normalized in _FORBIDDEN_REQUEST_HEADERS:
                raise ValueError("invalid header")
            _require_public_text(name, redactor=self._redactor)
            sensitive = normalized in _SENSITIVE_HEADERS or is_secret_key(name)
            if sensitive and not _is_runtime_instance(value, SecretValue):
                raise ValueError("sensitive headers require SecretValue")
            if _is_runtime_instance(value, SecretValue):
                rendered = cast(SecretValue, value).reveal()
                if rendered not in protected_secrets:
                    protected_secrets.append(rendered)
            elif _is_runtime_instance(value, str):
                rendered = cast(str, value)
                _require_public_text(rendered, redactor=self._redactor)
            else:
                raise ValueError("invalid header")
            if (
                not rendered
                or len(rendered) > 8192
                or any(not 32 <= ord(character) <= 126 for character in rendered)
            ):
                raise ValueError("invalid header")
            size += len(name.encode("ascii")) + len(rendered.encode("utf-8"))
            if size > self._limits.max_header_bytes:
                raise ValueError("headers too large")
            output[name] = rendered
        return output, tuple(sorted(protected_secrets, key=len, reverse=True))

    async def _follow_redirects(
        self,
        *,
        method: str,
        url: httpx.URL,
        destination: EgressDestination,
        headers: dict[str, str],
        content: bytes,
        protected_secrets: tuple[str, ...],
    ) -> OutboundHTTPResponse:
        redirects = 0
        while True:
            self._policy.authorize_destination(destination)
            response = await self._send(
                method=method,
                url=url,
                headers=headers,
                content=content,
            )
            try:
                bounded_headers = self._response_headers(
                    response.headers,
                    protected_secrets=protected_secrets,
                )
                location = response.headers.get("location")
                if response.status_code not in _REDIRECT_STATUSES or location is None:
                    body = await self._read_body(
                        response,
                        protected_secrets=protected_secrets,
                    )
                    return OutboundHTTPResponse(
                        status_code=response.status_code,
                        headers=bounded_headers,
                        body=body,
                    )
                if redirects >= self._limits.max_redirects:
                    raise OutboundHTTPError(ErrorCode.UNAVAILABLE, request_id="redirect-limit")
                redirects += 1
                next_url_value = str(url.join(location))
                if _contains_protected_text(next_url_value, protected_secrets):
                    raise EgressPolicyViolation()
                try:
                    next_url, next_destination = _parse_url(
                        next_url_value,
                        redactor=self._redactor,
                    )
                except RedactionError:
                    raise
                except ValueError:
                    raise OutboundHTTPError(
                        ErrorCode.INVALID_INPUT,
                        request_id="redirect",
                    ) from None
                self._policy.authorize_destination(next_destination)
                if next_destination != destination:
                    headers = {
                        name: value
                        for name, value in headers.items()
                        if name.casefold() not in _SENSITIVE_HEADERS and not is_secret_key(name)
                    }
                if response.status_code == 303 or (
                    response.status_code in {301, 302} and method == "POST"
                ):
                    method = "GET"
                    content = b""
                url = next_url
                destination = next_destination
            finally:
                await response.aclose()

    async def _send(
        self,
        *,
        method: str,
        url: httpx.URL,
        headers: dict[str, str],
        content: bytes,
    ) -> httpx.Response:
        request_headers = {
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "User-Agent": "tesserix-mcp-runtime",
            **headers,
        }
        timeout = self._limits.request_timeout
        request = httpx.Request(
            method,
            url,
            headers=request_headers,
            content=content,
            extensions={
                "timeout": {
                    "connect": timeout,
                    "read": timeout,
                    "write": timeout,
                    "pool": timeout,
                }
            },
        )
        response = await self._transport.handle_async_request(request)
        response.request = request
        return response

    def _response_headers(
        self,
        headers: httpx.Headers,
        *,
        protected_secrets: tuple[str, ...],
    ) -> tuple[tuple[str, str], ...]:
        raw = headers.multi_items()
        if len(raw) > self._limits.max_headers:
            raise OutboundHTTPError(ErrorCode.RESULT_TOO_LARGE, request_id="response-headers")
        output: list[tuple[str, str]] = []
        size = 0
        redacted_size = 0
        for name, value in raw:
            size += len(name.encode("ascii")) + len(value.encode("utf-8"))
            if size > self._limits.max_header_bytes:
                raise OutboundHTTPError(ErrorCode.RESULT_TOO_LARGE, request_id="response-headers")
            if name.casefold() in _SENSITIVE_HEADERS or is_secret_key(name):
                redacted = REDACTED_TEXT
            else:
                for secret in protected_secrets:
                    value = value.replace(secret, REDACTED_TEXT)
                try:
                    redacted = self._redactor.redact_text(value)
                except Exception:
                    raise RedactionError() from None
            redacted_size += len(name.encode("ascii")) + len(redacted.encode("utf-8"))
            if redacted_size > self._limits.max_header_bytes:
                raise OutboundHTTPError(
                    ErrorCode.RESULT_TOO_LARGE,
                    request_id="response-headers",
                )
            output.append((name.casefold(), redacted))
        return tuple(output)

    async def _read_body(
        self,
        response: httpx.Response,
        *,
        protected_secrets: tuple[str, ...],
    ) -> bytes:
        content_encoding = response.headers.get("content-encoding")
        if content_encoding is not None and content_encoding.casefold() != "identity":
            raise OutboundHTTPError(ErrorCode.RESULT_TOO_LARGE, request_id="response-body")
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self._limits.max_response_bytes:
                    raise OutboundHTTPError(
                        ErrorCode.RESULT_TOO_LARGE,
                        request_id="response-body",
                    )
            except ValueError:
                pass
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > self._limits.max_response_bytes:
                raise OutboundHTTPError(ErrorCode.RESULT_TOO_LARGE, request_id="response-body")
            chunks.append(chunk)
        body = b"".join(chunks)
        for secret in protected_secrets:
            body = body.replace(secret.encode("utf-8"), REDACTED_TEXT.encode("ascii"))
        if len(body) > self._limits.max_response_bytes:
            raise OutboundHTTPError(ErrorCode.RESULT_TOO_LARGE, request_id="response-body")
        return body

    def _emit_audit(
        self,
        *,
        request_id: str,
        method: str,
        destination: EgressDestination | None,
        outcome: str,
        status_code: int | None,
    ) -> None:
        if self._audit_sink is None:
            return
        try:
            event = OutboundHTTPAuditEvent(
                request_id=self._redactor.redact_text(request_id),
                method=method if method in _ALLOWED_METHODS else "INVALID",
                destination_fingerprint=_destination_fingerprint(destination),
                outcome=outcome,
                status_code=status_code,
            )
            self._audit_sink.append(event)
        except Exception:
            self._audit_failures += 1

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._transport.aclose()

    async def __aenter__(self) -> OutboundHTTPClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        del exc_info
        await self.aclose()


__all__ = [
    "HostResolver",
    "OutboundHTTPAuditEvent",
    "OutboundHTTPAuditSink",
    "OutboundHTTPClient",
    "OutboundHTTPError",
    "OutboundHTTPLimits",
    "OutboundHTTPResponse",
    "SystemHostResolver",
]
