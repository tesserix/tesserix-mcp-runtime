from __future__ import annotations

import asyncio
import gzip
import logging
import ssl
import traceback
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpcore
import pytest

from tesserix_mcp_runtime import ErrorCode, JsonValue
from tesserix_mcp_runtime.adapters.outbound_http import (
    HostResolver,
    OutboundHTTPAuditEvent,
    OutboundHTTPAuditSink,
    OutboundHTTPClient,
    OutboundHTTPError,
    OutboundHTTPLimits,
    OutboundHTTPResponse,
    SystemHostResolver,
)
from tesserix_mcp_runtime.egress import (
    DeclaredEgressPolicy,
    EgressDestination,
    EgressManifest,
)
from tesserix_mcp_runtime.redaction import (
    RedactionLimits,
    RedactionPolicy,
    SecretRedactor,
    SecretValue,
)

CANARY = "synthetic-outbound-canary-4Rm8"
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1::34"


class UnrenderableRequestID:
    def __str__(self) -> str:
        raise AssertionError("request identifiers must not be rendered before validation")


@dataclass(frozen=True, slots=True)
class ConnectionScript:
    response: bytes
    actual_address: str | None = None


class ScriptedStream(httpcore.AsyncNetworkStream):
    def __init__(self, script: ConnectionScript, host: str, port: int) -> None:
        self._buffer = script.response
        self._actual_address = script.actual_address or host
        self._port = port
        self.writes: list[bytes] = []
        self.closed = False
        self.server_hostname: str | None = None

    async def read(
        self,
        max_bytes: int,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> bytes:
        del timeout
        if not self._buffer:
            return b""
        chunk = self._buffer[:max_bytes]
        self._buffer = self._buffer[max_bytes:]
        return chunk

    async def write(
        self,
        buffer: bytes,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> None:
        del timeout
        self.writes.append(buffer)

    async def aclose(self) -> None:
        self.closed = True

    async def start_tls(
        self,
        ssl_context: Any,
        server_hostname: str | None = None,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> httpcore.AsyncNetworkStream:
        del ssl_context, timeout
        self.server_hostname = server_hostname
        return self

    def get_extra_info(self, info: str) -> object:
        if info == "server_addr":
            return (self._actual_address, self._port)
        return None


class ScriptedNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, scripts: list[ConnectionScript]) -> None:
        self._scripts = scripts
        self.connects: list[tuple[str, int]] = []
        self.streams: list[ScriptedStream] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout, local_address, socket_options
        self.connects.append((host, port))
        if not self._scripts:
            raise OSError("synthetic backend exhausted")
        stream = ScriptedStream(self._scripts.pop(0), host, port)
        self.streams.append(stream)
        return stream

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        raise AssertionError("unix sockets must not be reachable")

    async def sleep(self, seconds: float) -> None:
        del seconds


class StaticResolver:
    def __init__(self, answers: Mapping[str, tuple[str, ...]]) -> None:
        self._answers = dict(answers)
        self.calls: list[tuple[str, int]] = []

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        self.calls.append((host, port))
        return self._answers[host]


class FailingResolver:
    def __init__(self, error: Exception) -> None:
        self._error = error

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        del host, port
        raise self._error


class RecordingAuditSink:
    def __init__(self) -> None:
        self.events: list[OutboundHTTPAuditEvent] = []

    def append(self, event: OutboundHTTPAuditEvent) -> None:
        self.events.append(event)


class FailingAuditSink:
    def append(self, event: OutboundHTTPAuditEvent) -> None:
        del event
        raise RuntimeError(CANARY)


class FailingTextRedactor:
    limits = RedactionLimits()

    def redact_text(self, value: str) -> str:
        if value == "value":
            raise RuntimeError(CANARY)
        return value

    def redact(self, value: JsonValue) -> JsonValue:
        return value


class ExpandingTextRedactor:
    limits = RedactionLimits()

    def redact_text(self, value: str) -> str:
        return "x" * 65_537 if value == "value" else value

    def redact(self, value: JsonValue) -> JsonValue:
        return value


def raw_response(
    status: int,
    *,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
) -> bytes:
    fields = [
        f"HTTP/1.1 {status} Synthetic\r\n".encode(),
        f"Content-Length: {len(body)}\r\n".encode(),
        *(f"{name}: {value}\r\n".encode() for name, value in headers),
        b"\r\n",
        body,
    ]
    return b"".join(fields)


def destination(host: str = "api.example.test", port: int = 443) -> EgressDestination:
    return EgressDestination(host=host, port=port)


def client(
    backend: ScriptedNetworkBackend,
    resolver: HostResolver,
    *,
    destinations: tuple[EgressDestination, ...] | None = None,
    limits: OutboundHTTPLimits | None = None,
    audit_sink: OutboundHTTPAuditSink | None = None,
    redactor: RedactionPolicy | None = None,
) -> OutboundHTTPClient:
    return OutboundHTTPClient(
        policy=DeclaredEgressPolicy(
            manifest=EgressManifest(destinations=destinations or (destination(),))
        ),
        resolver=resolver,
        network_backend=backend,
        limits=limits or OutboundHTTPLimits(),
        redactor=redactor or SecretRedactor(known_secrets=(SecretValue(CANARY),)),
        audit_sink=audit_sink,
    )


def test_client_connects_to_the_validated_ip_with_original_tls_name() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([ConnectionScript(raw_response(200, body=b'{"ok":true}'))])
        resolver = StaticResolver({"api.example.test": (PUBLIC_V4, PUBLIC_V6)})
        outbound = client(backend, resolver)

        response = await outbound.request(
            "GET",
            "https://api.example.test/v1/items?limit=2",
            request_id="request-1",
        )

        assert response.status_code == 200
        assert response.body == b'{"ok":true}'
        assert backend.connects == [(PUBLIC_V4, 443)]
        assert resolver.calls == [("api.example.test", 443)]
        assert backend.streams[0].server_hostname == "api.example.test"
        written = b"".join(backend.streams[0].writes)
        assert b"GET /v1/items?limit=2 HTTP/1.1" in written
        assert b"Host: api.example.test" in written
        await outbound.aclose()

    asyncio.run(exercise())


def test_connected_address_is_checked_before_request_bytes_are_written() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend(
            [ConnectionScript(raw_response(200), actual_address="127.0.0.1")]
        )
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
        )

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/",
                request_id="request-2",
            )

        assert captured.value.error.code is ErrorCode.FORBIDDEN
        assert backend.streams[0].writes == []
        assert backend.streams[0].closed
        await outbound.aclose()

    asyncio.run(exercise())


def test_mixed_dns_answer_is_blocked_before_connect() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([])
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4, "169.254.169.254")}),
        )

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/",
                request_id="request-3",
            )

        assert captured.value.error.code is ErrorCode.FORBIDDEN
        assert backend.connects == []
        await outbound.aclose()

    asyncio.run(exercise())


def test_redirect_to_private_resolution_is_blocked_before_second_connect() -> None:
    async def exercise() -> None:
        redirect = destination("redirect.example.test")
        backend = ScriptedNetworkBackend(
            [
                ConnectionScript(
                    raw_response(
                        302,
                        headers=(
                            ("Location", "https://redirect.example.test/metadata"),
                            ("Connection", "close"),
                        ),
                    )
                )
            ]
        )
        resolver = StaticResolver(
            {
                "api.example.test": (PUBLIC_V4,),
                "redirect.example.test": ("169.254.169.254",),
            }
        )
        outbound = client(backend, resolver, destinations=(destination(), redirect))

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/start",
                request_id="request-4",
            )

        assert captured.value.error.code is ErrorCode.FORBIDDEN
        assert backend.connects == [(PUBLIC_V4, 443)]
        await outbound.aclose()

    asyncio.run(exercise())


def test_cross_origin_redirect_does_not_forward_secret_headers() -> None:
    async def exercise() -> None:
        second = destination("files.example.test")
        backend = ScriptedNetworkBackend(
            [
                ConnectionScript(
                    raw_response(
                        302,
                        headers=(
                            ("Location", "https://files.example.test/final"),
                            ("Connection", "close"),
                        ),
                    )
                ),
                ConnectionScript(raw_response(200, body=b"done")),
            ]
        )
        outbound = client(
            backend,
            StaticResolver(
                {
                    "api.example.test": (PUBLIC_V4,),
                    "files.example.test": ("93.184.216.35",),
                }
            ),
            destinations=(destination(), second),
        )

        response = await outbound.request(
            "GET",
            "https://api.example.test/start",
            request_id="request-5",
            headers={"Authorization": SecretValue(CANARY), "X-Public": "visible"},
        )

        assert response.body == b"done"
        first = b"".join(backend.streams[0].writes)
        second_request = b"".join(backend.streams[1].writes)
        assert CANARY.encode() in first
        assert CANARY.encode() not in second_request
        assert b"X-Public: visible" in second_request
        await outbound.aclose()

    asyncio.run(exercise())


def test_redirect_cannot_move_an_outbound_secret_into_the_url() -> None:
    async def exercise() -> None:
        redirect_secret = "synthetic/redirect?canary=4Rm8"
        backend = ScriptedNetworkBackend(
            [
                ConnectionScript(
                    raw_response(
                        302,
                        headers=(
                            (
                                "Location",
                                "https://api.example.test/echo/"
                                "synthetic%2Fredirect%3Fcanary%3D4Rm8",
                            ),
                            ("Connection", "close"),
                        ),
                    )
                )
            ]
        )
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
            redactor=SecretRedactor(),
        )

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/start",
                request_id="request-secret-redirect",
                headers={"Authorization": SecretValue(redirect_secret)},
            )

        assert captured.value.error.code is ErrorCode.FORBIDDEN
        assert backend.connects == [(PUBLIC_V4, 443)]
        await outbound.aclose()

    asyncio.run(exercise())


def test_dependency_cookies_are_never_persisted_or_replayed_between_requests() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend(
            [
                ConnectionScript(
                    raw_response(
                        200,
                        headers=(
                            ("Set-Cookie", "session=tenant-a; Path=/"),
                            ("Connection", "close"),
                        ),
                        body=b"first",
                    )
                ),
                ConnectionScript(raw_response(200, body=b"second")),
            ]
        )
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
        )

        await outbound.request(
            "GET",
            "https://api.example.test/first",
            request_id="request-cookie-a",
        )
        await outbound.request(
            "GET",
            "https://api.example.test/second",
            request_id="request-cookie-b",
        )

        second_request = b"".join(backend.streams[1].writes).lower()
        assert b"cookie:" not in second_request
        assert b"tenant-a" not in second_request
        await outbound.aclose()

    asyncio.run(exercise())


def test_dependency_library_does_not_log_full_urls(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([ConnectionScript(raw_response(200, body=b"ok"))])
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
        )
        with caplog.at_level(logging.INFO, logger="httpx"):
            await outbound.request(
                "GET",
                "https://api.example.test/items?sensitive-payload=value",
                request_id="request-log",
            )

        assert "api.example.test" not in caplog.text
        assert "sensitive-payload" not in caplog.text
        await outbound.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.test/",
        "https://user:pass@api.example.test/",
        "https://api%2eexample.test/",
        "https://2130706433/",
        "https://api.example.test:0/",
        "https://api.example.test/#fragment",
        "https://api.example.test/?access_token=value",
        "https://api.example.test/?api_key=value",
        f"https://api.example.test/?value={CANARY}",
    ],
)
def test_unsafe_url_forms_are_rejected_without_dns_or_connect(url: str) -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([])
        resolver = StaticResolver({"api.example.test": (PUBLIC_V4,)})
        outbound = client(backend, resolver)

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request("GET", url, request_id="request-6")

        assert captured.value.error.code is ErrorCode.INVALID_INPUT
        assert resolver.calls == []
        assert backend.connects == []
        await outbound.aclose()

    asyncio.run(exercise())


def test_invalid_request_identifier_still_uses_a_safe_structured_error() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([])
        resolver = StaticResolver({"api.example.test": (PUBLIC_V4,)})
        outbound = client(backend, resolver)
        request_id: Any = UnrenderableRequestID()

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "http://api.example.test/",
                request_id=request_id,
            )

        assert captured.value.error.code is ErrorCode.INVALID_INPUT
        assert captured.value.error.request_id == "redaction-failed-invalid"
        assert resolver.calls == []
        assert backend.connects == []
        await outbound.aclose()

    asyncio.run(exercise())


def test_exact_undeclared_port_is_rejected_without_dns() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([])
        resolver = StaticResolver({"api.example.test": (PUBLIC_V4,)})
        outbound = client(backend, resolver)

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test:8443/",
                request_id="request-7",
            )

        assert captured.value.error.code is ErrorCode.FORBIDDEN
        assert resolver.calls == []
        await outbound.aclose()

    asyncio.run(exercise())


def test_sensitive_headers_require_secret_values() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([])
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
        )

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/",
                request_id="request-8",
                headers={"X-API-Key": CANARY},
            )

        assert captured.value.error.code is ErrorCode.INVALID_INPUT
        assert backend.connects == []
        await outbound.aclose()

    asyncio.run(exercise())


def test_known_secret_in_an_ordinary_header_is_rejected_before_connect() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([])
        resolver = StaticResolver({"api.example.test": (PUBLIC_V4,)})
        outbound = client(backend, resolver)

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/",
                request_id="request-secret-header",
                headers={"X-Public": f"prefix-{CANARY}"},
            )

        assert captured.value.error.code is ErrorCode.INVALID_INPUT
        assert resolver.calls == []
        assert backend.connects == []
        await outbound.aclose()

    asyncio.run(exercise())


def test_non_ascii_header_values_are_rejected_as_invalid_input() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([])
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
        )

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/",
                request_id="request-header",
                headers={"X-Visible": "café"},
            )

        assert captured.value.error.code is ErrorCode.INVALID_INPUT
        assert backend.connects == []
        await outbound.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "headers",
    [
        {"Accept-Encoding": "gzip"},
        {"Upgrade": "websocket"},
        {"Proxy-Authorization": SecretValue(CANARY)},
        {"X-HTTP-Method-Override": "CONNECT"},
    ],
)
def test_hop_by_hop_and_transport_control_headers_are_rejected(
    headers: Mapping[str, str | SecretValue],
) -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([])
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
        )

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/",
                request_id="request-header-control",
                headers=headers,
            )

        assert captured.value.error.code is ErrorCode.INVALID_INPUT
        assert backend.connects == []
        await outbound.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize("method", ["CONNECT", "TRACE", "CUSTOM"])
def test_tunneling_and_unreviewed_methods_are_rejected_before_connect(method: str) -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([])
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
        )

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                method,
                "https://api.example.test/",
                request_id="request-method",
            )

        assert captured.value.error.code is ErrorCode.INVALID_INPUT
        assert backend.connects == []
        await outbound.aclose()

    asyncio.run(exercise())


def test_request_and_response_payload_ceilings_fail_closed() -> None:
    async def exercise() -> None:
        request_backend = ScriptedNetworkBackend([])
        request_client = client(
            request_backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
            limits=OutboundHTTPLimits(max_request_bytes=4),
        )
        with pytest.raises(OutboundHTTPError) as request_error:
            await request_client.request(
                "POST",
                "https://api.example.test/",
                request_id="request-9",
                content=b"12345",
            )
        assert request_error.value.error.code is ErrorCode.INVALID_INPUT
        assert request_backend.connects == []
        await request_client.aclose()

        response_backend = ScriptedNetworkBackend(
            [ConnectionScript(raw_response(200, body=b"12345"))]
        )
        response_client = client(
            response_backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
            limits=OutboundHTTPLimits(max_response_bytes=4),
        )
        with pytest.raises(OutboundHTTPError) as response_error:
            await response_client.request(
                "GET",
                "https://api.example.test/",
                request_id="request-10",
            )
        assert response_error.value.error.code is ErrorCode.RESULT_TOO_LARGE
        assert response_error.value.error.request_id == "request-10"
        await response_client.aclose()

    asyncio.run(exercise())


def test_encoded_response_is_rejected_before_decompression() -> None:
    async def exercise() -> None:
        compressed = gzip.compress(b"x" * 1024)
        assert len(compressed) < 64
        backend = ScriptedNetworkBackend(
            [
                ConnectionScript(
                    raw_response(
                        200,
                        headers=(("Content-Encoding", "gzip"),),
                        body=compressed,
                    )
                )
            ]
        )
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
            limits=OutboundHTTPLimits(max_response_bytes=64),
        )

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/compressed",
                request_id="request-compressed",
            )

        assert captured.value.error.code is ErrorCode.RESULT_TOO_LARGE
        assert b"accept-encoding: identity" in b"".join(backend.streams[0].writes).lower()
        await outbound.aclose()

    asyncio.run(exercise())


def test_response_representation_and_sensitive_headers_are_redacted() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend(
            [
                ConnectionScript(
                    raw_response(
                        200,
                        headers=(("Set-Cookie", CANARY),),
                        body=CANARY.encode(),
                    )
                )
            ]
        )
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
        )

        response = await outbound.request(
            "GET",
            "https://api.example.test/",
            request_id="request-11",
            headers={"Authorization": SecretValue(CANARY)},
        )

        assert dict(response.headers)["set-cookie"] == "[REDACTED]"
        assert response.body == b"[REDACTED]"
        assert CANARY not in repr(response)
        await outbound.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("resolver_error", "code"),
    [
        (TimeoutError(CANARY), ErrorCode.TIMEOUT),
        (RuntimeError(f"{CANARY} internal.example SQL httpcore/1.0 body"), ErrorCode.UNAVAILABLE),
    ],
)
def test_dependency_failures_use_one_safe_structured_error(
    resolver_error: Exception,
    code: ErrorCode,
) -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend([])
        outbound = client(backend, FailingResolver(resolver_error))

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/",
                request_id="request-safe",
            )

        error = captured.value
        document = str(error.to_dict())
        rendered_traceback = "".join(traceback.format_exception(error))
        assert error.error.code is code
        assert set(error.to_dict()) == {"code", "message", "request_id", "retryability"}
        assert error.error.request_id == "request-safe"
        assert CANARY not in str(error)
        assert CANARY not in repr(error)
        assert CANARY not in document
        assert CANARY not in rendered_traceback
        assert "internal.example" not in document
        assert "httpcore" not in document
        assert "SQL" not in document
        await outbound.aclose()

    asyncio.run(exercise())


def test_explicit_audit_is_payload_free_redacted_and_failure_is_nonfatal() -> None:
    async def exercise() -> None:
        recording = RecordingAuditSink()
        backend = ScriptedNetworkBackend(
            [ConnectionScript(raw_response(200, body=CANARY.encode()))]
        )
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
            audit_sink=recording,
        )

        await outbound.request(
            "POST",
            "https://api.example.test/items?visible=true",
            request_id=f"request-{CANARY}",
            content=CANARY.encode(),
        )

        assert len(recording.events) == 1
        event: dict[str, JsonValue] = recording.events[0].to_dict()
        assert set(event) == {
            "destination_fingerprint",
            "method",
            "outcome",
            "request_id",
            "status_code",
        }
        assert CANARY not in str(event)
        assert "items" not in str(event)
        assert "visible" not in str(event)
        await outbound.aclose()

        failing_backend = ScriptedNetworkBackend([ConnectionScript(raw_response(200, body=b"ok"))])
        failing = client(
            failing_backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
            audit_sink=FailingAuditSink(),
        )
        response = await failing.request(
            "GET",
            "https://api.example.test/",
            request_id="request-12",
        )
        assert response.status_code == 200
        assert failing.audit_failures == 1
        await failing.aclose()

    asyncio.run(exercise())


def test_audit_contracts_are_independently_replaceable() -> None:
    sink: OutboundHTTPAuditSink = RecordingAuditSink()
    resolver: HostResolver = StaticResolver({"api.example.test": (PUBLIC_V4,)})

    assert isinstance(sink, OutboundHTTPAuditSink)
    assert isinstance(resolver, HostResolver)


def test_client_rejects_an_unverified_custom_tls_context() -> None:
    insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_context.check_hostname = False
    insecure_context.verify_mode = ssl.CERT_NONE

    with pytest.raises(ValueError, match="dependencies"):
        OutboundHTTPClient(
            policy=DeclaredEgressPolicy(manifest=EgressManifest(destinations=(destination(),))),
            redactor=SecretRedactor(),
            resolver=StaticResolver({"api.example.test": (PUBLIC_V4,)}),
            network_backend=ScriptedNetworkBackend([]),
            ssl_context=insecure_context,
        )


def test_system_resolver_deduplicates_answers_without_opening_a_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        loop = asyncio.get_running_loop()

        async def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[Any, ...]]:
            del args, kwargs
            return [
                (2, 1, 6, "", (PUBLIC_V4, 443)),
                (2, 1, 6, "", (PUBLIC_V4, 443)),
                (10, 1, 6, "", (PUBLIC_V6, 443, 0, 0)),
            ]

        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)

        assert await SystemHostResolver().resolve("api.example.test", 443) == (
            PUBLIC_V4,
            PUBLIC_V6,
        )

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"request_id": ""},
        {"method": "BAD METHOD"},
        {"destination_fingerprint": "not-a-digest"},
        {"outcome": "not-valid!"},
        {"status_code": 99},
    ],
)
def test_audit_event_rejects_invalid_bounded_fields(kwargs: dict[str, Any]) -> None:
    fields: dict[str, Any] = {
        "request_id": "request-audit",
        "method": "GET",
        "destination_fingerprint": "a" * 64,
        "outcome": "success",
        "status_code": 200,
    }
    fields.update(kwargs)

    with pytest.raises(ValueError):
        OutboundHTTPAuditEvent(**fields)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status_code": 99, "headers": (), "body": b""},
        {"status_code": 200, "headers": (), "body": "not-bytes"},
    ],
)
def test_response_contract_rejects_invalid_runtime_values(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="response"):
        OutboundHTTPResponse(**kwargs)


def test_redirect_limit_uses_the_original_safe_request_identifier() -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend(
            [
                ConnectionScript(
                    raw_response(
                        302,
                        headers=(("Location", "https://api.example.test/again"),),
                    )
                )
            ]
        )
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
            limits=OutboundHTTPLimits(max_redirects=0),
        )

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/start",
                request_id="request-redirect-limit",
            )

        assert captured.value.error.code is ErrorCode.UNAVAILABLE
        assert captured.value.error.request_id == "request-redirect-limit"
        await outbound.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("redactor", "code"),
    [
        (FailingTextRedactor(), ErrorCode.INTERNAL_FAILURE),
        (ExpandingTextRedactor(), ErrorCode.RESULT_TOO_LARGE),
    ],
)
def test_response_header_redaction_failure_or_expansion_fails_closed(
    redactor: RedactionPolicy,
    code: ErrorCode,
) -> None:
    async def exercise() -> None:
        backend = ScriptedNetworkBackend(
            [ConnectionScript(raw_response(200, headers=(("X-Visible", "value"),), body=b"ok"))]
        )
        outbound = client(
            backend,
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
            redactor=redactor,
        )

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/",
                request_id="request-redactor",
            )

        assert captured.value.error.code is code
        assert CANARY not in repr(captured.value)
        await outbound.aclose()

    asyncio.run(exercise())


def test_request_after_close_uses_stable_unavailable_error() -> None:
    async def exercise() -> None:
        outbound = client(
            ScriptedNetworkBackend([]),
            StaticResolver({"api.example.test": (PUBLIC_V4,)}),
        )
        await outbound.aclose()
        await outbound.aclose()

        with pytest.raises(OutboundHTTPError) as captured:
            await outbound.request(
                "GET",
                "https://api.example.test/",
                request_id="request-closed",
            )

        assert captured.value.error.code is ErrorCode.UNAVAILABLE
        assert captured.value.error.request_id == "request-closed"

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_request_bytes": 0},
        {"max_request_bytes": 1_048_577},
        {"max_response_bytes": 0},
        {"max_response_bytes": 1_048_577},
        {"max_redirects": 11},
        {"request_timeout": 31.0},
        {"max_connections": 257},
        {"max_headers": 129},
        {"max_header_bytes": 65_537},
    ],
)
def test_outbound_limits_have_non_bypassable_hard_maxima(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="outbound HTTP limit"):
        OutboundHTTPLimits(**kwargs)
