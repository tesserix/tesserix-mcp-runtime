from __future__ import annotations

import math
import threading
from collections.abc import Mapping
from dataclasses import dataclass

from tesserix_mcp_runtime import (
    AuthenticatedIdentity,
    CallContext,
    Cancellation,
    InvocationResult,
    JsonValue,
    SecretValue,
)
from tesserix_mcp_runtime.adapters.streamable_http import HTTPRequestMetadata
from tesserix_mcp_testkit.faults import FaultScript


def _bounded_text(name: str, value: object, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name} must be bounded visible text")
    return value


def _is_finite_number(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int | float) and math.isfinite(value)


def _is_bounded_integer(value: object, *, minimum: int, maximum: int) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and minimum <= value <= maximum


@dataclass(frozen=True, slots=True)
class CredentialRequest:
    audience: str
    scopes: tuple[str, ...]
    tenant: str


@dataclass(frozen=True, slots=True)
class BackingAPIRequest:
    method: str
    path: str
    body: JsonValue


@dataclass(frozen=True, slots=True)
class RegistryQuery:
    text: str
    limit: int


@dataclass(frozen=True, slots=True)
class RegistryRecord:
    server_id: str
    capability: str
    score: float

    def __post_init__(self) -> None:
        _bounded_text("server_id", self.server_id, 128)
        _bounded_text("capability", self.capability, 128)
        if not _is_finite_number(self.score) or not 0 <= self.score <= 1:
            raise ValueError("score must be between zero and one")


@dataclass(frozen=True, slots=True)
class MCPCall:
    name: str
    arguments: Mapping[str, JsonValue]


class FakeClock:
    def __init__(self, *, now: float = 0.0) -> None:
        if not _is_finite_number(now) or now < 0:
            raise ValueError("now must be a finite non-negative timestamp")
        self._now = float(now)
        self._sleeps: list[float] = []
        self._lock = threading.Lock()

    def now(self) -> float:
        with self._lock:
            return self._now

    async def sleep(self, seconds: float) -> None:
        if not _is_finite_number(seconds) or seconds < 0:
            raise ValueError("sleep seconds must be finite and non-negative")
        with self._lock:
            value = float(seconds)
            self._sleeps.append(value)
            self._now += value

    @property
    def sleeps(self) -> tuple[float, ...]:
        with self._lock:
            return tuple(self._sleeps)


class FakeIdentityFactory:
    def __init__(
        self,
        *,
        issuer: str = "https://identity.example.invalid",
        subject: str = "test-subject",
        default_scopes: tuple[str, ...] = (),
    ) -> None:
        self._issuer = _bounded_text("issuer", issuer, 2_048)
        self._subject = _bounded_text("subject", subject)
        self._default_scopes = default_scopes
        AuthenticatedIdentity(
            tenant="validation-tenant",
            subject=self._subject,
            issuer=self._issuer,
            scopes=default_scopes,
        )
        self._requests = 0
        self._lock = threading.Lock()

    def context(
        self,
        *,
        tenant: str = "test-tenant",
        scopes: tuple[str, ...] | None = None,
    ) -> CallContext:
        with self._lock:
            self._requests += 1
            request_id = f"test-request-{self._requests}"
        return CallContext(
            identity=AuthenticatedIdentity(
                tenant=tenant,
                subject=self._subject,
                issuer=self._issuer,
                scopes=self._default_scopes if scopes is None else scopes,
            ),
            request_id=request_id,
            run_id="test-run",
        )


class FakeCredentialIssuer:
    def __init__(self, script: FaultScript[SecretValue] | None = None) -> None:
        self._script = script
        self._requests: list[CredentialRequest] = []

    async def issue(
        self,
        *,
        audience: str,
        scopes: tuple[str, ...],
        context: CallContext,
    ) -> SecretValue:
        request = CredentialRequest(
            audience=_bounded_text("audience", audience, 2_048),
            scopes=scopes,
            tenant=context.tenant,
        )
        self._requests.append(request)
        if self._script is not None:
            return self._script.resolve()
        return SecretValue(f"test-credential-{len(self._requests)}")

    @property
    def requests(self) -> tuple[CredentialRequest, ...]:
        return tuple(self._requests)


class FakeBackingAPI:
    def __init__(self, script: FaultScript[JsonValue]) -> None:
        self._script = script
        self._requests: list[BackingAPIRequest] = []

    async def request(self, method: str, path: str, body: JsonValue) -> JsonValue:
        self._requests.append(
            BackingAPIRequest(
                method=_bounded_text("method", method, 16),
                path=_bounded_text("path", path, 2_048),
                body=body,
            )
        )
        return self._script.resolve()

    @property
    def requests(self) -> tuple[BackingAPIRequest, ...]:
        return tuple(self._requests)


class FakeGateway:
    def __init__(self, script: FaultScript[CallContext]) -> None:
        self._script = script
        self._requests: list[HTTPRequestMetadata] = []
        self._cancellations: list[Cancellation] = []

    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        self._requests.append(request)
        self._cancellations.append(cancellation)
        return self._script.resolve()

    @property
    def requests(self) -> tuple[HTTPRequestMetadata, ...]:
        return tuple(self._requests)

    @property
    def cancellations(self) -> tuple[Cancellation, ...]:
        return tuple(self._cancellations)


class FakeRegistry:
    def __init__(self, script: FaultScript[tuple[RegistryRecord, ...]]) -> None:
        self._script = script
        self._queries: list[RegistryQuery] = []

    async def search(self, text: str, *, limit: int) -> tuple[RegistryRecord, ...]:
        if not _is_bounded_integer(limit, minimum=1, maximum=100):
            raise ValueError("limit must be between 1 and 100")
        self._queries.append(RegistryQuery(_bounded_text("query", text, 4_096), limit))
        return self._script.resolve()

    @property
    def queries(self) -> tuple[RegistryQuery, ...]:
        return tuple(self._queries)


class FakeMCPClient:
    def __init__(
        self,
        *,
        list_script: FaultScript[tuple[str, ...]],
        call_script: FaultScript[InvocationResult],
    ) -> None:
        self._list_script = list_script
        self._call_script = call_script
        self._calls: list[MCPCall] = []

    async def list_tools(self) -> tuple[str, ...]:
        return self._list_script.resolve()

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
    ) -> InvocationResult:
        self._calls.append(MCPCall(_bounded_text("tool name", name, 128), arguments))
        return self._call_script.resolve()

    @property
    def calls(self) -> tuple[MCPCall, ...]:
        return tuple(self._calls)


__all__ = [
    "BackingAPIRequest",
    "CredentialRequest",
    "FakeBackingAPI",
    "FakeClock",
    "FakeCredentialIssuer",
    "FakeGateway",
    "FakeIdentityFactory",
    "FakeMCPClient",
    "FakeRegistry",
    "MCPCall",
    "RegistryQuery",
    "RegistryRecord",
]
