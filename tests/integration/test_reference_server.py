from __future__ import annotations

import json

import httpx
import pytest
from integration.journey.backing import JOURNEY_CANARY, BackingService, BackingStore
from integration.journey.identity import IdentityAuthority, TokenRequest
from integration.journey.reference_server import (
    JOURNEY_APPROVAL_ID,
    BackingClient,
    JourneyJWKSFetcher,
    TenantBoundContextProvider,
    build_reference_runtime,
)

from tesserix_mcp_runtime import (
    AuthenticatedIdentity,
    CallContext,
    ErrorCode,
    InvocationStatus,
    JsonValue,
    SystemClock,
    TraceContext,
)
from tesserix_mcp_runtime import Cancellation as CancellationProtocol
from tesserix_mcp_runtime.adapters.gateway_identity import (
    GatewayIdentityConfig,
    GatewayJWTContextProvider,
    JWKSFetchError,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport
from tesserix_mcp_runtime.adapters.streamable_http import (
    HTTPRequestAuthenticationError,
    HTTPRequestMetadata,
)

NOW = 1_800_000_000
ISSUER = "https://identity.journey.invalid"
AUDIENCE = "tesserix-mcp-journey"
TRACE_ID = "1" * 32
TRACEPARENT = f"00-{TRACE_ID}-{'2' * 16}-01"


class FakeCancellation:
    @property
    def cancelled(self) -> bool:
        return False

    async def wait(self) -> None:
        raise AssertionError("cancellation wait is not used")


def context(
    *,
    tenant: str = "tenant-a",
    request_id: str = "request-runtime-001",
    idempotency_key: str | None = None,
    approval_id: str | None = None,
    deadline: float | None = None,
) -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant=tenant,
            subject="subject-a",
            issuer=ISSUER,
            scopes=("journey:approve", "journey:read", "journey:write"),
        ),
        request_id=request_id,
        run_id="journey-run-001",
        trace_context=TraceContext(traceparent=TRACEPARENT),
        idempotency_key=idempotency_key,
        approval_id=approval_id,
        deadline=deadline,
    )


def backing_client(store: BackingStore) -> BackingClient:
    return BackingClient(
        endpoint="http://backing.test",
        transport=httpx.ASGITransport(app=BackingService(store)),
    )


async def test_reference_catalog_has_reviewed_risk_and_scope_metadata() -> None:
    runtime = build_reference_runtime(
        transport=InProcessTransport(),
        backing=backing_client(BackingStore()),
        wall_clock=lambda: NOW,
    )

    manifests = {item.metadata.name: item for item in runtime.catalog.manifests}
    assert set(manifests) == {
        "journey.approve_order",
        "journey.fail",
        "journey.read_order",
        "journey.secret_canary",
        "journey.slow",
        "journey.write_order",
    }
    assert manifests["journey.read_order"].metadata.effect.value == "read"
    assert manifests["journey.write_order"].metadata.effect.value == "write"
    assert manifests["journey.write_order"].metadata.idempotency.value == "required"
    assert manifests["journey.approve_order"].metadata.approval.value == "required"
    await runtime.application.start()
    try:
        assert runtime.application.list_tools() == tuple(sorted(manifests))
    finally:
        await runtime.application.drain()
        await runtime.application.stop()


async def test_reference_runtime_returns_structured_read_and_one_replayed_write() -> None:
    store = BackingStore()
    transport = InProcessTransport()
    runtime = build_reference_runtime(
        transport=transport,
        backing=backing_client(store),
        wall_clock=lambda: NOW,
    )
    await runtime.application.start()
    try:
        read = await transport.invoke(
            "journey.read_order",
            {"order_id": "order-001"},
            context=context(),
        )
        first = await transport.invoke(
            "journey.write_order",
            {"order_id": "order-001", "status": "created"},
            context=context(idempotency_key="write-order-001"),
        )
        replay = await transport.invoke(
            "journey.write_order",
            {"order_id": "order-001", "status": "created"},
            context=context(
                request_id="request-runtime-002",
                idempotency_key="write-order-001",
            ),
        )
    finally:
        await runtime.application.drain()
        await runtime.application.stop()

    assert read.status is InvocationStatus.SUCCESS
    assert read.value == {"order_id": "order-001", "status": "missing"}
    assert first.status is InvocationStatus.SUCCESS
    assert (
        first.value
        == replay.value
        == {
            "effect_id": "effect-000001",
            "order_id": "order-001",
            "status": "created",
        }
    )
    assert store.effect_count == 1
    assert store.observations[-1].replayed is True
    assert {item.context.tenant for item in store.observations} == {"tenant-a"}
    assert {item.context.trace_id for item in store.observations} == {TRACE_ID}


async def test_mutation_requires_idempotency_before_the_backing_boundary() -> None:
    store = BackingStore()
    transport = InProcessTransport()
    runtime = build_reference_runtime(
        transport=transport,
        backing=backing_client(store),
        wall_clock=lambda: NOW,
    )
    await runtime.application.start()
    try:
        result = await transport.invoke(
            "journey.write_order",
            {"order_id": "order-001", "status": "created"},
            context=context(),
        )
    finally:
        await runtime.application.drain()
        await runtime.application.stop()

    assert result.status is InvocationStatus.FAILURE
    assert result.error is not None
    assert result.error.code is ErrorCode.CONFLICT
    assert store.effect_count == 0
    assert store.observations == ()


async def test_approval_required_tool_denies_then_accepts_the_exact_reviewed_action() -> None:
    store = BackingStore()
    transport = InProcessTransport()
    runtime = build_reference_runtime(
        transport=transport,
        backing=backing_client(store),
        wall_clock=lambda: NOW,
    )
    arguments: dict[str, JsonValue] = {"order_id": "order-001"}
    await runtime.application.start()
    try:
        denied = await transport.invoke(
            "journey.approve_order",
            arguments,
            context=context(idempotency_key="approve-order-001"),
        )
        allowed = await transport.invoke(
            "journey.approve_order",
            arguments,
            context=context(
                idempotency_key="approve-order-001",
                approval_id=JOURNEY_APPROVAL_ID,
            ),
        )
    finally:
        await runtime.application.drain()
        await runtime.application.stop()

    assert denied.status is InvocationStatus.FAILURE
    assert denied.error is not None
    assert denied.error.code is ErrorCode.APPROVAL_REQUIRED
    assert allowed.status is InvocationStatus.SUCCESS
    assert allowed.value == {
        "effect_id": "effect-000001",
        "order_id": "order-001",
        "status": "approved",
    }
    assert store.effect_count == 1


async def test_failure_deadline_and_canary_are_safe_at_the_final_boundary() -> None:
    store = BackingStore()
    transport = InProcessTransport()
    runtime = build_reference_runtime(
        transport=transport,
        backing=backing_client(store),
        wall_clock=lambda: NOW,
    )
    await runtime.application.start()
    try:
        failed = await transport.invoke("journey.fail", {}, context=context())
        timed_out = await transport.invoke(
            "journey.slow",
            {"delay_ms": 200},
            context=context(deadline=SystemClock().now() + 0.01),
        )
        redacted = await transport.invoke(
            "journey.secret_canary",
            {},
            context=context(),
        )
        metrics = runtime.observability.render_prometheus()
    finally:
        await runtime.application.drain()
        await runtime.application.stop()

    assert failed.status is InvocationStatus.FAILURE
    assert failed.error is not None
    assert failed.error.code is ErrorCode.INTERNAL_FAILURE
    assert JOURNEY_CANARY not in json.dumps(failed.error.to_dict())
    assert timed_out.status is InvocationStatus.FAILURE
    assert timed_out.error is not None
    assert timed_out.error.code is ErrorCode.TIMEOUT
    assert redacted.status is InvocationStatus.SUCCESS
    assert redacted.value == {"api_key": "[REDACTED]"}
    assert JOURNEY_CANARY not in json.dumps(redacted.value)
    assert "mcp_server_request_count_total" in metrics


async def test_backing_client_propagates_verified_context_without_bearer_authority() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "effect_id": "effect-000001",
                "order_id": "order-001",
                "status": "created",
            },
        )

    client = BackingClient(
        endpoint="http://backing.test",
        transport=httpx.MockTransport(handler),
    )
    result = await client.write_order(
        context(idempotency_key="write-order-001"),
        order_id="order-001",
        status="created",
    )
    await client.stop()

    assert result["effect_id"] == "effect-000001"
    assert len(seen) == 1
    request = seen[0]
    assert request.headers["x-journey-tenant"] == "tenant-a"
    assert request.headers["x-journey-subject"] == "subject-a"
    assert request.headers["x-journey-scopes"] == ("journey:approve journey:read journey:write")
    assert request.headers["idempotency-key"] == "write-order-001"
    assert request.headers["traceparent"] == TRACEPARENT
    assert "authorization" not in request.headers


async def test_jwks_fetcher_is_bounded_and_rejects_dependency_failures() -> None:
    authority = IdentityAuthority(
        issuer=ISSUER,
        audience=AUDIENCE,
        now=lambda: NOW,
    )
    valid = JourneyJWKSFetcher(
        endpoint="http://identity.test/jwks.json",
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json=authority.jwks_document())
        ),
    )
    oversized = JourneyJWKSFetcher(
        endpoint="http://identity.test/jwks.json",
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, content=b"x" * 65_537)),
    )
    unavailable = JourneyJWKSFetcher(
        endpoint="http://identity.test/jwks.json",
        transport=httpx.MockTransport(lambda _request: httpx.Response(503)),
    )

    assert await valid.fetch() == authority.jwks_document()
    with pytest.raises(JWKSFetchError):
        await oversized.fetch()
    with pytest.raises(JWKSFetchError):
        await unavailable.fetch()
    await valid.stop()
    await oversized.stop()
    await unavailable.stop()


class StaticContextProvider:
    def __init__(self, resolved: CallContext) -> None:
        self.resolved = resolved

    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: CancellationProtocol,
    ) -> CallContext:
        del request, cancellation
        return self.resolved


async def test_tenant_bound_context_provider_returns_one_non_disclosing_failure() -> None:
    request = HTTPRequestMetadata(method="POST", path="/mcp", headers=(), peer_host="172.30.0.3")
    allowed = TenantBoundContextProvider(
        StaticContextProvider(context()),
        tenant="tenant-a",
    )
    denied = TenantBoundContextProvider(
        StaticContextProvider(context(tenant="tenant-b")),
        tenant="tenant-a",
    )

    assert (await allowed.create(request, cancellation=FakeCancellation())).tenant == "tenant-a"
    with pytest.raises(HTTPRequestAuthenticationError) as captured:
        await denied.create(request, cancellation=FakeCancellation())

    assert captured.value.request_id == "request-runtime-001"
    assert "tenant" not in str(captured.value)


async def test_gateway_provider_and_route_wrapper_enforce_tenant() -> None:
    authority = IdentityAuthority(
        issuer=ISSUER,
        audience=AUDIENCE,
        now=lambda: NOW,
    )
    fetcher = JourneyJWKSFetcher(
        endpoint="http://identity.test/jwks.json",
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json=authority.jwks_document())
        ),
    )
    provider = GatewayJWTContextProvider(
        GatewayIdentityConfig(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_url="https://identity.journey.invalid/jwks.json",
            jwks_allowed_hosts=("identity.journey.invalid",),
            trusted_proxy_cidrs=("172.30.0.0/24",),
        ),
        jwks_fetcher=fetcher,
        wall_clock=lambda: NOW,
        cache_clock=lambda: 100.0,
        request_id_factory=lambda: "request-generated",
    )
    bound = TenantBoundContextProvider(provider, tenant="tenant-a")

    async def resolve(tenant: str) -> CallContext:
        encoded = authority.issue(
            TokenRequest(
                tenant=tenant,
                subject="subject-a",
                scopes=("journey:read",),
                run_id="journey-run-001",
            )
        )
        request = HTTPRequestMetadata(
            method="POST",
            path="/mcp",
            headers=(("authorization", f"Bearer {encoded.reveal()}"),),
            peer_host="172.30.0.3",
        )
        return await bound.create(request, cancellation=FakeCancellation())

    owner = await resolve("tenant-a")
    with pytest.raises(HTTPRequestAuthenticationError):
        await resolve("tenant-b")
    await fetcher.stop()

    assert owner.tenant == "tenant-a"
    assert owner.subject == "subject-a"
    assert owner.scopes == ("journey:read",)


def test_reference_configuration_rejects_unsafe_dependency_endpoints() -> None:
    for endpoint in (
        "https://backing.example.com",
        "http://user:pass@backing.test",
        "http://127.0.0.1:8082/path",
    ):
        with pytest.raises(ValueError, match="endpoint"):
            BackingClient(endpoint=endpoint)

    with pytest.raises(ValueError, match="endpoint"):
        JourneyJWKSFetcher(endpoint="https://identity.example.com/jwks.json")


def test_reference_audit_and_telemetry_types_never_render_tokens() -> None:
    runtime = build_reference_runtime(
        transport=InProcessTransport(),
        backing=backing_client(BackingStore()),
        wall_clock=lambda: NOW,
    )
    rendered = repr(runtime.audit)

    assert "Bearer" not in rendered
    assert JOURNEY_CANARY not in rendered
    assert runtime.audit.events == ()
