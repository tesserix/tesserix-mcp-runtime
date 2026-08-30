from __future__ import annotations

import asyncio

import pytest
from tesserix_mcp_testkit import (
    CONFORMANCE_TOOL_NAME,
    FakeBackingAPI,
    FakeClock,
    FakeCredentialIssuer,
    FakeGateway,
    FakeIdentityFactory,
    FakeMCPClient,
    FakeRegistry,
    FaultKind,
    FaultScript,
    FaultStep,
    InjectedFault,
    RegistryRecord,
)

from tesserix_mcp_runtime import ErrorCode, ErrorResponse, InvocationResult
from tesserix_mcp_runtime.adapters.streamable_http import HTTPRequestMetadata


class Cancellation:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()


def test_fake_clock_advances_without_sleeping_or_reading_wall_time() -> None:
    async def exercise() -> None:
        clock = FakeClock(now=100.0)
        await clock.sleep(2.5)
        await clock.sleep(0.0)

        assert clock.now() == 102.5
        assert clock.sleeps == (2.5, 0.0)

    asyncio.run(exercise())


def test_identity_factory_produces_bounded_distinct_contexts_and_tenants() -> None:
    identities = FakeIdentityFactory(
        issuer="https://identity.example.invalid",
        default_scopes=("tools:invoke",),
    )

    first = identities.context(tenant="tenant-a")
    second = identities.context(tenant="tenant-b", scopes=("tools:read",))

    assert first.tenant == "tenant-a"
    assert first.request_id == "test-request-1"
    assert first.scopes == ("tools:invoke",)
    assert second.tenant == "tenant-b"
    assert second.request_id == "test-request-2"
    assert second.scopes == ("tools:read",)
    assert first.subject == second.subject == "test-subject"


def test_credential_issuer_records_authority_and_redacts_fake_values() -> None:
    async def exercise() -> None:
        context = FakeIdentityFactory().context(tenant="tenant-a")
        issuer = FakeCredentialIssuer()

        credential = await issuer.issue(
            audience="https://api.example.invalid",
            scopes=("orders:read",),
            context=context,
        )

        assert str(credential) == "[REDACTED]"
        assert credential.reveal() == "test-credential-1"
        assert issuer.requests[0].audience == "https://api.example.invalid"
        assert issuer.requests[0].scopes == ("orders:read",)
        assert issuer.requests[0].tenant == "tenant-a"

    asyncio.run(exercise())


def test_backing_api_and_registry_consume_scripts_without_network() -> None:
    async def exercise() -> None:
        backing = FakeBackingAPI(FaultScript((FaultStep.success({"status": "ok"}),)))
        records = (
            RegistryRecord(
                server_id="orders-mcp",
                capability="orders.read",
                score=0.9,
            ),
        )
        registry = FakeRegistry(FaultScript((FaultStep.success(records),)))

        assert await backing.request("GET", "/orders/1", {"request": "bounded"}) == {"status": "ok"}
        assert backing.requests[0].method == "GET"
        assert backing.requests[0].path == "/orders/1"
        assert await registry.search("find orders", limit=5) == records
        assert registry.queries[0].text == "find orders"
        assert registry.queries[0].limit == 5

    asyncio.run(exercise())


def test_gateway_uses_scripted_context_and_preserves_cancellation() -> None:
    async def exercise() -> None:
        context = FakeIdentityFactory().context(tenant="tenant-a")
        gateway = FakeGateway(FaultScript((FaultStep.success(context),)))
        cancellation = Cancellation()
        request = HTTPRequestMetadata(
            method="POST",
            path="/mcp",
            headers=(("authorization", "not-a-real-credential"),),
        )

        observed = await gateway.create(request, cancellation=cancellation)

        assert observed is context
        assert gateway.requests == (request,)
        assert gateway.cancellations == (cancellation,)

    asyncio.run(exercise())


def test_mcp_client_scripts_discovery_calls_and_unavailability() -> None:
    async def exercise() -> None:
        client = FakeMCPClient(
            list_script=FaultScript((FaultStep.success((CONFORMANCE_TOOL_NAME,)),)),
            call_script=FaultScript(
                (
                    FaultStep.success(InvocationResult.success("ok")),
                    FaultStep.inject(FaultKind.UNAVAILABLE),
                )
            ),
        )

        assert await client.list_tools() == (CONFORMANCE_TOOL_NAME,)
        assert await client.call_tool(CONFORMANCE_TOOL_NAME, {"text": "hello"}) == (
            InvocationResult.success("ok")
        )
        with pytest.raises(InjectedFault) as captured:
            await client.call_tool(CONFORMANCE_TOOL_NAME, {"text": "again"})
        assert captured.value.kind is FaultKind.UNAVAILABLE
        assert [call.name for call in client.calls] == [
            CONFORMANCE_TOOL_NAME,
            CONFORMANCE_TOOL_NAME,
        ]

    asyncio.run(exercise())


def test_mcp_client_preserves_stable_failure_results() -> None:
    async def exercise() -> None:
        client = FakeMCPClient(
            list_script=FaultScript((FaultStep.success(()),)),
            call_script=FaultScript(
                (
                    FaultStep.success(
                        InvocationResult.failure(
                            ErrorResponse.from_code(
                                ErrorCode.FORBIDDEN,
                                request_id="test-request",
                            )
                        )
                    ),
                )
            ),
        )

        result = await client.call_tool(CONFORMANCE_TOOL_NAME, {})
        assert result.error is not None
        assert result.error.code is ErrorCode.FORBIDDEN

    asyncio.run(exercise())
