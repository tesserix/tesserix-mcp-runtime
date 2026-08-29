from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager

import httpx2 as httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from tesserix_adk.adapters.mcp_server import McpExportError, published
from tesserix_adk.adapters.mcp_surface import fingerprint
from tesserix_adk.core.errors import ToolRefusal, ToolTimedOutError
from tesserix_adk.core.hooks import ApprovalPolicy
from tesserix_adk.mcp import META_PREFIX
from tesserix_adk.tools import ToolContext, ToolRegistry, tool

from tesserix_mcp_runtime import AuthenticatedIdentity, CallContext, TraceContext
from tesserix_mcp_runtime.adapters.adk import ADKStreamableHTTPBridge
from tesserix_mcp_runtime.adapters.streamable_http import (
    ASGIApplication,
    HTTPCallContextProvider,
    HTTPRequestMetadata,
    ProtocolTelemetryEvent,
    StreamableHTTPConfig,
    StreamableHTTPLimits,
    StreamableHTTPTransport,
)
from tesserix_mcp_runtime.contracts import Cancellation


class _ContextProvider:
    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        del request
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
            cancellation=cancellation,
            idempotency_key="idempotency-example",
        )


class _Telemetry:
    def emit(self, event: ProtocolTelemetryEvent) -> None:
        del event


class _MissingContextProvider:
    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        del request, cancellation
        raise PermissionError("no authenticated tenant")


class _Listener:
    def __init__(self) -> None:
        self.app: ASGIApplication | None = None
        self._receive: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self._send: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None

    @property
    def bound_port(self) -> int:
        return 8000

    async def start(self, app: ASGIApplication, *, startup_timeout: float) -> None:
        self.app = app

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
            raise RuntimeError("fixture lifespan did not start")

    async def stop(self) -> None:
        task = self._task
        if task is not None:
            await self._receive.put({"type": "lifespan.shutdown"})
            message = await asyncio.wait_for(self._send.get(), timeout=2)
            if message.get("type") != "lifespan.shutdown.complete":
                raise RuntimeError("fixture lifespan did not stop")
            await task
            self._task = None
        self.app = None


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


@asynccontextmanager
async def _remote_session(
    bridge: ADKStreamableHTTPBridge,
    *,
    context_provider: HTTPCallContextProvider | None = None,
) -> AsyncIterator[ClientSession]:
    listener = _Listener()
    transport = StreamableHTTPTransport(
        config=StreamableHTTPConfig(),
        limits=StreamableHTTPLimits(),
        context_provider=context_provider or _ContextProvider(),
        telemetry=_Telemetry(),
        listener=listener,
    )
    await transport.start(bridge)
    assert listener.app is not None
    try:
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
            yield session
    finally:
        await transport.stop()


def test_adk_success_is_byte_equivalent_locally_and_over_streamable_http() -> None:
    @tool(name="fare_for")
    def fare_for(leg: str) -> dict[str, object]:
        """Price one leg."""
        return {"leg": leg, "eur": 40}

    async def exercise() -> None:
        view = ToolRegistry((fare_for,)).view(allow=("fare_for",), agent="planner")
        local = await view.invoke("fare_for", {"leg": "Osaka"})
        bridge = ADKStreamableHTTPBridge(
            view,
            exports=("fare_for",),
            name="fares",
            version="1.0.0",
        )
        async with _remote_session(bridge) as session:
            listed = await session.list_tools()
            remote = await session.call_tool("fare_for", {"leg": "Osaka"})

        assert [descriptor.name for descriptor in listed.tools] == ["fare_for"]
        assert remote.is_error is False
        assert remote.structured_content is not None
        assert isinstance(local, Mapping)
        assert _canonical(remote.structured_content) == _canonical(local)

    asyncio.run(exercise())


def test_unexported_and_unknown_adk_tools_are_indistinguishable() -> None:
    @tool(name="visible")
    def visible() -> str:
        """Return a public value."""
        return "visible"

    @tool(name="hidden")
    def hidden() -> str:
        """Return an internal value."""
        return "hidden"

    async def exercise() -> None:
        view = ToolRegistry((visible, hidden)).view(
            allow=("visible", "hidden"),
            agent="planner",
        )
        bridge = ADKStreamableHTTPBridge(view, exports=("visible",))
        errors: list[dict[str, object]] = []
        async with _remote_session(bridge) as session:
            for name in ("hidden", "missing"):
                with pytest.raises(MCPError) as raised:
                    await session.call_tool(name, {})
                errors.append(raised.value.error.model_dump(mode="json"))

        assert errors[0] == errors[1]
        rendered = json.dumps(errors, sort_keys=True)
        assert "hidden" not in rendered
        assert "missing" not in rendered

    asyncio.run(exercise())


def test_mismatched_remote_tenant_is_rejected_before_the_tool_body() -> None:
    calls = 0

    @tool(name="whose")
    def whose() -> str:
        """Return only after the authenticated boundary admits the call."""
        nonlocal calls
        calls += 1
        return "called"

    async def exercise() -> None:
        view = ToolRegistry((whose,)).view(allow=("whose",), agent="planner")
        bridge = ADKStreamableHTTPBridge(view, exports=("whose",))
        async with _remote_session(bridge) as session:
            with pytest.raises(MCPError) as raised:
                await session.call_tool(
                    "whose",
                    {},
                    meta={f"{META_PREFIX}/tenant": "globex"},
                )

        assert calls == 0
        rendered = json.dumps(raised.value.error.model_dump(mode="json"), sort_keys=True)
        assert "acme" not in rendered
        assert "globex" not in rendered

    asyncio.run(exercise())


def test_approval_required_result_is_preserved_without_running_the_tool() -> None:
    calls = 0

    @tool(
        name="refund",
        requires_approval=ApprovalPolicy(required=True, reason="money leaves"),
    )
    def refund(order: str, amount: int) -> dict[str, object]:
        """Refund one order."""
        nonlocal calls
        calls += 1
        return {"order": order, "amount": amount}

    async def exercise() -> None:
        view = ToolRegistry((refund,)).view(allow=("refund",), agent="planner")
        bridge = ADKStreamableHTTPBridge(view, exports=("refund",))
        async with _remote_session(bridge) as session:
            result = await session.call_tool("refund", {"order": "A-1", "amount": 40})

        assert calls == 0
        assert result.is_error is True
        assert result.structured_content is not None
        assert result.structured_content["refusal"] == {"code": "approval_required"}
        assert isinstance(result.structured_content["approval"], dict)

    asyncio.run(exercise())


def test_adk_refusal_code_matches_the_local_tool_without_its_message() -> None:
    @tool(name="decline")
    def decline(order: str) -> str:
        """Decline every call."""
        raise ToolRefusal("decline", "not_cancellable", f"{order} has shipped")

    async def exercise() -> None:
        view = ToolRegistry((decline,)).view(allow=("decline",), agent="planner")
        with pytest.raises(ToolRefusal) as local:
            await view.invoke("decline", {"order": "A-1"})
        bridge = ADKStreamableHTTPBridge(view, exports=("decline",))
        async with _remote_session(bridge) as session:
            remote = await session.call_tool("decline", {"order": "A-1"})

        assert remote.is_error is True
        assert remote.structured_content is not None
        assert remote.structured_content["refusal"] == {"code": local.value.code}
        assert "has shipped" not in json.dumps(remote.model_dump(mode="json"), sort_keys=True)

    asyncio.run(exercise())


def test_adk_failure_code_is_preserved_without_the_failure_message() -> None:
    @tool(name="slow")
    def slow() -> str:
        """Model a tool whose own ceiling elapsed."""
        raise ToolTimedOutError("slow", 1)

    async def exercise() -> None:
        view = ToolRegistry((slow,)).view(allow=("slow",), agent="planner")
        with pytest.raises(ToolTimedOutError):
            await view.invoke("slow", {})
        bridge = ADKStreamableHTTPBridge(view, exports=("slow",))
        async with _remote_session(bridge) as session:
            remote = await session.call_tool("slow", {})

        assert remote.is_error is True
        assert remote.structured_content == {"failure": {"code": "tool_timed_out"}}
        assert "timed out" not in json.dumps(remote.model_dump(mode="json"), sort_keys=True)

    asyncio.run(exercise())


def test_adk_tool_context_comes_from_authenticated_runtime_context() -> None:
    @tool(name="context")
    def context(tool_context: ToolContext) -> dict[str, object]:
        """Return the authority visible inside the tool."""
        return {
            "tenant": tool_context.tenant,
            "user": tool_context.user,
            "run": tool_context.run_id,
            "scopes": list(tool_context.scopes),
            "traceparent_matches": tool_context.trace.get("traceparent")
            == "00-11111111111111111111111111111111-1111111111111111-01",
            "idempotency_key": tool_context.idempotency_key,
        }

    async def exercise() -> None:
        view = ToolRegistry((context,)).view(allow=("context",), agent="planner")
        bridge = ADKStreamableHTTPBridge(view, exports=("context",))
        async with _remote_session(bridge) as session:
            remote = await session.call_tool(
                "context",
                {},
                meta={
                    f"{META_PREFIX}/tenant": "acme",
                    f"{META_PREFIX}/subject": "mallory",
                    f"{META_PREFIX}/run": "untrusted-run",
                    f"{META_PREFIX}/scopes": "admin",
                    f"{META_PREFIX}/idempotency-key": "untrusted-key",
                },
            )

        assert remote.structured_content == {
            "tenant": "acme",
            "user": "ada",
            "run": "run-1",
            "scopes": ["fares:read"],
            "traceparent_matches": True,
            "idempotency_key": "idempotency-example",
        }

    asyncio.run(exercise())


def test_bridge_construction_cannot_widen_the_adk_view() -> None:
    @tool(name="widen_visible")
    def widen_visible() -> str:
        """Return a public value."""
        return "visible"

    @tool(name="widen_outside_view")
    def widen_outside_view() -> str:
        """Remain outside this agent's authority."""
        return "outside"

    view = ToolRegistry((widen_visible, widen_outside_view)).view(
        allow=("widen_visible",),
        agent="planner",
    )

    with pytest.raises(McpExportError):
        ADKStreamableHTTPBridge(
            view,
            exports=("widen_visible", "widen_outside_view"),
        )


def test_bridge_uses_adk_generated_descriptors_and_fingerprints() -> None:
    @tool(name="descriptor_fare_for")
    def descriptor_fare_for(leg: str) -> dict[str, object]:
        """Price one leg."""
        return {"leg": leg, "eur": 40}

    view = ToolRegistry((descriptor_fare_for,)).view(
        allow=("descriptor_fare_for",),
        agent="planner",
    )
    adk_descriptor = published(descriptor_fare_for)
    runtime_descriptor = ADKStreamableHTTPBridge(
        view,
        exports=("descriptor_fare_for",),
    ).protocol_tools()[0]

    assert runtime_descriptor.name == adk_descriptor.name
    assert runtime_descriptor.description == adk_descriptor.description
    assert runtime_descriptor.input_schema == adk_descriptor.input_schema
    assert runtime_descriptor.output_schema == adk_descriptor.output_schema
    assert runtime_descriptor.fingerprint == fingerprint(adk_descriptor)


def test_adk_result_redaction_is_preserved_over_streamable_http() -> None:
    secret = "credential-value-123456"

    @tool(name="leak")
    def leak() -> dict[str, object]:
        """Model a body that accidentally returns a held secret."""
        return {"note": f"the credential is {secret}"}

    async def exercise() -> None:
        view = ToolRegistry((leak,)).view(allow=("leak",), agent="planner")
        bridge = ADKStreamableHTTPBridge(
            view,
            exports=("leak",),
            secrets=(secret,),
        )
        async with _remote_session(bridge) as session:
            remote = await session.call_tool("leak", {})

        rendered = json.dumps(remote.model_dump(mode="json"), sort_keys=True)
        assert secret not in rendered
        assert "[redacted]" in rendered

    asyncio.run(exercise())


def test_missing_authenticated_tenant_is_rejected_before_adk_session_use() -> None:
    calls = 0

    @tool(name="guarded")
    def guarded() -> str:
        """Run only after transport authentication succeeds."""
        nonlocal calls
        calls += 1
        return "called"

    async def exercise() -> None:
        view = ToolRegistry((guarded,)).view(allow=("guarded",), agent="planner")
        bridge = ADKStreamableHTTPBridge(view, exports=("guarded",))
        rejected = False
        try:
            async with _remote_session(
                bridge,
                context_provider=_MissingContextProvider(),
            ):
                pass
        except* MCPError as failures:
            rejected = True
            assert "Unauthorized" in repr(failures)
        assert rejected
        assert calls == 0

    asyncio.run(exercise())


def test_exact_adk_release_accepts_the_modern_protocol_revision() -> None:
    @tool(name="modern_revision")
    def modern_revision() -> str:
        """Return through the modern protocol lane."""
        return "modern"

    async def exercise() -> None:
        view = ToolRegistry((modern_revision,)).view(
            allow=("modern_revision",),
            agent="planner",
        )
        bridge = ADKStreamableHTTPBridge(view, exports=("modern_revision",))
        session = bridge.connect(
            context=CallContext(
                identity=AuthenticatedIdentity(
                    tenant="acme",
                    subject="ada",
                    issuer="https://gateway.internal.example",
                    scopes=("fares:read",),
                ),
                request_id="modern-request",
                run_id="modern-run",
            ),
            protocol_version="2026-07-28",
        )
        await session.initialize()
        assert [item.name for item in await session.list_tools()] == ["modern_revision"]
        await session.close()

    asyncio.run(exercise())
