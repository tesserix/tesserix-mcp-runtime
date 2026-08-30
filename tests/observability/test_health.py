from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tesserix_mcp_runtime import (
    Application,
    ApplicationLimits,
    ApprovalRequirement,
    AuthenticatedIdentity,
    CallContext,
    IdempotencyRequirement,
    InvocationResult,
    JsonValue,
    ScrubbedError,
    SystemClock,
    ToolCatalog,
    ToolDefinition,
    ToolEffect,
    ToolMetadata,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport
from tesserix_mcp_runtime.application import ApplicationEndpoint
from tesserix_mcp_runtime.health import RuntimeOperationsEndpoint
from tesserix_mcp_runtime.observability import RuntimeObservability


class Cancellation:
    @property
    def cancelled(self) -> bool:
        return False

    async def wait(self) -> None:
        await asyncio.Future[None]()


class AllowAll:
    async def authorize(
        self,
        *,
        tool: ToolDefinition[Any, JsonValue],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context


class IgnoreTelemetry:
    def emit(self, event: ScrubbedError) -> None:
        del event


class MutableReadinessCheck:
    name = "orders_dependency"

    def __init__(self) -> None:
        self.result = True
        self.failure: Exception | None = None
        self.calls = 0

    async def ready(self) -> bool:
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return self.result


class ObservingTransport:
    name = "observing_transport"

    def __init__(self) -> None:
        self.endpoint: object | None = None
        self.accepting = False
        self.readiness_before_admission_closed: bool | None = None

    async def start(self, endpoint: ApplicationEndpoint) -> None:
        self.endpoint = endpoint
        self.accepting = True

    async def drain(self, *, deadline: float) -> None:
        del deadline
        endpoint = self.endpoint
        assert isinstance(endpoint, RuntimeOperationsEndpoint)
        assert self.accepting
        self.readiness_before_admission_closed = await endpoint.readiness_status()
        self.accepting = False

    async def stop(self) -> None:
        self.accepting = False


class SignalingInProcessTransport(InProcessTransport):
    def __init__(self) -> None:
        super().__init__()
        self.draining = asyncio.Event()

    async def drain(self, *, deadline: float) -> None:
        self.draining.set()
        await super().drain(deadline=deadline)


@dataclass(frozen=True, slots=True)
class Input:
    text: str


class BlockingTool:
    metadata = ToolMetadata(
        name="orders.block",
        title="Block",
        description="Wait for a deterministic test gate.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("orders:read",),
    )
    input_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {"text": {"type": "string", "maxLength": 64}},
        "required": ["text"],
        "additionalProperties": False,
    }
    output_schema = input_schema

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> Input:
        text = arguments.get("text")
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        return Input(text)

    async def handler(self, input_model: Input, *, context: CallContext) -> Input:
        del context
        self.entered.set()
        await self.release.wait()
        return input_model

    def serialize_output(self, output_model: Input) -> JsonValue:
        return {"text": output_model.text}


def context() -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant="tenant-example",
            subject="subject-example",
            issuer="https://identity.example.invalid",
            scopes=("orders:read",),
        ),
        request_id="request-example",
        run_id="run-example",
        cancellation=Cancellation(),
    )


def test_liveness_never_checks_dependencies_and_readiness_is_state_aware() -> None:
    async def exercise() -> None:
        check = MutableReadinessCheck()
        application = Application(
            catalog=ToolCatalog([]),
            authorizer=AllowAll(),
            transport=InProcessTransport(),
            telemetry=IgnoreTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0, readiness_timeout=0.1),
            clock=SystemClock(),
            readiness_checks=(check,),
        )

        assert application.liveness_status()
        assert not await application.readiness_status()
        assert check.calls == 0
        await application.start()
        assert application.startup_status()
        assert await application.readiness_status()
        assert check.calls == 1

        check.failure = RuntimeError("SyntheticReadinessCanary7Jx4")
        assert not await application.readiness_status()
        assert check.calls == 2
        assert application.liveness_status()
        assert check.calls == 2

        await application.drain()
        assert not await application.readiness_status()
        assert check.calls == 2
        await application.stop()

    asyncio.run(exercise())


def test_readiness_turns_false_before_transport_admission_closes() -> None:
    async def exercise() -> None:
        transport = ObservingTransport()
        application = Application(
            catalog=ToolCatalog([]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=IgnoreTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            clock=SystemClock(),
        )
        await application.start()

        await application.drain()

        assert transport.readiness_before_admission_closed is False
        assert not transport.accepting
        await application.stop()

    asyncio.run(exercise())


def test_in_flight_metrics_reach_zero_after_graceful_drain() -> None:
    async def exercise() -> None:
        tool = BlockingTool()
        transport = SignalingInProcessTransport()
        observability = RuntimeObservability(server_name="orders-mcp")
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=IgnoreTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            clock=SystemClock(),
            observability=observability,
        )
        await application.start()
        invocation = asyncio.create_task(
            transport.invoke("orders.block", {"text": "hello"}, context=context())
        )
        await tool.entered.wait()
        assert 'mcp_server_in_flight{server="orders-mcp"} 1' in (observability.render_prometheus())

        draining = asyncio.create_task(application.drain())
        await transport.draining.wait()
        assert not await application.readiness_status()
        tool.release.set()

        assert await invocation == InvocationResult.success({"text": "hello"})
        await draining
        assert 'mcp_server_in_flight{server="orders-mcp"} 0' in (observability.render_prometheus())
        rejected = await application.invoke(
            "orders.block",
            {"text": "new-work"},
            context=context(),
        )
        assert rejected.error is not None
        assert (
            'mcp_server_limit_count_total{limit="drain",server="orders-mcp",'
            'tool="orders.block"} 1' in observability.render_prometheus()
        )
        await application.stop()

    asyncio.run(exercise())
