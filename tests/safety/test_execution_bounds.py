from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tesserix_mcp_runtime import (
    Application,
    ApplicationConfigurationError,
    ApplicationLimits,
    ApprovalRequirement,
    AuthenticatedIdentity,
    CallContext,
    Cancellation,
    ErrorCode,
    ExecutionLimits,
    IdempotencyRequirement,
    JsonValue,
    RuntimeFailure,
    ScrubbedError,
    SystemClock,
    ToolEffect,
    ToolHandler,
    ToolMetadata,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport
from tesserix_mcp_runtime.contracts import ToolDefinition
from tesserix_mcp_runtime.observability import RuntimeObservability
from tesserix_mcp_runtime.tool import ToolCatalog


@dataclass(frozen=True, slots=True)
class BoundedInput:
    value: str


@dataclass(frozen=True, slots=True)
class BoundedOutput:
    value: str


class RecordingHandler:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(
        self,
        input_model: BoundedInput,
        *,
        context: CallContext,
    ) -> BoundedOutput:
        del context
        self.calls += 1
        return BoundedOutput(value=input_model.value)


class BoundedTool:
    def __init__(
        self,
        *,
        name: str = "bounds.echo",
        handler: ToolHandler[BoundedInput, BoundedOutput] | None = None,
        effect: ToolEffect = ToolEffect.READ,
    ) -> None:
        self.metadata = ToolMetadata(
            name=name,
            title="Bounded echo",
            description="Return one bounded value.",
            effect=effect,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=(
                IdempotencyRequirement.NOT_APPLICABLE
                if effect is ToolEffect.READ
                else IdempotencyRequirement.REQUIRED
            ),
            required_scopes=(),
        )
        self.input_schema: Mapping[str, JsonValue] = {
            "type": "object",
            "properties": {"value": {"type": "string", "maxLength": 65_536}},
            "required": ["value"],
            "additionalProperties": False,
        }
        self.output_schema = self.input_schema
        self.handler = handler or RecordingHandler()
        self.parse_calls = 0

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> BoundedInput:
        self.parse_calls += 1
        return BoundedInput(value=str(arguments["value"]))

    def serialize_output(self, output_model: BoundedOutput) -> JsonValue:
        return {"value": output_model.value}


class AllowAll:
    async def authorize(
        self,
        *,
        tool: ToolDefinition[object, object],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context


class BlockingAuthorizer:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = 0

    async def authorize(
        self,
        *,
        tool: ToolDefinition[object, object],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context
        self.calls += 1
        self.entered.set()
        await self.release.wait()


class RecordingTelemetry:
    def __init__(self) -> None:
        self.events: list[ScrubbedError] = []

    def emit(self, event: ScrubbedError) -> None:
        self.events.append(event)


class TenantBlockingHandler:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.calls: list[str] = []

    async def __call__(
        self,
        input_model: BoundedInput,
        *,
        context: CallContext,
    ) -> BoundedOutput:
        self.calls.append(context.tenant)
        if input_model.value == "hold":
            self.entered.set()
            await self.release.wait()
        return BoundedOutput(value=input_model.value)


class DeadlineRecordingHandler:
    def __init__(self) -> None:
        self.deadlines: list[float | None] = []

    async def __call__(
        self,
        input_model: BoundedInput,
        *,
        context: CallContext,
    ) -> BoundedOutput:
        self.deadlines.append(context.deadline)
        return BoundedOutput(value=input_model.value)


class DeadlineBlockingHandler:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.context_cancelled = False

    async def __call__(
        self,
        input_model: BoundedInput,
        *,
        context: CallContext,
    ) -> BoundedOutput:
        self.entered.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.context_cancelled = context.cancelled
            self.cancelled.set()
            raise
        return BoundedOutput(value=input_model.value)


class CooperativeCancellationHandler:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.observed = asyncio.Event()

    async def __call__(
        self,
        input_model: BoundedInput,
        *,
        context: CallContext,
    ) -> BoundedOutput:
        self.entered.set()
        await context.cancellation.wait()
        self.observed.set()
        return BoundedOutput(value=input_model.value)


class StubbornHandler:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.ignored_cancellation = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(
        self,
        input_model: BoundedInput,
        *,
        context: CallContext,
    ) -> BoundedOutput:
        self.entered.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            assert context.cancelled
            self.ignored_cancellation.set()
            await self.release.wait()
        return BoundedOutput(value=input_model.value)


class TransientHandler:
    def __init__(self, failures: int) -> None:
        self._failures = failures
        self.failed: asyncio.Queue[int] = asyncio.Queue()
        self.calls = 0
        self.idempotency_keys: list[str | None] = []

    async def __call__(
        self,
        input_model: BoundedInput,
        *,
        context: CallContext,
    ) -> BoundedOutput:
        self.calls += 1
        self.idempotency_keys.append(context.idempotency_key)
        if self.calls <= self._failures:
            self.failed.put_nowait(self.calls)
            raise RuntimeFailure(ErrorCode.UNAVAILABLE)
        return BoundedOutput(value=input_model.value)


class FixedFailureHandler:
    def __init__(self, code: ErrorCode) -> None:
        self._code = code
        self.calls = 0

    async def __call__(
        self,
        input_model: BoundedInput,
        *,
        context: CallContext,
    ) -> BoundedOutput:
        del input_model, context
        self.calls += 1
        raise RuntimeFailure(self._code)


class ManualClock:
    def __init__(self, now: float) -> None:
        self._now = now
        self._sleepers: list[tuple[float, asyncio.Future[None]]] = []
        self.sleep_requests: asyncio.Queue[float] = asyncio.Queue()

    def now(self) -> float:
        return self._now

    async def sleep(self, seconds: float) -> None:
        self.sleep_requests.put_nowait(seconds)
        deadline = self._now + seconds
        if deadline <= self._now:
            return
        sleeper = asyncio.get_running_loop().create_future()
        self._sleepers.append((deadline, sleeper))
        try:
            await sleeper
        finally:
            self._sleepers = [item for item in self._sleepers if item[1] is not sleeper]

    def advance(self, seconds: float) -> None:
        self._now += seconds
        for deadline, sleeper in tuple(self._sleepers):
            if deadline <= self._now and not sleeper.done():
                sleeper.set_result(None)

    async def next_short_sleep(self) -> float:
        while True:
            seconds = await self.sleep_requests.get()
            if seconds <= 5.0:
                return seconds


class ManualCancellation:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()

    def cancel(self) -> None:
        self._event.set()


def call_context(
    *,
    tenant: str = "tenant-blue",
    deadline: float | None = None,
    cancellation: Cancellation | None = None,
    idempotency_key: str | None = None,
) -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant=tenant,
            subject="subject-example",
            issuer="https://issuer.example",
            scopes=(),
        ),
        request_id=f"request-{tenant}",
        run_id="run-example",
        deadline=deadline,
        cancellation=cancellation or ManualCancellation(),
        idempotency_key=idempotency_key,
    )


@pytest.mark.parametrize(
    ("arguments", "limits"),
    [
        ({"value": "x" * 64}, ExecutionLimits(max_input_bytes=32)),
        ({"value": {"nested": {"too": "deep"}}}, ExecutionLimits(max_json_depth=2)),
        ({"a": 1, "b": 2, "c": 3}, ExecutionLimits(max_object_properties=2)),
        ({"value": [1, 2, 3]}, ExecutionLimits(max_array_items=2)),
        ({"value": [1, 2, 3, 4]}, ExecutionLimits(max_json_nodes=4)),
    ],
    ids=["bytes", "depth", "properties", "array-items", "nodes"],
)
def test_over_limit_arguments_are_rejected_before_tool_parsing(
    arguments: Mapping[str, JsonValue],
    limits: ExecutionLimits,
) -> None:
    async def exercise() -> None:
        handler = RecordingHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        observability = RuntimeObservability(server_name="bounds-mcp")
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=limits,
            clock=SystemClock(),
            observability=observability,
        )
        await application.start()

        result = await transport.invoke(
            tool.metadata.name,
            arguments,
            context=call_context(),
        )

        assert result.error is not None
        assert result.error.code.value == "invalid_input"
        assert tool.parse_calls == 0
        assert handler.calls == 0
        assert (
            'mcp_server_limit_count_total{limit="input",server="bounds-mcp",'
            f'tool="{tool.metadata.name}"}} 1' in observability.render_prometheus()
        )

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_exact_input_and_result_byte_ceilings_are_accepted() -> None:
    async def exercise() -> None:
        value = "exact-ceiling"
        encoded_size = len(b'{"value":"exact-ceiling"}')
        handler = RecordingHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_input_bytes=encoded_size,
                max_result_bytes=encoded_size,
            ),
            clock=SystemClock(),
        )
        await application.start()

        result = await transport.invoke(
            tool.metadata.name,
            {"value": value},
            context=call_context(),
        )

        assert result.error is None
        assert result.value == {"value": value}
        assert tool.parse_calls == 1
        assert handler.calls == 1

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


@given(st.integers(min_value=1, max_value=64))
@settings(max_examples=25, deadline=None)
def test_generated_array_limits_accept_the_ceiling_and_reject_one_more(limit: int) -> None:
    async def exercise() -> None:
        handler = RecordingHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(max_array_items=limit),
            clock=SystemClock(),
        )
        await application.start()

        accepted = await transport.invoke(
            tool.metadata.name,
            {"value": list(range(limit))},
            context=call_context(),
        )
        rejected = await transport.invoke(
            tool.metadata.name,
            {"value": list(range(limit + 1))},
            context=call_context(),
        )

        assert accepted.error is None
        assert rejected.error is not None
        assert rejected.error.code is ErrorCode.INVALID_INPUT
        assert tool.parse_calls == 1
        assert handler.calls == 1

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_over_limit_result_is_replaced_without_returning_tool_output() -> None:
    async def exercise() -> None:
        handler = RecordingHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        observability = RuntimeObservability(server_name="bounds-mcp")
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(max_result_bytes=32),
            clock=SystemClock(),
            observability=observability,
        )
        await application.start()

        result = await transport.invoke(
            tool.metadata.name,
            {"value": "private-result-" * 4},
            context=call_context(),
        )

        assert result.error is not None
        assert result.error.code.value == "result_too_large"
        assert "private-result" not in repr(result)
        assert handler.calls == 1
        assert (
            'mcp_server_limit_count_total{limit="result",server="bounds-mcp",'
            f'tool="{tool.metadata.name}"}} 1' in observability.render_prometheus()
        )

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_application_rejects_a_catalog_above_the_tool_ceiling() -> None:
    with pytest.raises(ApplicationConfigurationError) as raised:
        Application(
            catalog=ToolCatalog(
                [
                    BoundedTool(name="bounds.first"),
                    BoundedTool(name="bounds.second"),
                ]
            ),
            authorizer=AllowAll(),
            transport=InProcessTransport(),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(max_tools=1),
            clock=SystemClock(),
        )

    assert raised.value.code == "tool_limit_exceeded"
    assert raised.value.path == "catalog"


def test_tenant_at_capacity_does_not_block_another_tenant() -> None:
    async def exercise() -> None:
        handler = TenantBlockingHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_global_concurrency=2,
                max_server_concurrency=2,
                max_tool_concurrency=2,
                max_tenant_concurrency=1,
            ),
            clock=SystemClock(),
        )
        await application.start()

        holding = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "hold"},
                context=call_context(tenant="tenant-blue"),
            )
        )
        await handler.entered.wait()
        same_tenant = await transport.invoke(
            tool.metadata.name,
            {"value": "probe"},
            context=call_context(tenant="tenant-blue"),
        )
        other_tenant = await transport.invoke(
            tool.metadata.name,
            {"value": "probe"},
            context=call_context(tenant="tenant-green"),
        )
        handler.release.set()
        held = await holding

        assert same_tenant.error is not None
        assert same_tenant.error.code.value == "overloaded"
        assert other_tenant.error is None
        assert held.error is None
        assert handler.calls == ["tenant-blue", "tenant-green"]

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_tool_at_capacity_does_not_block_another_tool() -> None:
    async def exercise() -> None:
        handler = TenantBlockingHandler()
        first = BoundedTool(name="bounds.first", handler=handler)
        second = BoundedTool(name="bounds.second", handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([first, second]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_global_concurrency=3,
                max_server_concurrency=3,
                max_tool_concurrency=1,
                max_tenant_concurrency=2,
            ),
            clock=SystemClock(),
        )
        await application.start()

        holding = asyncio.create_task(
            transport.invoke(
                first.metadata.name,
                {"value": "hold"},
                context=call_context(tenant="tenant-blue"),
            )
        )
        await handler.entered.wait()
        same_tool = await transport.invoke(
            first.metadata.name,
            {"value": "probe"},
            context=call_context(tenant="tenant-green"),
        )
        other_tool = await transport.invoke(
            second.metadata.name,
            {"value": "probe"},
            context=call_context(tenant="tenant-green"),
        )
        handler.release.set()
        await holding

        assert same_tool.error is not None
        assert same_tool.error.code.value == "overloaded"
        assert other_tool.error is None
        assert handler.calls == ["tenant-blue", "tenant-green"]

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("global_limit", "server_limit"),
    [(1, 2), (2, 1)],
    ids=["global", "server"],
)
def test_process_and_server_capacity_shed_without_queueing(
    global_limit: int,
    server_limit: int,
) -> None:
    async def exercise() -> None:
        handler = TenantBlockingHandler()
        first = BoundedTool(name="bounds.first", handler=handler)
        second = BoundedTool(name="bounds.second", handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([first, second]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_global_concurrency=global_limit,
                max_server_concurrency=server_limit,
                max_tool_concurrency=2,
                max_tenant_concurrency=2,
            ),
            clock=SystemClock(),
        )
        await application.start()

        holding = asyncio.create_task(
            transport.invoke(
                first.metadata.name,
                {"value": "hold"},
                context=call_context(tenant="tenant-blue"),
            )
        )
        await handler.entered.wait()
        shed = await transport.invoke(
            second.metadata.name,
            {"value": "probe"},
            context=call_context(tenant="tenant-green"),
        )
        handler.release.set()
        await holding

        assert shed.error is not None
        assert shed.error.code.value == "overloaded"
        assert handler.calls == ["tenant-blue"]

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_capacity_is_acquired_before_authorization_dependencies() -> None:
    async def exercise() -> None:
        authorizer = BlockingAuthorizer()
        tool = BoundedTool()
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=authorizer,
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_global_concurrency=1,
                max_server_concurrency=1,
                max_tool_concurrency=1,
                max_tenant_concurrency=1,
            ),
            clock=SystemClock(),
        )
        await application.start()

        holding = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "hold"},
                context=call_context(),
            )
        )
        await authorizer.entered.wait()
        shed = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "probe"},
                context=call_context(),
            )
        )
        for _ in range(100):
            await asyncio.sleep(0)

        try:
            assert shed.done()
            overloaded = await shed
            assert overloaded.error is not None
            assert overloaded.error.code is ErrorCode.OVERLOADED
            assert authorizer.calls == 1
        finally:
            authorizer.release.set()
            await holding
            if not shed.done():
                await shed

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_handler_receives_the_earliest_authenticated_runtime_and_tool_deadline() -> None:
    async def exercise() -> None:
        handler = DeadlineRecordingHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_call_seconds=10.0,
                max_tool_seconds=5.0,
            ),
            clock=ManualClock(100.0),
        )
        await application.start()

        result = await transport.invoke(
            tool.metadata.name,
            {"value": "bounded"},
            context=call_context(deadline=200.0),
        )

        assert result.error is None
        assert handler.deadlines == [105.0]

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_effective_deadline_cancels_the_handler_and_returns_timeout() -> None:
    async def exercise() -> None:
        clock = ManualClock(100.0)
        handler = DeadlineBlockingHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_call_seconds=10.0,
                max_tool_seconds=5.0,
            ),
            clock=clock,
        )
        await application.start()

        invocation = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "wait"},
                context=call_context(deadline=200.0),
            )
        )
        await handler.entered.wait()
        clock.advance(5.0)
        for _ in range(100):
            await asyncio.sleep(0)

        try:
            assert invocation.done()
            result = await invocation
            assert result.error is not None
            assert result.error.code.value == "timeout"
            assert handler.cancelled.is_set()
            assert handler.context_cancelled
        finally:
            handler.release.set()
            if not invocation.done():
                await invocation

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_caller_cancellation_stops_the_handler_and_returns_cancelled() -> None:
    async def exercise() -> None:
        cancellation = ManualCancellation()
        handler = DeadlineBlockingHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(),
            clock=ManualClock(100.0),
        )
        await application.start()

        invocation = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "wait"},
                context=call_context(cancellation=cancellation),
            )
        )
        await handler.entered.wait()
        cancellation.cancel()
        for _ in range(100):
            await asyncio.sleep(0)

        try:
            assert invocation.done()
            result = await invocation
            assert result.error is not None
            assert result.error.code.value == "cancelled"
            assert handler.cancelled.is_set()
            assert handler.context_cancelled
        finally:
            handler.release.set()
            if not invocation.done():
                await invocation

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_caller_cancellation_allows_a_cooperative_handler_to_finish() -> None:
    async def exercise() -> None:
        cancellation = ManualCancellation()
        handler = CooperativeCancellationHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(),
            clock=ManualClock(100.0),
        )
        await application.start()

        invocation = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "wait"},
                context=call_context(cancellation=cancellation),
            )
        )
        await handler.entered.wait()
        cancellation.cancel()
        for _ in range(100):
            await asyncio.sleep(0)

        result = await invocation
        assert result.error is not None
        assert result.error.code is ErrorCode.CANCELLED
        assert handler.observed.is_set()

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_stubborn_handler_caller_cancellation_uses_one_grace_period() -> None:
    async def exercise() -> None:
        clock = ManualClock(100.0)
        cancellation = ManualCancellation()
        handler = StubbornHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(cancellation_grace_seconds=1.0),
            clock=clock,
        )
        await application.start()

        invocation = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "wait"},
                context=call_context(cancellation=cancellation),
            )
        )
        await handler.entered.wait()
        cancellation.cancel()
        await handler.ignored_cancellation.wait()
        clock.advance(1.0)
        for _ in range(100):
            await asyncio.sleep(0)

        assert invocation.done()
        result = await invocation
        assert result.error is not None
        assert result.error.code is ErrorCode.CANCELLED
        assert application.detached_invocations == 1

        handler.release.set()
        for _ in range(100):
            await asyncio.sleep(0)
        assert application.detached_invocations == 0

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_stubborn_handler_detaches_after_grace_and_reports_until_exit() -> None:
    async def exercise() -> None:
        clock = ManualClock(100.0)
        handler = StubbornHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_call_seconds=5.0,
                max_tool_seconds=5.0,
                cancellation_grace_seconds=1.0,
            ),
            clock=clock,
        )
        await application.start()

        invocation = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "wait"},
                context=call_context(),
            )
        )
        await handler.entered.wait()
        clock.advance(5.0)
        await handler.ignored_cancellation.wait()
        clock.advance(1.0)
        for _ in range(100):
            await asyncio.sleep(0)

        result = await invocation
        assert result.error is not None
        assert result.error.code.value == "timeout"
        assert application.detached_invocations == 1

        handler.release.set()
        for _ in range(100):
            await asyncio.sleep(0)
        assert application.detached_invocations == 0

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_detached_handler_retains_capacity_until_it_exits() -> None:
    async def exercise() -> None:
        clock = ManualClock(100.0)
        handler = StubbornHandler()
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_global_concurrency=1,
                max_server_concurrency=1,
                max_tool_concurrency=1,
                max_tenant_concurrency=1,
                max_call_seconds=5.0,
                max_tool_seconds=5.0,
                cancellation_grace_seconds=1.0,
            ),
            clock=clock,
        )
        await application.start()

        invocation = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "hold"},
                context=call_context(),
            )
        )
        await handler.entered.wait()
        clock.advance(5.0)
        await handler.ignored_cancellation.wait()
        clock.advance(1.0)
        for _ in range(100):
            await asyncio.sleep(0)
        timed_out = await invocation

        overloaded = await transport.invoke(
            tool.metadata.name,
            {"value": "blocked"},
            context=call_context(),
        )

        assert timed_out.error is not None
        assert timed_out.error.code is ErrorCode.TIMEOUT
        assert overloaded.error is not None
        assert overloaded.error.code is ErrorCode.OVERLOADED
        assert application.detached_invocations == 1

        handler.release.set()
        for _ in range(100):
            await asyncio.sleep(0)
        recovered = await transport.invoke(
            tool.metadata.name,
            {"value": "released"},
            context=call_context(),
        )

        assert application.detached_invocations == 0
        assert recovered.error is None
        assert recovered.value == {"value": "released"}

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_read_retries_transient_failures_with_capped_jittered_backoff() -> None:
    async def exercise() -> None:
        clock = ManualClock(100.0)
        handler = TransientHandler(failures=2)
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        observability = RuntimeObservability(server_name="bounds-mcp")
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_attempts=3,
                retry_base_delay_seconds=0.1,
                retry_max_delay_seconds=0.3,
            ),
            clock=clock,
            observability=observability,
        )
        await application.start()

        invocation = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "retry"},
                context=call_context(),
            )
        )
        delays: list[float] = []
        for expected_attempt in (1, 2):
            assert await handler.failed.get() == expected_attempt
            for _ in range(20):
                await asyncio.sleep(0)
            if invocation.done():
                result = await invocation
                assert result.error is None
            delay = await clock.next_short_sleep()
            delays.append(delay)
            clock.advance(delay)

        result = await invocation
        assert result.error is None
        assert result.value == {"value": "retry"}
        assert handler.calls == 3
        assert all(0 < delay <= 0.3 for delay in delays)
        assert len(set(delays)) == 2
        assert (
            'mcp_tool_retry_count_total{server="bounds-mcp",tool="bounds.echo"} 2'
            in observability.render_prometheus()
        )

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_idempotent_mutation_retries_with_the_same_verified_key() -> None:
    async def exercise() -> None:
        clock = ManualClock(100.0)
        handler = TransientHandler(failures=1)
        tool = BoundedTool(handler=handler, effect=ToolEffect.WRITE)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(max_attempts=2),
            clock=clock,
        )
        await application.start()

        invocation = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "retry"},
                context=call_context(idempotency_key="stable-key"),
            )
        )
        assert await handler.failed.get() == 1
        for _ in range(20):
            await asyncio.sleep(0)
        if invocation.done():
            failed = await invocation
            assert failed.error is None
        delay = await clock.next_short_sleep()
        clock.advance(delay)

        result = await invocation
        assert result.error is None
        assert handler.calls == 2
        assert handler.idempotency_keys == ["stable-key", "stable-key"]

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_mutation_without_idempotency_key_is_never_retried() -> None:
    async def exercise() -> None:
        handler = TransientHandler(failures=1)
        tool = BoundedTool(handler=handler, effect=ToolEffect.WRITE)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(max_attempts=5),
            clock=SystemClock(),
        )
        await application.start()

        result = await transport.invoke(
            tool.metadata.name,
            {"value": "do-not-retry"},
            context=call_context(),
        )

        assert result.error is not None
        assert result.error.code is ErrorCode.UNAVAILABLE
        assert handler.calls == 1
        assert handler.idempotency_keys == [None]

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_non_transient_failure_is_never_retried() -> None:
    async def exercise() -> None:
        handler = FixedFailureHandler(ErrorCode.INVALID_INPUT)
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(max_attempts=5),
            clock=SystemClock(),
        )
        await application.start()

        result = await transport.invoke(
            tool.metadata.name,
            {"value": "invalid"},
            context=call_context(),
        )

        assert result.error is not None
        assert result.error.code is ErrorCode.INVALID_INPUT
        assert handler.calls == 1

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_transient_retries_stop_at_the_attempt_cap() -> None:
    async def exercise() -> None:
        clock = ManualClock(100.0)
        handler = TransientHandler(failures=10)
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(max_attempts=3),
            clock=clock,
        )
        await application.start()

        invocation = asyncio.create_task(
            transport.invoke(
                tool.metadata.name,
                {"value": "retry"},
                context=call_context(),
            )
        )
        delays: list[float] = []
        for expected_attempt in (1, 2):
            assert await handler.failed.get() == expected_attempt
            delay = await clock.next_short_sleep()
            delays.append(delay)
            clock.advance(delay)
        assert await handler.failed.get() == 3

        result = await invocation
        assert result.error is not None
        assert result.error.code is ErrorCode.UNAVAILABLE
        assert handler.calls == 3
        assert len(delays) == 2

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_retry_backoff_never_crosses_the_original_deadline() -> None:
    async def exercise() -> None:
        clock = ManualClock(100.0)
        handler = TransientHandler(failures=1)
        tool = BoundedTool(handler=handler)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_attempts=5,
                retry_base_delay_seconds=0.1,
            ),
            clock=clock,
        )
        await application.start()

        result = await transport.invoke(
            tool.metadata.name,
            {"value": "retry"},
            context=call_context(deadline=100.001),
        )

        assert result.error is not None
        assert result.error.code is ErrorCode.TIMEOUT
        assert handler.calls == 1
        assert clock.now() == 100.0

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_failure_releases_all_concurrency_capacity() -> None:
    async def exercise() -> None:
        handler = TransientHandler(failures=1)
        tool = BoundedTool(handler=handler, effect=ToolEffect.WRITE)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([tool]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            execution_limits=ExecutionLimits(
                max_global_concurrency=1,
                max_server_concurrency=1,
                max_tool_concurrency=1,
                max_tenant_concurrency=1,
            ),
            clock=SystemClock(),
        )
        await application.start()

        failed = await transport.invoke(
            tool.metadata.name,
            {"value": "first"},
            context=call_context(),
        )
        recovered = await transport.invoke(
            tool.metadata.name,
            {"value": "second"},
            context=call_context(),
        )

        assert failed.error is not None
        assert failed.error.code is ErrorCode.UNAVAILABLE
        assert recovered.error is None
        assert recovered.value == {"value": "second"}

        await application.drain()
        await application.stop()

    asyncio.run(exercise())
