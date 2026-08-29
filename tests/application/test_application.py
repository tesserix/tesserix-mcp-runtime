from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pytest

from tesserix_mcp_runtime import (
    Application,
    ApplicationConfigurationError,
    ApplicationDeadlineExceeded,
    ApplicationDiagnostic,
    ApplicationDiagnosticCode,
    ApplicationLimits,
    ApplicationRunResult,
    ApprovalRequirement,
    AuthenticatedIdentity,
    CallContext,
    ErrorCode,
    IdempotencyRequirement,
    InvocationResult,
    JsonValue,
    LifecycleFailure,
    LifecycleState,
    RuntimeFailure,
    ScrubbedError,
    ShutdownSignal,
    ToolCatalog,
    ToolDefinition,
    ToolEffect,
    ToolMetadata,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport


@dataclass(frozen=True, slots=True)
class EchoInput:
    text: str


@dataclass(frozen=True, slots=True)
class EchoOutput:
    text: str


class EchoHandler:
    async def __call__(
        self,
        input_model: EchoInput,
        *,
        context: CallContext,
    ) -> EchoOutput:
        return EchoOutput(text=f"{context.tenant}:{input_model.text}")


class EchoDefinition:
    metadata = ToolMetadata(
        name="example.echo",
        title="Echo",
        description="Return bounded synthetic text.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("example:read",),
    )
    input_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "maxLength": 128,
            }
        },
        "required": ["text"],
        "additionalProperties": False,
    }
    output_schema = input_schema
    handler = EchoHandler()

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> EchoInput:
        text = arguments.get("text")
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        return EchoInput(text=text)

    def serialize_output(self, output_model: EchoOutput) -> JsonValue:
        return {"text": output_model.text}


class RecordingAuthorizer:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def authorize(
        self,
        *,
        tool: ToolDefinition[Any, Any],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        self.calls.append(f"{context.tenant}:{tool.metadata.name}:{arguments['text']}")


class RecordingTelemetry:
    def __init__(self) -> None:
        self.events: list[ScrubbedError] = []

    def emit(self, event: ScrubbedError) -> None:
        self.events.append(event)


class FailingTelemetry:
    def emit(self, event: ScrubbedError) -> None:
        del event
        raise RuntimeError("telemetry-secret-must-not-escape")


class RejectingAuthorizer(RecordingAuthorizer):
    async def authorize(
        self,
        *,
        tool: ToolDefinition[Any, Any],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context
        raise RuntimeFailure(ErrorCode.FORBIDDEN)


class ManualClock:
    def __init__(self, now: float) -> None:
        self._now = now
        self._sleepers: list[tuple[float, asyncio.Event]] = []

    def now(self) -> float:
        return self._now

    async def sleep(self, seconds: float) -> None:
        deadline = self._now + seconds
        if deadline <= self._now:
            return
        completed = asyncio.Event()
        sleeper = (deadline, completed)
        self._sleepers.append(sleeper)
        try:
            await completed.wait()
        finally:
            self._sleepers.remove(sleeper)

    @property
    def pending_sleeps(self) -> int:
        return len(self._sleepers)

    def advance(self, seconds: float) -> None:
        self._now += seconds
        for deadline, completed in tuple(self._sleepers):
            if deadline <= self._now:
                completed.set()


class RecordingLifecycle:
    def __init__(self, name: str, events: list[str]) -> None:
        self.name = name
        self._events = events

    async def start(self) -> None:
        self._events.append(f"{self.name}.start")

    async def drain(self, *, deadline: float) -> None:
        self._events.append(f"{self.name}.drain:{deadline}")

    async def stop(self) -> None:
        self._events.append(f"{self.name}.stop")


class RecordingTransport:
    name = "transport"

    def __init__(self, events: list[str]) -> None:
        self._events = events

    async def start(self, endpoint: object) -> None:
        del endpoint
        self._events.append("transport.start")

    async def drain(self, *, deadline: float) -> None:
        self._events.append(f"transport.drain:{deadline}")

    async def stop(self) -> None:
        self._events.append("transport.stop")


class BlockingHandler:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def __call__(
        self,
        input_model: EchoInput,
        *,
        context: CallContext,
    ) -> EchoOutput:
        del context
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        return EchoOutput(text=input_model.text)


class HangingDrainLifecycle(RecordingLifecycle):
    def __init__(self, events: list[str]) -> None:
        super().__init__("hanging", events)
        self.drain_started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def drain(self, *, deadline: float) -> None:
        del deadline
        self.drain_started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise


class FailingStartLifecycle(RecordingLifecycle):
    async def start(self) -> None:
        await super().start()
        raise RuntimeError("startup details must stay internal")


class FailingDrainLifecycle(RecordingLifecycle):
    async def drain(self, *, deadline: float) -> None:
        await super().drain(deadline=deadline)
        raise RuntimeError("drain details must stay internal")


class FailingStopLifecycle(RecordingLifecycle):
    async def stop(self) -> None:
        await super().stop()
        raise RuntimeError("stop details must stay internal")


class FailingSignalSource:
    async def wait(self) -> ShutdownSignal:
        raise RuntimeError("signal details must stay internal")


class InvalidNameLifecycle(RecordingLifecycle):
    def __init__(self, events: list[str]) -> None:
        super().__init__("invalid component name", events)


class BlockingDefinition:
    metadata = EchoDefinition.metadata
    input_schema = EchoDefinition.input_schema
    output_schema = EchoDefinition.output_schema

    def __init__(self, handler: BlockingHandler) -> None:
        self.handler = handler

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> EchoInput:
        text = arguments.get("text")
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        return EchoInput(text=text)

    def serialize_output(self, output_model: EchoOutput) -> JsonValue:
        return {"text": output_model.text}


class CoordinatedTransport:
    name = "coordinated_transport"

    def __init__(self) -> None:
        self._delegate = InProcessTransport()
        self.started = asyncio.Event()
        self.drain_started = asyncio.Event()

    async def start(self, endpoint: Any) -> None:
        await self._delegate.start(endpoint)
        self.started.set()

    async def drain(self, *, deadline: float) -> None:
        await self._delegate.drain(deadline=deadline)
        self.drain_started.set()

    async def stop(self) -> None:
        await self._delegate.stop()

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> InvocationResult:
        return await self._delegate.invoke(name, arguments, context=context)


class ManualSignalSource:
    def __init__(self) -> None:
        self.waiting = asyncio.Event()
        self._received = asyncio.Event()
        self._signal: ShutdownSignal | None = None

    async def wait(self) -> ShutdownSignal:
        self.waiting.set()
        await self._received.wait()
        signal = self._signal
        if signal is None:
            raise RuntimeError("signal source invariant violated")
        return signal

    def trigger(self, signal: ShutdownSignal) -> None:
        self._signal = signal
        self._received.set()


def call_context(
    *,
    tenant: str = "tenant-example",
    request_id: str = "request-example",
) -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant=tenant,
            subject="subject-example",
            issuer="https://identity.example.invalid",
            scopes=("example:read",),
        ),
        request_id=request_id,
        run_id="run-example",
    )


def assert_state(application: Application, expected: LifecycleState) -> None:
    assert application.state is expected


def test_application_starts_serves_drains_and_stops() -> None:
    async def exercise() -> None:
        authorizer = RecordingAuthorizer()
        telemetry = RecordingTelemetry()
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=authorizer,
            transport=transport,
            telemetry=telemetry,
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
        )

        assert_state(application, LifecycleState.STARTUP)
        await application.start()
        assert_state(application, LifecycleState.READY)
        assert await transport.list_tools() == ("example.echo",)

        result = await transport.invoke(
            "example.echo",
            {"text": "hello"},
            context=call_context(),
        )

        assert result == InvocationResult.success({"text": "tenant-example:hello"})
        assert authorizer.calls == ["tenant-example:example.echo:hello"]
        assert telemetry.events == []

        await application.drain()
        assert_state(application, LifecycleState.DRAINING)
        assert await transport.list_tools() == ()
        await application.stop()
        assert_state(application, LifecycleState.STOPPED)

    asyncio.run(exercise())


def test_application_orders_hooks_around_transport() -> None:
    async def exercise() -> None:
        events: list[str] = []
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=RecordingTransport(events),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
            lifecycle=(
                RecordingLifecycle("dependency", events),
                RecordingLifecycle("service", events),
            ),
        )

        await application.start()
        await application.drain()
        await application.stop()

        assert events == [
            "dependency.start",
            "service.start",
            "transport.start",
            "transport.drain:105.0",
            "service.drain:105.0",
            "dependency.drain:105.0",
            "transport.stop",
            "service.stop",
            "dependency.stop",
        ]

    asyncio.run(exercise())


def test_drain_rejects_new_calls_and_waits_for_in_flight_work() -> None:
    async def exercise() -> None:
        handler = BlockingHandler()
        transport = CoordinatedTransport()
        application = Application(
            catalog=ToolCatalog([BlockingDefinition(handler)]),
            authorizer=RecordingAuthorizer(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
        )
        await application.start()
        first_call = asyncio.create_task(
            transport.invoke(
                "example.echo",
                {"text": "first"},
                context=call_context(),
            )
        )
        await handler.started.wait()

        drain = asyncio.create_task(application.drain())
        await transport.drain_started.wait()
        rejected = await transport.invoke(
            "example.echo",
            {"text": "second"},
            context=call_context(),
        )

        assert rejected.error is not None
        assert rejected.error.code.value == "unavailable"
        assert not drain.done()

        handler.release.set()
        assert await first_call == InvocationResult.success({"text": "first"})
        await drain

    asyncio.run(exercise())


def test_drain_deadline_cancels_in_flight_calls_before_returning() -> None:
    async def exercise() -> None:
        handler = BlockingHandler()
        clock = ManualClock(now=100.0)
        telemetry = RecordingTelemetry()
        transport = CoordinatedTransport()
        application = Application(
            catalog=ToolCatalog([BlockingDefinition(handler)]),
            authorizer=RecordingAuthorizer(),
            transport=transport,
            telemetry=telemetry,
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=clock,
        )
        await application.start()
        first_call = asyncio.create_task(
            transport.invoke(
                "example.echo",
                {"text": "first"},
                context=call_context(),
            )
        )
        await handler.started.wait()

        drain = asyncio.create_task(application.drain())
        await transport.drain_started.wait()
        assert clock.pending_sleeps >= 1
        clock.advance(5.0)

        with pytest.raises(ApplicationDeadlineExceeded):
            await drain
        assert handler.cancelled.is_set()
        cancelled = await first_call
        assert cancelled.error is not None
        assert cancelled.error.code.value == "cancelled"
        assert [event.code.value for event in telemetry.events] == ["cancelled"]

        await application.stop()

    asyncio.run(exercise())


def test_drain_deadline_cancels_a_hanging_hook() -> None:
    async def exercise() -> None:
        events: list[str] = []
        hook = HangingDrainLifecycle(events)
        clock = ManualClock(now=100.0)
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=InProcessTransport(),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=clock,
            lifecycle=(hook,),
        )
        await application.start()

        drain = asyncio.create_task(application.drain())
        await hook.drain_started.wait()
        assert clock.pending_sleeps == 1
        clock.advance(5.0)
        await hook.cancelled.wait()

        with pytest.raises(ApplicationDeadlineExceeded) as captured:
            await drain
        assert captured.value.phase is LifecycleState.DRAINING
        assert_state(application, LifecycleState.DRAINING)

        await application.stop()
        assert_state(application, LifecycleState.STOPPED)

    asyncio.run(exercise())


def test_invalid_component_configuration_fails_before_transport_start() -> None:
    events: list[str] = []

    with pytest.raises(ApplicationConfigurationError) as captured:
        Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=RecordingTransport(events),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
            lifecycle=(
                RecordingLifecycle("duplicate", events),
                RecordingLifecycle("duplicate", events),
            ),
        )

    assert captured.value.code == "duplicate_component_name"
    assert captured.value.path == "lifecycle[1].name"
    assert events == []


@pytest.mark.parametrize(
    "drain_timeout",
    [0.0, -1.0, float("inf"), float("-inf"), float("nan")],
)
def test_application_limits_reject_non_positive_or_non_finite_timeouts(
    drain_timeout: float,
) -> None:
    with pytest.raises(ValueError, match="drain_timeout must be a positive finite number"):
        ApplicationLimits(drain_timeout=drain_timeout)


def test_application_diagnostics_and_run_results_reject_invalid_combinations() -> None:
    with pytest.raises(ValueError, match="exception_type must be a bounded type name"):
        ApplicationDiagnostic(
            code=ApplicationDiagnosticCode.STARTUP_FAILED,
            phase=LifecycleState.STARTUP,
            exception_type="unsafe-type-name",
        )
    with pytest.raises(ValueError, match="exit_code must be zero or one"):
        ApplicationRunResult(exit_code=2, diagnostic=None)
    with pytest.raises(ValueError, match="exit_code and diagnostic must agree"):
        ApplicationRunResult(exit_code=1, diagnostic=None)


def test_invalid_component_name_is_rejected_without_echoing_its_value() -> None:
    with pytest.raises(ApplicationConfigurationError) as captured:
        Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=InProcessTransport(),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
            lifecycle=(InvalidNameLifecycle([]),),
        )

    assert captured.value.code == "invalid_component_name"
    assert captured.value.path == "lifecycle[0].name"
    assert "invalid component name" not in str(captured.value)


def test_partial_startup_failure_unwinds_hooks_without_binding_transport() -> None:
    async def exercise() -> None:
        events: list[str] = []
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=RecordingTransport(events),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
            lifecycle=(
                RecordingLifecycle("dependency", events),
                FailingStartLifecycle("failing", events),
            ),
        )

        with pytest.raises(LifecycleFailure) as captured:
            await application.start()

        assert captured.value.component == "failing"
        assert captured.value.failure_count == 1
        assert_state(application, LifecycleState.STOPPED)
        assert events == [
            "dependency.start",
            "failing.start",
            "failing.stop",
            "dependency.stop",
        ]

    asyncio.run(exercise())


def test_run_returns_scrubbed_startup_failure() -> None:
    async def exercise() -> None:
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=InProcessTransport(),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
            lifecycle=(FailingStartLifecycle("failing", []),),
        )

        result = await application.run(ManualSignalSource())

        assert result.exit_code == 1
        assert result.diagnostic is not None
        assert result.diagnostic.to_dict() == {
            "code": "startup_failed",
            "phase": "startup",
            "exception_type": "LifecycleFailure",
        }
        assert_state(application, LifecycleState.STOPPED)

    asyncio.run(exercise())


def test_two_application_instances_do_not_share_lifecycle_or_calls() -> None:
    async def exercise() -> None:
        first_transport = InProcessTransport()
        second_transport = InProcessTransport()
        first = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=first_transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
        )
        second = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=second_transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=200.0),
        )
        await first.start()
        await second.start()

        await first.drain()
        first_result = await first.invoke(
            "example.echo",
            {"text": "isolated"},
            context=call_context(tenant="tenant-first", request_id="request-first"),
        )
        second_result = await second_transport.invoke(
            "example.echo",
            {"text": "isolated"},
            context=call_context(tenant="tenant-second", request_id="request-second"),
        )

        assert first_result.error is not None
        assert first_result.error.code.value == "unavailable"
        assert second_result == InvocationResult.success({"text": "tenant-second:isolated"})
        assert_state(first, LifecycleState.DRAINING)
        assert_state(second, LifecycleState.READY)

        await first.stop()
        await second.drain()
        await second.stop()

    asyncio.run(exercise())


def test_unknown_and_malformed_calls_return_stable_invalid_input() -> None:
    async def exercise() -> None:
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=transport,
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
        )
        await application.start()

        unknown = await transport.invoke(
            "example.unknown",
            {},
            context=call_context(),
        )
        malformed = await transport.invoke(
            "example.echo",
            {"text": 42},
            context=call_context(),
        )

        assert unknown.error is not None
        assert unknown.error.code is ErrorCode.INVALID_INPUT
        assert malformed.error is not None
        assert malformed.error.code is ErrorCode.INVALID_INPUT

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_telemetry_failure_does_not_replace_a_stable_invocation_error() -> None:
    async def exercise() -> None:
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RejectingAuthorizer(),
            transport=transport,
            telemetry=FailingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
        )
        await application.start()

        result = await transport.invoke(
            "example.echo",
            {"text": "hello"},
            context=call_context(),
        )

        assert result.error is not None
        assert result.error.code is ErrorCode.FORBIDDEN
        assert application.telemetry_failures == 1

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_run_handles_a_shutdown_signal_and_returns_zero() -> None:
    async def exercise() -> None:
        signals = ManualSignalSource()
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=InProcessTransport(),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
        )

        running = asyncio.create_task(application.run(signals))
        await signals.waiting.wait()
        assert_state(application, LifecycleState.READY)
        signals.trigger(ShutdownSignal.SIGTERM)

        result = await running

        assert result.exit_code == 0
        assert result.diagnostic is None
        assert_state(application, LifecycleState.STOPPED)

    asyncio.run(exercise())


def test_run_returns_scrubbed_nonzero_result_after_drain_timeout() -> None:
    async def exercise() -> None:
        events: list[str] = []
        hook = HangingDrainLifecycle(events)
        clock = ManualClock(now=100.0)
        signals = ManualSignalSource()
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=InProcessTransport(),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=clock,
            lifecycle=(hook,),
        )

        running = asyncio.create_task(application.run(signals))
        await signals.waiting.wait()
        signals.trigger(ShutdownSignal.SIGINT)
        await hook.drain_started.wait()
        assert clock.pending_sleeps == 1
        clock.advance(5.0)
        await hook.cancelled.wait()

        result = await running

        assert result.exit_code == 1
        assert result.diagnostic is not None
        assert result.diagnostic.to_dict() == {
            "code": "drain_failed",
            "phase": "draining",
            "exception_type": "ApplicationDeadlineExceeded",
        }
        assert_state(application, LifecycleState.STOPPED)
        assert events[-1] == "hanging.stop"

    asyncio.run(exercise())


def test_run_preserves_signal_failure_and_still_drains_and_stops() -> None:
    async def exercise() -> None:
        events: list[str] = []
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=InProcessTransport(),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
            lifecycle=(FailingDrainLifecycle("failing_drain", events),),
        )

        result = await application.run(FailingSignalSource())

        assert result.exit_code == 1
        assert result.diagnostic is not None
        assert result.diagnostic.to_dict() == {
            "code": "signal_failed",
            "phase": "ready",
            "exception_type": "RuntimeError",
        }
        assert events[-1] == "failing_drain.stop"
        assert_state(application, LifecycleState.STOPPED)

    asyncio.run(exercise())


def test_run_reports_stop_failure_after_a_clean_signal_and_drain() -> None:
    async def exercise() -> None:
        events: list[str] = []
        signals = ManualSignalSource()
        application = Application(
            catalog=ToolCatalog([EchoDefinition()]),
            authorizer=RecordingAuthorizer(),
            transport=InProcessTransport(),
            telemetry=RecordingTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=ManualClock(now=100.0),
            lifecycle=(FailingStopLifecycle("failing_stop", events),),
        )
        running = asyncio.create_task(application.run(signals))
        await signals.waiting.wait()
        signals.trigger(ShutdownSignal.SIGTERM)

        result = await running

        assert result.exit_code == 1
        assert result.diagnostic is not None
        assert result.diagnostic.to_dict() == {
            "code": "stop_failed",
            "phase": "stopped",
            "exception_type": "LifecycleFailure",
        }
        assert events[-1] == "failing_stop.stop"
        assert_state(application, LifecycleState.STOPPED)

    asyncio.run(exercise())
