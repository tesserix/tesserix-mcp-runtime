from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Protocol

import pytest
from tesserix_mcp_testkit import (
    CONFORMANCE_CASES,
    CONFORMANCE_TOOL_NAME,
    ConformanceCapability,
    ConformanceCase,
    ConformanceFailure,
    ConformanceObservation,
    ConformanceTarget,
    FakeIdentityFactory,
    assert_conformance_case,
)
from tesserix_mcp_testkit.pytest_plugin import (
    assert_mcp_conformance as _assert_mcp_conformance_fixture,
)
from tesserix_mcp_testkit.pytest_plugin import conformance_case as _conformance_case_fixture

import tesserix_mcp_runtime.application as application_module
from tesserix_mcp_runtime import (
    Application,
    ApplicationLimits,
    ApprovalRequirement,
    Authorizer,
    CallContext,
    ErrorCode,
    ExecutionLimits,
    IdempotencyRequirement,
    InvocationResult,
    JsonValue,
    LifecycleState,
    MappedError,
    RuntimeFailure,
    ScrubbedError,
    SystemClock,
    ToolCatalog,
    ToolDefinition,
    ToolEffect,
    ToolMetadata,
    ToolPolicy,
    ToolPolicyAuditEvent,
    map_exception,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport

assert_mcp_conformance = _assert_mcp_conformance_fixture
conformance_case = _conformance_case_fixture


async def _checkpoint() -> None:
    ready = asyncio.Event()
    ready.set()
    await ready.wait()


class _Action(Protocol):
    async def __call__(
        self,
        value: str,
        *,
        context: CallContext,
    ) -> dict[str, JsonValue]: ...


class _EchoAction:
    async def __call__(
        self,
        value: str,
        *,
        context: CallContext,
    ) -> dict[str, JsonValue]:
        del context
        await _checkpoint()
        return {"echo": value}


class _FailureAction:
    def __init__(self, code: ErrorCode) -> None:
        self._code = code

    async def __call__(
        self,
        value: str,
        *,
        context: CallContext,
    ) -> dict[str, JsonValue]:
        del value, context
        await _checkpoint()
        if self._code is ErrorCode.TIMEOUT:
            raise TimeoutError
        if self._code is ErrorCode.CANCELLED:
            raise asyncio.CancelledError
        if self._code is ErrorCode.INTERNAL_FAILURE:
            raise RuntimeError("synthetic conformance failure")
        raise RuntimeFailure(self._code)


class _TelemetryFailureAction:
    async def __call__(
        self,
        value: str,
        *,
        context: CallContext,
    ) -> dict[str, JsonValue]:
        del context
        await _checkpoint()
        raise RuntimeError(f"{value}:SyntheticCredentialCanary2Zp7")


class _BlockingAction:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(
        self,
        value: str,
        *,
        context: CallContext,
    ) -> dict[str, JsonValue]:
        self.entered.set()
        await self.release.wait()
        return {"echo": value, "cancelled": context.cancelled}


class _ConformanceTool:
    metadata = ToolMetadata(
        name=CONFORMANCE_TOOL_NAME,
        title="Conformance echo",
        description="Exercise one bounded synthetic runtime behavior.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("conformance:invoke",),
    )
    input_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {"value": {"type": "string", "maxLength": 65_536}},
        "required": ["value"],
        "additionalProperties": False,
    }
    output_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {
            "echo": {"type": "string", "maxLength": 65_536},
            "cancelled": {"type": "boolean"},
        },
        "required": ["echo"],
        "additionalProperties": False,
    }

    def __init__(self, action: _Action) -> None:
        self._action = action
        self.calls = 0

    async def handler(
        self,
        input_model: str,
        *,
        context: CallContext,
    ) -> dict[str, JsonValue]:
        self.calls += 1
        return await self._action(input_model, context=context)

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> str:
        value = arguments.get("value")
        if not isinstance(value, str):
            raise ValueError("value must be text")
        return value

    def serialize_output(self, output_model: dict[str, JsonValue]) -> JsonValue:
        return output_model


class _AllowAll:
    async def authorize(
        self,
        *,
        tool: ToolDefinition[object, object],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context
        await _checkpoint()


class _DenyWith:
    def __init__(self, code: ErrorCode) -> None:
        self._code = code

    async def authorize(
        self,
        *,
        tool: ToolDefinition[object, object],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context
        await _checkpoint()
        raise RuntimeFailure(self._code)


class _TenantAuthorizer:
    def __init__(self, allowed_tenant: str) -> None:
        self._allowed_tenant = allowed_tenant

    async def authorize(
        self,
        *,
        tool: ToolDefinition[object, object],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments
        await _checkpoint()
        if context.tenant != self._allowed_tenant:
            raise RuntimeFailure(ErrorCode.FORBIDDEN)


class _Telemetry:
    def __init__(self) -> None:
        self.events: list[ScrubbedError] = []

    def emit(self, event: ScrubbedError) -> None:
        self.events.append(event)

    def render(self) -> str:
        return json.dumps([event.to_dict() for event in self.events], sort_keys=True)


class _PolicyAudit:
    def __init__(self) -> None:
        self.events: list[ToolPolicyAuditEvent] = []

    def append(self, event: ToolPolicyAuditEvent) -> None:
        self.events.append(event)


class _ManualCancellation:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()

    def cancel(self) -> None:
        self._event.set()


@dataclass(frozen=True, slots=True)
class _Scenario:
    application: Application
    transport: InProcessTransport
    tool: _ConformanceTool
    telemetry: _Telemetry


def _scenario(
    action: _Action,
    *,
    authorizer: Authorizer | None = None,
    authorizer_factory: Callable[[ToolCatalog], Authorizer] | None = None,
    execution_limits: ExecutionLimits | None = None,
) -> _Scenario:
    tool = _ConformanceTool(action)
    catalog = ToolCatalog([tool])
    if authorizer is not None and authorizer_factory is not None:
        raise ValueError("choose one authorizer source")
    resolved_authorizer = (
        authorizer_factory(catalog)
        if authorizer_factory is not None
        else (_AllowAll() if authorizer is None else authorizer)
    )
    transport = InProcessTransport()
    telemetry = _Telemetry()
    application = Application(
        catalog=catalog,
        authorizer=resolved_authorizer,
        transport=transport,
        telemetry=telemetry,
        limits=ApplicationLimits(drain_timeout=1.0),
        execution_limits=(
            ExecutionLimits(max_attempts=1) if execution_limits is None else execution_limits
        ),
        clock=SystemClock(),
    )
    return _Scenario(application, transport, tool, telemetry)


def _context(
    *,
    tenant: str = "conformance-tenant",
    cancellation: _ManualCancellation | None = None,
) -> CallContext:
    context = FakeIdentityFactory(default_scopes=("conformance:invoke",)).context(tenant=tenant)
    return context if cancellation is None else replace(context, cancellation=cancellation)


async def _close(scenario: _Scenario) -> None:
    if scenario.application.state is LifecycleState.READY:
        await scenario.application.drain()
    if scenario.application.state is not LifecycleState.STOPPED:
        await scenario.application.stop()


async def _invoke(
    scenario: _Scenario,
    arguments: Mapping[str, JsonValue],
    *,
    context: CallContext | None = None,
) -> InvocationResult:
    await scenario.application.start()
    try:
        return await scenario.transport.invoke(
            CONFORMANCE_TOOL_NAME,
            arguments,
            context=_context() if context is None else context,
        )
    finally:
        await _close(scenario)


def _error_code(result: InvocationResult) -> ErrorCode | None:
    return result.error.code if result.error is not None else None


class CoreRuntimeTarget:
    capabilities = frozenset(ConformanceCapability)

    async def observe(self, case: ConformanceCase) -> ConformanceObservation:
        if case.id == "discovery.tools":
            scenario = _scenario(_EchoAction())
            await scenario.application.start()
            try:
                return ConformanceObservation(tool_names=await scenario.transport.list_tools())
            finally:
                await _close(scenario)
        if case.id == "invocation.success":
            result = await _invoke(_scenario(_EchoAction()), {"value": "ok"})
            return ConformanceObservation(value=result.value, error_code=_error_code(result))
        if case.id.startswith("errors."):
            return await self._error(case)
        if case.id.startswith("lifecycle."):
            return await self._lifecycle(case)
        if case.id == "authorization.default_deny":
            return await self._default_deny()
        if case.id == "tenancy.cross_tenant":
            return await self._cross_tenant()
        if case.id == "limits.input":
            return await self._input_limit()
        if case.id == "limits.result":
            return await self._result_limit()
        if case.id == "limits.concurrency":
            return await self._concurrency_limit()
        if case.id == "telemetry.payload_free":
            return await self._payload_free_telemetry()
        if case.id == "cancellation.cancelled":
            return await self._cancellation()
        raise AssertionError(f"unhandled conformance case: {case.id}")

    async def _error(self, case: ConformanceCase) -> ConformanceObservation:
        code = case.expected_error
        if code is None:
            raise AssertionError("error case is missing its expected error")
        if code is ErrorCode.INVALID_INPUT:
            result = await _invoke(_scenario(_EchoAction()), {})
        elif code in {
            ErrorCode.UNAUTHENTICATED,
            ErrorCode.FORBIDDEN,
            ErrorCode.APPROVAL_REQUIRED,
            ErrorCode.CONFLICT,
        }:
            result = await _invoke(
                _scenario(_EchoAction(), authorizer=_DenyWith(code)),
                {"value": "ok"},
            )
        else:
            result = await _invoke(_scenario(_FailureAction(code)), {"value": "ok"})
        return ConformanceObservation(error_code=_error_code(result))

    async def _lifecycle(self, case: ConformanceCase) -> ConformanceObservation:
        expected = case.expected_state
        if expected is None:
            raise AssertionError("lifecycle case is missing its expected state")
        scenario = _scenario(_EchoAction())
        try:
            if expected is not LifecycleState.STARTUP:
                await scenario.application.start()
            if expected in {LifecycleState.DRAINING, LifecycleState.STOPPED}:
                await scenario.application.drain()
            if expected is LifecycleState.STOPPED:
                await scenario.application.stop()
            return ConformanceObservation(state=scenario.application.state)
        finally:
            await _close(scenario)

    async def _default_deny(self) -> ConformanceObservation:
        def policy(catalog: ToolCatalog) -> Authorizer:
            return ToolPolicy(
                catalog=catalog,
                server_scopes=("conformance:invoke",),
                rules=(),
                audit_sink=_PolicyAudit(),
            )

        result = await _invoke(
            _scenario(_EchoAction(), authorizer_factory=policy),
            {"value": "ok"},
        )
        return ConformanceObservation(error_code=_error_code(result))

    async def _cross_tenant(self) -> ConformanceObservation:
        scenario = _scenario(
            _EchoAction(),
            authorizer=_TenantAuthorizer("allowed-tenant"),
        )
        result = await _invoke(
            scenario,
            {"value": "ok"},
            context=_context(tenant="other-tenant"),
        )
        if scenario.tool.calls != 0:
            raise AssertionError("cross-tenant call reached the tool body")
        return ConformanceObservation(error_code=_error_code(result))

    async def _input_limit(self) -> ConformanceObservation:
        result = await _invoke(
            _scenario(
                _EchoAction(),
                execution_limits=ExecutionLimits(max_input_bytes=32, max_attempts=1),
            ),
            {"value": "x" * 64},
        )
        return ConformanceObservation(error_code=_error_code(result))

    async def _result_limit(self) -> ConformanceObservation:
        result = await _invoke(
            _scenario(
                _EchoAction(),
                execution_limits=ExecutionLimits(max_result_bytes=32, max_attempts=1),
            ),
            {"value": "x" * 64},
        )
        return ConformanceObservation(error_code=_error_code(result))

    async def _concurrency_limit(self) -> ConformanceObservation:
        action = _BlockingAction()
        scenario = _scenario(
            action,
            execution_limits=ExecutionLimits(
                max_global_concurrency=1,
                max_server_concurrency=1,
                max_tool_concurrency=1,
                max_tenant_concurrency=1,
                max_attempts=1,
            ),
        )
        await scenario.application.start()
        first = asyncio.create_task(
            scenario.transport.invoke(
                CONFORMANCE_TOOL_NAME,
                {"value": "first"},
                context=_context(),
            )
        )
        try:
            await action.entered.wait()
            rejected = await scenario.transport.invoke(
                CONFORMANCE_TOOL_NAME,
                {"value": "second"},
                context=_context(),
            )
            return ConformanceObservation(error_code=_error_code(rejected))
        finally:
            action.release.set()
            await first
            await _close(scenario)

    async def _payload_free_telemetry(self) -> ConformanceObservation:
        scenario = _scenario(_TelemetryFailureAction())
        await _invoke(
            scenario,
            {"value": "SyntheticPayloadCanary8Kq3"},
        )
        return ConformanceObservation(telemetry_text=scenario.telemetry.render())

    async def _cancellation(self) -> ConformanceObservation:
        action = _BlockingAction()
        cancellation = _ManualCancellation()
        scenario = _scenario(action)
        await scenario.application.start()
        invocation = asyncio.create_task(
            scenario.transport.invoke(
                CONFORMANCE_TOOL_NAME,
                {"value": "wait"},
                context=_context(cancellation=cancellation),
            )
        )
        try:
            await action.entered.wait()
            cancellation.cancel()
            result = await invocation
            return ConformanceObservation(error_code=_error_code(result))
        finally:
            action.release.set()
            if not invocation.done():
                await invocation
            await _close(scenario)


@pytest.fixture
def conformance_target() -> ConformanceTarget:
    return CoreRuntimeTarget()


def test_core_runtime_conforms(
    conformance_target: ConformanceTarget,
    conformance_case: ConformanceCase,
    assert_mcp_conformance: Callable[[ConformanceTarget, ConformanceCase], None],
) -> None:
    assert_mcp_conformance(conformance_target, conformance_case)


def test_contract_kills_timeout_error_mapping_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mutated_mapping(error: BaseException, *, request_id: str) -> MappedError:
        if isinstance(error, TimeoutError):
            return map_exception(RuntimeError("mutated timeout"), request_id=request_id)
        return map_exception(error, request_id=request_id)

    monkeypatch.setattr(application_module, "map_exception", mutated_mapping)
    case = next(case for case in CONFORMANCE_CASES if case.id == "errors.timeout")

    with pytest.raises(ConformanceFailure) as captured:
        asyncio.run(assert_conformance_case(CoreRuntimeTarget(), case))

    assert captured.value.case_id == "errors.timeout"
    assert captured.value.code == "error_code_mismatch"


def test_contract_kills_policy_default_deny_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def allow_without_rule(
        self: ToolPolicy,
        *,
        tool: ToolDefinition[object, object],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del self, tool, arguments, context
        await _checkpoint()

    monkeypatch.setattr(ToolPolicy, "authorize", allow_without_rule)
    case = next(case for case in CONFORMANCE_CASES if case.id == "authorization.default_deny")

    with pytest.raises(ConformanceFailure) as captured:
        asyncio.run(assert_conformance_case(CoreRuntimeTarget(), case))

    assert captured.value.case_id == "authorization.default_deny"
    assert captured.value.code == "error_code_mismatch"
