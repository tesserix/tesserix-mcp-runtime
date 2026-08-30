"""Explicit composition root for one reusable MCP server application."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import math
import re
from collections.abc import Coroutine, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from tesserix_mcp_runtime.contracts import (
    Authorizer,
    CallContext,
    Clock,
    ErrorCode,
    ErrorResponse,
    IdempotencyRequirement,
    InvocationResult,
    JsonValue,
    Lifecycle,
    LifecycleState,
    Telemetry,
    ToolEffect,
)
from tesserix_mcp_runtime.errors import RuntimeFailure, ScrubbedError, map_exception
from tesserix_mcp_runtime.execution import (
    ExecutionController,
    ExecutionLimitExceeded,
    ExecutionLimits,
    validate_json_value,
)
from tesserix_mcp_runtime.lifecycle import LifecycleController
from tesserix_mcp_runtime.redaction import (
    DEFAULT_REDACTION_POLICY,
    RedactionError,
    RedactionPolicy,
)
from tesserix_mcp_runtime.tool import ToolCatalog
from tesserix_mcp_runtime.tool_manifest import ToolManifest

_COMPONENT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")
_EXCEPTION_TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}\Z")
_DEFAULT_EXECUTION_LIMITS = ExecutionLimits()


class _Named(Protocol):
    @property
    def name(self) -> str: ...


@runtime_checkable
class _ToolVisibilityPolicy(Protocol):
    def is_exported(self, tool_name: str) -> bool: ...


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


async def _cancel_task[ResultT](task: asyncio.Task[ResultT]) -> None:
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


@dataclass(frozen=True, slots=True, kw_only=True)
class ApplicationLimits:
    """Bound application shutdown work with one monotonic drain timeout."""

    drain_timeout: float

    def __post_init__(self) -> None:
        if (
            _is_runtime_instance(self.drain_timeout, bool)
            or not (
                _is_runtime_instance(self.drain_timeout, int)
                or _is_runtime_instance(self.drain_timeout, float)
            )
            or not math.isfinite(self.drain_timeout)
            or not 0 < self.drain_timeout <= 300
        ):
            raise ValueError("drain_timeout must be a positive finite number at most 300 seconds")


class ApplicationDeadlineExceeded(TimeoutError):
    """Report a monotonic lifecycle deadline without exposing hook details."""

    def __init__(self, *, phase: LifecycleState) -> None:
        self.phase = phase
        super().__init__(f"application {phase.value} deadline exceeded")


class ApplicationConfigurationError(ValueError):
    """Identify one invalid configuration field without echoing its value."""

    def __init__(self, *, code: str, path: str) -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code} at {path}")


class ShutdownSignal(StrEnum):
    SIGINT = "sigint"
    SIGTERM = "sigterm"


@runtime_checkable
class ShutdownSignalSource(Protocol):
    async def wait(self) -> ShutdownSignal: ...


class ApplicationDiagnosticCode(StrEnum):
    STARTUP_FAILED = "startup_failed"
    SIGNAL_FAILED = "signal_failed"
    DRAIN_FAILED = "drain_failed"
    STOP_FAILED = "stop_failed"


@dataclass(frozen=True, slots=True, kw_only=True)
class ApplicationDiagnostic:
    code: ApplicationDiagnosticCode
    phase: LifecycleState
    exception_type: str

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.code, ApplicationDiagnosticCode):
            raise ValueError("code must be an application diagnostic code")
        if not _is_runtime_instance(self.phase, LifecycleState):
            raise ValueError("phase must be a lifecycle state")
        if _EXCEPTION_TYPE.fullmatch(self.exception_type) is None:
            raise ValueError("exception_type must be a bounded type name")

    @classmethod
    def from_exception(
        cls,
        code: ApplicationDiagnosticCode,
        *,
        phase: LifecycleState,
        error: Exception,
    ) -> ApplicationDiagnostic:
        exception_type = type(error).__name__
        if _EXCEPTION_TYPE.fullmatch(exception_type) is None:
            exception_type = "Exception"
        return cls(
            code=code,
            phase=phase,
            exception_type=exception_type,
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "code": self.code.value,
            "phase": self.phase.value,
            "exception_type": self.exception_type,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class ApplicationRunResult:
    exit_code: int
    diagnostic: ApplicationDiagnostic | None

    def __post_init__(self) -> None:
        if self.exit_code not in {0, 1}:
            raise ValueError("exit_code must be zero or one")
        if (self.exit_code == 0) is (self.diagnostic is not None):
            raise ValueError("exit_code and diagnostic must agree")

    @classmethod
    def success(cls) -> ApplicationRunResult:
        return cls(exit_code=0, diagnostic=None)

    @classmethod
    def failure(cls, diagnostic: ApplicationDiagnostic) -> ApplicationRunResult:
        return cls(exit_code=1, diagnostic=diagnostic)


class ApplicationEndpoint(Protocol):
    """Expose adapter-neutral capabilities to one bound transport."""

    def list_tools(self) -> tuple[str, ...]: ...

    def list_tool_manifests(self) -> tuple[ToolManifest, ...]: ...

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> InvocationResult: ...


@runtime_checkable
class ApplicationTransport(Protocol):
    """Bind one transport without importing adapter code into core."""

    @property
    def name(self) -> str: ...

    async def start(self, endpoint: ApplicationEndpoint) -> None: ...

    async def drain(self, *, deadline: float) -> None: ...

    async def stop(self) -> None: ...


class _TransportLifecycle:
    def __init__(self, transport: ApplicationTransport, endpoint: ApplicationEndpoint) -> None:
        self._transport = transport
        self._endpoint = endpoint

    @property
    def name(self) -> str:
        return self._transport.name

    async def start(self) -> None:
        await self._transport.start(self._endpoint)

    async def drain(self, *, deadline: float) -> None:
        await self._transport.drain(deadline=deadline)

    async def stop(self) -> None:
        await self._transport.stop()


class _InvocationLifecycle:
    name = "in_flight_invocations"

    def __init__(self) -> None:
        self._tasks: set[asyncio.Task[Any]] = set()
        self._empty = asyncio.Event()
        self._empty.set()

    async def start(self) -> None:
        return None

    def begin(self) -> asyncio.Task[Any]:
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("invocation requires an asyncio task")
        self._tasks.add(task)
        self._empty.clear()
        return task

    def finish(self, task: asyncio.Task[Any]) -> None:
        self._tasks.discard(task)
        if not self._tasks:
            self._empty.set()

    async def drain(self, *, deadline: float) -> None:
        del deadline
        if not self._tasks:
            return
        try:
            await self._empty.wait()
        except asyncio.CancelledError:
            await self._cancel_calls()
            raise

    async def stop(self) -> None:
        await self._cancel_calls()

    async def _cancel_calls(self) -> None:
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


class Application:
    """Own one isolated tool catalog, transport, policy path, and lifecycle."""

    def __init__(
        self,
        *,
        catalog: ToolCatalog,
        authorizer: Authorizer,
        transport: ApplicationTransport,
        telemetry: Telemetry[ScrubbedError],
        limits: ApplicationLimits,
        clock: Clock,
        execution_limits: ExecutionLimits = _DEFAULT_EXECUTION_LIMITS,
        redactor: RedactionPolicy = DEFAULT_REDACTION_POLICY,
        lifecycle: Iterable[Lifecycle] = (),
    ) -> None:
        components = tuple(lifecycle)
        self._validate_configuration(
            catalog=catalog,
            authorizer=authorizer,
            transport=transport,
            telemetry=telemetry,
            limits=limits,
            clock=clock,
            execution_limits=execution_limits,
            redactor=redactor,
            lifecycle=components,
        )
        self._catalog = catalog
        self._authorizer = authorizer
        self._telemetry = telemetry
        self._limits = limits
        self._clock = clock
        self._execution_limits = execution_limits
        self._redactor = redactor
        self._execution = ExecutionController(execution_limits, clock=clock)
        self._telemetry_failures = 0
        self._invocations = _InvocationLifecycle()
        self._lifecycle = LifecycleController(
            [
                *components,
                self._invocations,
                _TransportLifecycle(transport, self),
            ]
        )

    @staticmethod
    def _validate_configuration(
        *,
        catalog: ToolCatalog,
        authorizer: Authorizer,
        transport: ApplicationTransport,
        telemetry: Telemetry[ScrubbedError],
        limits: ApplicationLimits,
        clock: Clock,
        execution_limits: ExecutionLimits,
        redactor: RedactionPolicy,
        lifecycle: tuple[Lifecycle, ...],
    ) -> None:
        dependencies: tuple[tuple[str, object, type[Any]], ...] = (
            ("catalog", catalog, ToolCatalog),
            ("authorizer", authorizer, Authorizer),
            ("transport", transport, ApplicationTransport),
            ("telemetry", telemetry, Telemetry),
            ("limits", limits, ApplicationLimits),
            ("clock", clock, Clock),
            ("execution_limits", execution_limits, ExecutionLimits),
            ("redactor", redactor, RedactionPolicy),
        )
        for path, dependency, expected in dependencies:
            if not _is_runtime_instance(dependency, expected):
                raise ApplicationConfigurationError(
                    code="invalid_dependency",
                    path=path,
                )

        if len(catalog) > execution_limits.max_tools:
            raise ApplicationConfigurationError(
                code="tool_limit_exceeded",
                path="catalog",
            )

        names = {_InvocationLifecycle.name}
        transport_name = Application._validated_component_name(
            transport,
            path="transport.name",
        )
        if transport_name in names:
            raise ApplicationConfigurationError(
                code="duplicate_component_name",
                path="transport.name",
            )
        names.add(transport_name)
        for index, component in enumerate(lifecycle):
            path = f"lifecycle[{index}]"
            if not _is_runtime_instance(component, Lifecycle):
                raise ApplicationConfigurationError(
                    code="invalid_dependency",
                    path=path,
                )
            name = Application._validated_component_name(
                component,
                path=f"{path}.name",
            )
            if name in names:
                raise ApplicationConfigurationError(
                    code="duplicate_component_name",
                    path=f"{path}.name",
                )
            names.add(name)

    @staticmethod
    def _validated_component_name(component: _Named, *, path: str) -> str:
        try:
            name = component.name
        except Exception as error:
            raise ApplicationConfigurationError(
                code="invalid_component_name",
                path=path,
            ) from error
        if not _is_runtime_instance(name, str) or _COMPONENT_NAME.fullmatch(name) is None:
            raise ApplicationConfigurationError(
                code="invalid_component_name",
                path=path,
            )
        return name

    @property
    def state(self) -> LifecycleState:
        return self._lifecycle.state

    @property
    def telemetry_failures(self) -> int:
        return self._telemetry_failures

    @property
    def detached_invocations(self) -> int:
        return self._execution.detached_count

    async def start(self) -> None:
        await self._lifecycle.start()

    async def drain(self) -> None:
        deadline = self._clock.now() + self._limits.drain_timeout
        await self._run_before_deadline(
            self._lifecycle.drain(deadline=deadline),
            deadline=deadline,
            phase=LifecycleState.DRAINING,
        )

    async def stop(self) -> None:
        deadline = self._clock.now() + self._limits.drain_timeout
        await self._run_before_deadline(
            self._lifecycle.stop(),
            deadline=deadline,
            phase=LifecycleState.STOPPED,
        )

    async def run(self, signals: ShutdownSignalSource) -> ApplicationRunResult:
        if not _is_runtime_instance(signals, ShutdownSignalSource):
            raise ApplicationConfigurationError(
                code="invalid_dependency",
                path="signals",
            )
        try:
            await self.start()
        except Exception as error:
            return ApplicationRunResult.failure(
                ApplicationDiagnostic.from_exception(
                    ApplicationDiagnosticCode.STARTUP_FAILED,
                    phase=LifecycleState.STARTUP,
                    error=error,
                )
            )

        diagnostic: ApplicationDiagnostic | None = None
        try:
            received = await signals.wait()
            if not _is_runtime_instance(received, ShutdownSignal):
                raise ApplicationConfigurationError(
                    code="invalid_signal",
                    path="signals.wait",
                )
        except Exception as error:
            diagnostic = ApplicationDiagnostic.from_exception(
                ApplicationDiagnosticCode.SIGNAL_FAILED,
                phase=LifecycleState.READY,
                error=error,
            )

        try:
            await self.drain()
        except Exception as error:
            if diagnostic is None:
                diagnostic = ApplicationDiagnostic.from_exception(
                    ApplicationDiagnosticCode.DRAIN_FAILED,
                    phase=LifecycleState.DRAINING,
                    error=error,
                )

        try:
            await self.stop()
        except Exception as error:
            if diagnostic is None:
                diagnostic = ApplicationDiagnostic.from_exception(
                    ApplicationDiagnosticCode.STOP_FAILED,
                    phase=LifecycleState.STOPPED,
                    error=error,
                )

        if diagnostic is not None:
            return ApplicationRunResult.failure(diagnostic)
        return ApplicationRunResult.success()

    def list_tools(self) -> tuple[str, ...]:
        if self.state is not LifecycleState.READY:
            return ()
        return tuple(
            manifest.metadata.name
            for manifest in self._catalog.manifests
            if self._is_exported(manifest.metadata.name)
        )

    def list_tool_manifests(self) -> tuple[ToolManifest, ...]:
        return tuple(
            manifest
            for manifest in self._catalog.manifests
            if self._is_exported(manifest.metadata.name)
        )

    def _is_exported(self, tool_name: str) -> bool:
        authorizer: object = self._authorizer
        if not isinstance(authorizer, _ToolVisibilityPolicy):
            return True
        return authorizer.is_exported(tool_name)

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> InvocationResult:
        if self.state is not LifecycleState.READY:
            return InvocationResult.failure(
                ErrorResponse.from_code(
                    ErrorCode.UNAVAILABLE,
                    request_id=self._safe_request_id(context.request_id),
                )
            )
        task = self._invocations.begin()
        try:
            result = await self._execution.execute(
                lambda bounded_context: self._invoke(
                    name,
                    arguments,
                    context=bounded_context,
                ),
                context=context,
            )
            return self._redact_result(result, request_id=context.request_id)
        except asyncio.CancelledError as error:
            return self._mapped_failure(error, request_id=context.request_id)
        except TimeoutError as error:
            return self._mapped_failure(error, request_id=context.request_id)
        finally:
            self._invocations.finish(task)

    async def _invoke(
        self,
        name: str,
        arguments: Mapping[str, JsonValue],
        *,
        context: CallContext,
    ) -> InvocationResult:
        try:
            validate_json_value(
                arguments,
                limits=self._execution_limits,
                maximum_bytes=self._execution_limits.max_input_bytes,
            )
        except ExecutionLimitExceeded:
            return InvocationResult.failure(
                ErrorResponse.from_code(ErrorCode.INVALID_INPUT, request_id=context.request_id)
            )
        tool = self._catalog.get(name)
        if tool is None:
            return InvocationResult.failure(
                ErrorResponse.from_code(ErrorCode.INVALID_INPUT, request_id=context.request_id)
            )
        try:
            input_model = tool.parse_input(arguments)
        except (KeyError, TypeError, ValueError):
            return InvocationResult.failure(
                ErrorResponse.from_code(ErrorCode.INVALID_INPUT, request_id=context.request_id)
            )
        try:
            lease = self._execution.admit(
                tool_name=tool.metadata.name,
                tenant=context.tenant,
            )
            if lease is None:
                raise RuntimeFailure(ErrorCode.OVERLOADED)
            try:
                await self._authorizer.authorize(
                    tool=tool,
                    arguments=arguments,
                    context=context,
                )
                retry_safe = tool.metadata.effect is ToolEffect.READ or (
                    tool.metadata.idempotency is IdempotencyRequirement.REQUIRED
                    and context.idempotency_key is not None
                )
                output_model = await self._execution.retry(
                    lambda: tool.handler(input_model, context=context),
                    context=context,
                    safe=retry_safe,
                )
                output = tool.serialize_output(output_model)
                try:
                    validate_json_value(
                        output,
                        limits=self._execution_limits,
                        maximum_bytes=self._execution_limits.max_result_bytes,
                    )
                except ExecutionLimitExceeded:
                    raise RuntimeFailure(ErrorCode.RESULT_TOO_LARGE) from None
                return InvocationResult.success(output)
            finally:
                self._execution.release(lease)
        except Exception as error:
            return self._mapped_failure(error, request_id=context.request_id)

    def _mapped_failure(self, error: BaseException, *, request_id: str) -> InvocationResult:
        safe_request_id = self._safe_request_id(request_id)
        mapped = map_exception(error, request_id=safe_request_id)
        exception_type = mapped.audit.exception_type
        try:
            redacted_type = self._redactor.redact_text(exception_type)
            if redacted_type != exception_type:
                exception_type = "RedactedException"
            audit = ScrubbedError(
                code=mapped.audit.code,
                exception_type=exception_type,
                request_id=safe_request_id,
            )
        except Exception:
            audit = ScrubbedError(
                code=mapped.audit.code,
                exception_type="RedactionError",
                request_id=safe_request_id,
            )
        try:
            self._telemetry.emit(audit)
        except Exception:
            self._telemetry_failures += 1
        return InvocationResult.failure(mapped.response)

    def _redact_result(self, result: InvocationResult, *, request_id: str) -> InvocationResult:
        if result.error is not None:
            return InvocationResult.failure(
                ErrorResponse.from_code(
                    result.error.code,
                    request_id=self._safe_request_id(request_id),
                )
            )
        try:
            value = self._redactor.redact(result.value)
            validate_json_value(
                value,
                limits=self._execution_limits,
                maximum_bytes=self._execution_limits.max_result_bytes,
            )
        except ExecutionLimitExceeded:
            return self._mapped_failure(
                RuntimeFailure(ErrorCode.RESULT_TOO_LARGE),
                request_id=request_id,
            )
        except Exception:
            return self._mapped_failure(RedactionError(), request_id=request_id)
        return InvocationResult.success(value)

    def _safe_request_id(self, request_id: str) -> str:
        try:
            value = self._redactor.redact_text(request_id)
            ErrorResponse.from_code(ErrorCode.INTERNAL_FAILURE, request_id=value)
            return value
        except Exception:
            digest = hashlib.sha256(str(request_id).encode("utf-8", errors="replace")).hexdigest()[
                :16
            ]
            return f"redaction-failed-{digest}"

    async def _run_before_deadline(
        self,
        operation: Coroutine[Any, Any, None],
        *,
        deadline: float,
        phase: LifecycleState,
    ) -> None:
        work = asyncio.create_task(operation)
        timed_out = asyncio.create_task(self._clock.sleep(max(0.0, deadline - self._clock.now())))
        done, _ = await asyncio.wait(
            {work, timed_out},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if work in done:
            await _cancel_task(timed_out)
            await work
            return
        work.cancel()
        await _cancel_task(work)
        raise ApplicationDeadlineExceeded(phase=phase)


__all__ = [
    "Application",
    "ApplicationConfigurationError",
    "ApplicationDeadlineExceeded",
    "ApplicationDiagnostic",
    "ApplicationDiagnosticCode",
    "ApplicationEndpoint",
    "ApplicationLimits",
    "ApplicationRunResult",
    "ApplicationTransport",
    "ShutdownSignal",
    "ShutdownSignalSource",
]
