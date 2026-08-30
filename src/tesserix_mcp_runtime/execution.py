from __future__ import annotations

import asyncio
import hashlib
import json
import math
from collections.abc import Callable, Coroutine, Mapping
from dataclasses import dataclass, replace
from typing import Any, Final, TypeGuard

from tesserix_mcp_runtime.contracts import CallContext, Cancellation, Clock, ErrorCode
from tesserix_mcp_runtime.errors import RuntimeFailure
from tesserix_mcp_runtime.observability import RuntimeLimit, RuntimeObservability

_INTEGER_MAXIMA: Final = (
    ("max_input_bytes", 65_536),
    ("max_result_bytes", 524_288),
    ("max_json_depth", 32),
    ("max_object_properties", 256),
    ("max_array_items", 4_096),
    ("max_json_nodes", 16_384),
    ("max_tools", 128),
    ("max_global_concurrency", 256),
    ("max_server_concurrency", 256),
    ("max_tool_concurrency", 128),
    ("max_tenant_concurrency", 64),
    ("max_attempts", 5),
)
_DURATION_MAXIMA: Final = (
    ("max_call_seconds", 300.0),
    ("max_tool_seconds", 300.0),
    ("cancellation_grace_seconds", 5.0),
    ("retry_base_delay_seconds", 1.0),
    ("retry_max_delay_seconds", 5.0),
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionLimits:
    max_input_bytes: int = 65_536
    max_result_bytes: int = 524_288
    max_json_depth: int = 16
    max_object_properties: int = 128
    max_array_items: int = 1_024
    max_json_nodes: int = 4_096
    max_tools: int = 128
    max_global_concurrency: int = 64
    max_server_concurrency: int = 64
    max_tool_concurrency: int = 32
    max_tenant_concurrency: int = 16
    max_call_seconds: float = 30.0
    max_tool_seconds: float = 30.0
    cancellation_grace_seconds: float = 1.0
    max_attempts: int = 3
    retry_base_delay_seconds: float = 0.05
    retry_max_delay_seconds: float = 0.5

    def __post_init__(self) -> None:
        for name, integer_maximum in _INTEGER_MAXIMA:
            integer_value = getattr(self, name)
            if (
                not isinstance(integer_value, int)
                or isinstance(integer_value, bool)
                or not 1 <= integer_value <= integer_maximum
            ):
                raise ValueError(f"{name} must be a positive integer at most {integer_maximum}")
        for name, duration_maximum in _DURATION_MAXIMA:
            duration_value = getattr(self, name)
            if (
                isinstance(duration_value, bool)
                or not isinstance(duration_value, int | float)
                or not math.isfinite(duration_value)
                or not 0 < duration_value <= duration_maximum
            ):
                raise ValueError(f"{name} must be finite, positive, and at most {duration_maximum}")
        if self.retry_base_delay_seconds > self.retry_max_delay_seconds:
            raise ValueError("retry_base_delay_seconds must not exceed retry_max_delay_seconds")


class ExecutionLimitExceeded(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ExecutionLease:
    tool_name: str
    tenant: str


class _LinkedCancellation:
    def __init__(self, parent: Cancellation) -> None:
        self._parent = parent
        self._local = asyncio.Event()

    @property
    def cancelled(self) -> bool:
        return self._local.is_set() or self._parent.cancelled

    async def wait(self) -> None:
        if self.cancelled:
            return
        await self._local.wait()

    def cancel(self) -> None:
        self._local.set()


async def _cancel_tasks(*tasks: asyncio.Task[Any]) -> None:
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


class ExecutionController:
    def __init__(
        self,
        limits: ExecutionLimits,
        *,
        clock: Clock,
        observability: RuntimeObservability | None = None,
    ) -> None:
        self._limits = limits
        self._clock = clock
        self._observability = (
            RuntimeObservability(server_name="tesserix-mcp-runtime")
            if observability is None
            else observability
        )
        self._active = 0
        self._by_tool: dict[str, int] = {}
        self._by_tenant: dict[str, int] = {}
        self._detached: set[asyncio.Task[Any]] = set()

    @property
    def detached_count(self) -> int:
        return len(self._detached)

    def bounded_context(self, context: CallContext, *, now: float) -> CallContext:
        deadline = min(
            now + self._limits.max_call_seconds,
            now + self._limits.max_tool_seconds,
            context.deadline if context.deadline is not None else math.inf,
        )
        return replace(context, deadline=deadline)

    async def execute[ResultT](
        self,
        operation: Callable[[CallContext], Coroutine[Any, Any, ResultT]],
        *,
        context: CallContext,
    ) -> ResultT:
        now = self._clock.now()
        linked = _LinkedCancellation(context.cancellation)
        bounded = replace(
            self.bounded_context(context, now=now),
            cancellation=linked,
        )
        if linked.cancelled:
            raise asyncio.CancelledError
        if bounded.deadline is None or bounded.deadline <= now:
            raise TimeoutError
        work: asyncio.Task[ResultT] = asyncio.create_task(operation(bounded))
        caller_cancelled = asyncio.create_task(context.cancellation.wait())
        deadline = asyncio.create_task(self._clock.sleep(bounded.deadline - now))
        try:
            done, _ = await asyncio.wait(
                {work, caller_cancelled, deadline},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if caller_cancelled in done or context.cancellation.cancelled:
                linked.cancel()
                raise asyncio.CancelledError
            if deadline in done:
                linked.cancel()
                await self._stop(work)
                raise TimeoutError
            return await work
        except asyncio.CancelledError:
            linked.cancel()
            await self._stop(work)
            raise
        finally:
            await _cancel_tasks(caller_cancelled, deadline)

    async def retry[ResultT](
        self,
        operation: Callable[[], Coroutine[Any, Any, ResultT]],
        *,
        context: CallContext,
        safe: bool,
        tool_name: str,
    ) -> ResultT:
        attempts = self._limits.max_attempts if safe else 1
        for attempt in range(1, attempts + 1):
            try:
                return await operation()
            except (ConnectionError, TimeoutError, RuntimeFailure) as error:
                transient = not isinstance(error, RuntimeFailure) or error.code in {
                    ErrorCode.OVERLOADED,
                    ErrorCode.UNAVAILABLE,
                }
                if not transient or attempt == attempts:
                    raise
                delay = self._retry_delay(context.request_id, attempt)
                now = self._clock.now()
                if context.deadline is None or now + delay >= context.deadline:
                    raise TimeoutError from error
                self._observability.record_retry(tool_name=tool_name)
                await self._clock.sleep(delay)
                if context.cancelled:
                    raise asyncio.CancelledError from error
        raise AssertionError("retry loop must return or raise")

    def _retry_delay(self, request_id: str, attempt: int) -> float:
        sample: int = hashlib.sha256(f"{request_id}:{attempt}".encode()).digest()[0]
        jitter = 0.5 + sample / 255
        exponential = self._limits.retry_base_delay_seconds * 2 ** (attempt - 1) * jitter
        return float(min(self._limits.retry_max_delay_seconds, exponential))

    async def _stop[ResultT](self, task: asyncio.Task[ResultT]) -> None:
        if task.done():
            await asyncio.gather(task, return_exceptions=True)
            return
        await asyncio.sleep(0)
        if task.done():
            await asyncio.gather(task, return_exceptions=True)
            return
        task.cancel()
        grace = asyncio.create_task(self._clock.sleep(self._limits.cancellation_grace_seconds))
        try:
            done, _ = await asyncio.wait(
                {task, grace},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if task in done:
                await asyncio.gather(task, return_exceptions=True)
            else:
                detached = task
                self._detached.add(detached)
                detached.add_done_callback(self._detached.discard)
        finally:
            await _cancel_tasks(grace)

    def admit(self, *, tool_name: str, tenant: str) -> _ExecutionLease | None:
        tool_active = self._by_tool.get(tool_name, 0)
        tenant_active = self._by_tenant.get(tenant, 0)
        limit = None
        if self._active >= self._limits.max_global_concurrency:
            limit = RuntimeLimit.GLOBAL
        elif self._active >= self._limits.max_server_concurrency:
            limit = RuntimeLimit.SERVER
        elif tool_active >= self._limits.max_tool_concurrency:
            limit = RuntimeLimit.TOOL
        elif tenant_active >= self._limits.max_tenant_concurrency:
            limit = RuntimeLimit.TENANT
        if limit is not None:
            self._observability.record_limit(tool_name=tool_name, limit=limit)
            return None
        self._active += 1
        self._by_tool[tool_name] = tool_active + 1
        self._by_tenant[tenant] = tenant_active + 1
        self._observability.change_in_flight(
            tool_name=tool_name,
            delta=1,
            server_capacity=self._limits.max_server_concurrency,
            tool_capacity=self._limits.max_tool_concurrency,
        )
        return _ExecutionLease(tool_name=tool_name, tenant=tenant)

    def release(self, lease: _ExecutionLease) -> None:
        self._active -= 1
        self._decrement(self._by_tool, lease.tool_name)
        self._decrement(self._by_tenant, lease.tenant)
        self._observability.change_in_flight(
            tool_name=lease.tool_name,
            delta=-1,
            server_capacity=self._limits.max_server_concurrency,
            tool_capacity=self._limits.max_tool_concurrency,
        )

    @staticmethod
    def _decrement(counts: dict[str, int], key: str) -> None:
        remaining = counts[key] - 1
        if remaining == 0:
            del counts[key]
        else:
            counts[key] = remaining


def _is_json_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    return isinstance(value, Mapping)


def _is_json_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def validate_json_value(
    value: object,
    *,
    limits: ExecutionLimits,
    maximum_bytes: int,
) -> None:
    nodes = 0
    pending = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > limits.max_json_nodes:
            raise ExecutionLimitExceeded
        if _is_json_mapping(current):
            if depth > limits.max_json_depth or len(current) > limits.max_object_properties:
                raise ExecutionLimitExceeded
            if any(not isinstance(name, str) for name in current):
                raise ExecutionLimitExceeded
            pending.extend((child, depth + 1) for child in current.values())
        elif _is_json_list(current):
            if depth > limits.max_json_depth or len(current) > limits.max_array_items:
                raise ExecutionLimitExceeded
            pending.extend((child, depth + 1) for child in current)
        elif (
            current is None
            or isinstance(current, str | bool | int)
            or (isinstance(current, float) and math.isfinite(current))
        ):
            continue
        else:
            raise ExecutionLimitExceeded
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError) as error:
        raise ExecutionLimitExceeded from error
    if len(encoded) > maximum_bytes:
        raise ExecutionLimitExceeded


__all__ = ["ExecutionLimits"]
