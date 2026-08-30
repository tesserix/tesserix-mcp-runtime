from __future__ import annotations

import argparse
import asyncio
import json
import re
import signal
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeGuard, cast
from urllib.parse import urlsplit

import httpx

from integration.journey.backing import JOURNEY_CANARY
from tesserix_mcp_runtime import (
    Application,
    ApplicationLimits,
    ApplicationTransport,
    ApprovalRecord,
    ApprovalRequirement,
    ApprovalUse,
    CallContext,
    Cancellation,
    ErrorCode,
    ExecutionLimits,
    IdempotencyRequirement,
    JsonValue,
    RuntimeFailure,
    RuntimeObservability,
    ScrubbedError,
    SecretRedactor,
    SecretValue,
    SystemClock,
    ToolCatalog,
    ToolDiscoveryMetadata,
    ToolEffect,
    ToolHandler,
    ToolMetadata,
    ToolPolicy,
    ToolPolicyAuditEvent,
    ToolPolicyRule,
    ToolPolicyState,
    ToolReview,
    tool_policy_fingerprint,
)
from tesserix_mcp_runtime.adapters.gateway_identity import (
    GatewayIdentityConfig,
    GatewayJWTContextProvider,
    JWKSFetcher,
    JWKSFetchError,
)
from tesserix_mcp_runtime.adapters.streamable_http import (
    HTTPCallContextProvider,
    HTTPRequestAuthenticationError,
    HTTPRequestMetadata,
    ProtocolTelemetryEvent,
    StreamableHTTPConfig,
    StreamableHTTPLimits,
    StreamableHTTPTransport,
)

JOURNEY_APPROVAL_ID = "journey-approval-order-001"

_ORDER_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_STATUS = re.compile(r"[a-z][a-z_]{0,31}\Z")
_TENANT = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_MAX_DEPENDENCY_BYTES = 65_536


def _is_json_value(value: object, *, depth: int = 0, budget: list[int] | None = None) -> bool:
    resolved_budget = [0] if budget is None else budget
    resolved_budget[0] += 1
    if depth > 8 or resolved_budget[0] > 1_024:
        return False
    if value is None or isinstance(value, str | bool):
        return True
    if isinstance(value, int) and not isinstance(value, bool):
        return True
    if isinstance(value, float):
        return value == value and value not in {float("inf"), float("-inf")}
    if isinstance(value, list):
        return len(value) <= 128 and all(
            _is_json_value(item, depth=depth + 1, budget=resolved_budget) for item in value
        )
    if isinstance(value, dict):
        return len(value) <= 128 and all(
            isinstance(key, str)
            and len(key) <= 128
            and _is_json_value(item, depth=depth + 1, budget=resolved_budget)
            for key, item in value.items()
        )
    return False


def _is_json_object(value: object) -> TypeGuard[dict[str, JsonValue]]:
    return isinstance(value, dict) and _is_json_value(value)


class JourneyJWKSFetcher(JWKSFetcher):
    name = "journey_jwks_fetcher"

    def __init__(
        self,
        *,
        endpoint: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"identity", "identity.test"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/jwks.json"
        ):
            raise ValueError("JWKS endpoint must be the isolated identity service")
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(2.0),
            trust_env=False,
        )
        self._endpoint = endpoint
        self._closed = False

    async def fetch(self) -> Mapping[str, JsonValue]:
        try:
            response = await self._client.get(self._endpoint)
        except httpx.HTTPError as error:
            raise JWKSFetchError("journey JWKS unavailable") from error
        if response.status_code != 200 or len(response.content) > _MAX_DEPENDENCY_BYTES:
            raise JWKSFetchError("journey JWKS unavailable")
        try:
            document: object = response.json()
        except ValueError as error:
            raise JWKSFetchError("journey JWKS unavailable") from error
        if not _is_json_object(document) or set(document) != {"keys"}:
            raise JWKSFetchError("journey JWKS unavailable")
        return document

    async def start(self) -> None:
        return None

    async def drain(self, *, deadline: float) -> None:
        del deadline

    async def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._client.aclose()


class TenantBoundContextProvider:
    def __init__(self, provider: HTTPCallContextProvider, *, tenant: str) -> None:
        if not isinstance(provider, HTTPCallContextProvider):
            raise TypeError("provider must implement HTTPCallContextProvider")
        if not isinstance(tenant, str) or _TENANT.fullmatch(tenant) is None:
            raise ValueError("tenant must be a canonical bounded label")
        self._provider = provider
        self._tenant = tenant

    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        context = await self._provider.create(request, cancellation=cancellation)
        if context.tenant != self._tenant:
            raise HTTPRequestAuthenticationError(request_id=context.request_id)
        return context


class RejectingContextProvider:
    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        del request, cancellation
        raise HTTPRequestAuthenticationError(request_id="candidate-probe-rejected")


class BackingClient:
    name = "journey_backing_client"

    def __init__(
        self,
        *,
        endpoint: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"backing", "backing.test"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("backing endpoint must be the isolated backing service")
        self._client = httpx.AsyncClient(
            base_url=endpoint.rstrip("/"),
            transport=transport,
            timeout=httpx.Timeout(2.0),
            trust_env=False,
        )
        self._closed = False

    async def start(self) -> None:
        return None

    async def drain(self, *, deadline: float) -> None:
        del deadline

    async def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._client.aclose()

    async def read_order(self, context: CallContext, *, order_id: str) -> dict[str, JsonValue]:
        return await self._request("GET", f"/v1/orders/{order_id}", context=context)

    async def write_order(
        self,
        context: CallContext,
        *,
        order_id: str,
        status: str,
    ) -> dict[str, JsonValue]:
        return await self._request(
            "POST",
            f"/v1/orders/{order_id}",
            context=context,
            document={"status": status},
        )

    async def secret_canary(self, context: CallContext) -> dict[str, JsonValue]:
        return await self._request("GET", "/v1/canary", context=context)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        context: CallContext,
        document: Mapping[str, JsonValue] | None = None,
    ) -> dict[str, JsonValue]:
        traceparent = context.trace.get("traceparent")
        if traceparent is None:
            raise RuntimeFailure(ErrorCode.INVALID_INPUT)
        headers = {
            "traceparent": traceparent,
            "x-journey-scopes": " ".join(sorted(context.scopes)),
            "x-journey-subject": context.subject,
            "x-journey-tenant": context.tenant,
            "x-request-id": context.request_id,
        }
        if context.idempotency_key is not None:
            headers["idempotency-key"] = context.idempotency_key
        try:
            response = await self._client.request(
                method,
                path,
                headers=headers,
                json=document,
            )
        except httpx.HTTPError as error:
            raise RuntimeFailure(ErrorCode.UNAVAILABLE) from error
        if len(response.content) > _MAX_DEPENDENCY_BYTES:
            raise RuntimeFailure(ErrorCode.RESULT_TOO_LARGE)
        if response.status_code == 409:
            raise RuntimeFailure(ErrorCode.CONFLICT)
        if response.status_code == 503:
            raise RuntimeFailure(ErrorCode.UNAVAILABLE)
        if response.status_code != 200:
            raise RuntimeFailure(ErrorCode.INTERNAL_FAILURE)
        try:
            value: object = response.json()
        except ValueError as error:
            raise RuntimeFailure(ErrorCode.INTERNAL_FAILURE) from error
        if not _is_json_object(value):
            raise RuntimeFailure(ErrorCode.INTERNAL_FAILURE)
        return value


class _Operation(StrEnum):
    APPROVE = "approve"
    FAIL = "fail"
    READ = "read"
    SECRET = "secret"
    SLOW = "slow"
    WRITE = "write"


_EMPTY_SCHEMA: Mapping[str, JsonValue] = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}
_ORDER_INPUT: Mapping[str, JsonValue] = {
    "type": "object",
    "properties": {
        "order_id": {"type": "string", "minLength": 1, "maxLength": 64},
    },
    "required": ["order_id"],
    "additionalProperties": False,
}
_WRITE_INPUT: Mapping[str, JsonValue] = {
    "type": "object",
    "properties": {
        "order_id": {"type": "string", "minLength": 1, "maxLength": 64},
        "status": {"type": "string", "minLength": 1, "maxLength": 32},
    },
    "required": ["order_id", "status"],
    "additionalProperties": False,
}
_SLOW_INPUT: Mapping[str, JsonValue] = {
    "type": "object",
    "properties": {
        "delay_ms": {"type": "integer", "minimum": 1, "maximum": 1_000},
    },
    "required": ["delay_ms"],
    "additionalProperties": False,
}
_ORDER_OUTPUT: Mapping[str, JsonValue] = {
    "type": "object",
    "properties": {
        "effect_id": {"type": "string", "maxLength": 64},
        "order_id": {"type": "string", "maxLength": 64},
        "status": {"type": "string", "maxLength": 32},
    },
    "required": ["order_id", "status"],
    "additionalProperties": False,
}
_CANARY_OUTPUT: Mapping[str, JsonValue] = {
    "type": "object",
    "properties": {"api_key": {"type": "string", "maxLength": 128}},
    "required": ["api_key"],
    "additionalProperties": False,
}
_SLOW_OUTPUT: Mapping[str, JsonValue] = {
    "type": "object",
    "properties": {"slept_ms": {"type": "integer", "minimum": 1, "maximum": 1_000}},
    "required": ["slept_ms"],
    "additionalProperties": False,
}
_FAIL_OUTPUT: Mapping[str, JsonValue] = {
    "type": "object",
    "properties": {"status": {"type": "string", "maxLength": 32}},
    "required": ["status"],
    "additionalProperties": False,
}


class JourneyTool:
    def __init__(
        self,
        *,
        backing: BackingClient,
        metadata: ToolMetadata,
        operation: _Operation,
        input_schema: Mapping[str, JsonValue],
        output_schema: Mapping[str, JsonValue],
    ) -> None:
        self._metadata = metadata
        self._input_schema = input_schema
        self._output_schema = output_schema
        self._backing = backing
        self._operation = operation

    @property
    def metadata(self) -> ToolMetadata:
        return self._metadata

    @property
    def input_schema(self) -> Mapping[str, JsonValue]:
        return self._input_schema

    @property
    def output_schema(self) -> Mapping[str, JsonValue]:
        return self._output_schema

    @property
    def handler(self) -> ToolHandler[dict[str, JsonValue], dict[str, JsonValue]]:
        return self

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        values = dict(arguments)
        if self._operation in {_Operation.FAIL, _Operation.SECRET}:
            if values:
                raise ValueError("arguments do not match tool contract")
            return values
        if self._operation is _Operation.SLOW:
            delay = values.get("delay_ms")
            if (
                set(values) != {"delay_ms"}
                or isinstance(delay, bool)
                or not isinstance(delay, int)
                or not 1 <= delay <= 1_000
            ):
                raise ValueError("arguments do not match tool contract")
            return values
        order_id = values.get("order_id")
        expected = {"order_id", "status"} if self._operation is _Operation.WRITE else {"order_id"}
        if (
            set(values) != expected
            or not isinstance(order_id, str)
            or _ORDER_ID.fullmatch(order_id) is None
        ):
            raise ValueError("arguments do not match tool contract")
        if self._operation is _Operation.WRITE:
            status = values.get("status")
            if not isinstance(status, str) or _STATUS.fullmatch(status) is None:
                raise ValueError("arguments do not match tool contract")
        return values

    async def __call__(
        self,
        input_model: dict[str, JsonValue],
        *,
        context: CallContext,
    ) -> dict[str, JsonValue]:
        if self._operation is _Operation.FAIL:
            raise RuntimeError(f"private reference failure {JOURNEY_CANARY}")
        if self._operation is _Operation.SECRET:
            return await self._backing.secret_canary(context)
        if self._operation is _Operation.SLOW:
            delay = cast(int, input_model["delay_ms"])
            await asyncio.sleep(delay / 1_000)
            return {"slept_ms": delay}
        order_id = cast(str, input_model["order_id"])
        if self._operation is _Operation.READ:
            return await self._backing.read_order(context, order_id=order_id)
        status = (
            "approved"
            if self._operation is _Operation.APPROVE
            else cast(str, input_model["status"])
        )
        return await self._backing.write_order(context, order_id=order_id, status=status)

    def serialize_output(self, output_model: dict[str, JsonValue]) -> JsonValue:
        if not _is_json_object(output_model):
            raise ValueError("tool output must be a bounded JSON object")
        return output_model


class JourneyAuditSink:
    def __init__(
        self,
        emit: Callable[[Mapping[str, JsonValue]], None] | None = None,
    ) -> None:
        self._events: list[ToolPolicyAuditEvent] = []
        self._emit = emit

    @property
    def events(self) -> tuple[ToolPolicyAuditEvent, ...]:
        return tuple(self._events)

    def append(self, event: ToolPolicyAuditEvent) -> None:
        self._events.append(event)
        if self._emit is not None:
            self._emit(event.to_dict())

    def __repr__(self) -> str:
        return f"JourneyAuditSink(event_count={len(self._events)})"


class JourneyTelemetry:
    def __init__(
        self,
        emit: Callable[[Mapping[str, JsonValue]], None] | None = None,
    ) -> None:
        self._events: list[dict[str, JsonValue]] = []
        self._emit = emit

    @property
    def events(self) -> tuple[Mapping[str, JsonValue], ...]:
        return tuple(self._events)

    def emit(self, event: ScrubbedError | ProtocolTelemetryEvent) -> None:
        if isinstance(event, ScrubbedError):
            document = event.to_dict()
        elif isinstance(event, ProtocolTelemetryEvent):
            document = {
                "method": event.method,
                "outcome": event.outcome,
                "protocol_version": event.protocol_version,
                "sdk_version": event.sdk_version,
            }
        else:
            raise TypeError("unsupported telemetry event")
        self._events.append(document)
        if self._emit is not None:
            self._emit(document)


class JourneyApprovalStore:
    def __init__(self, record: ApprovalRecord) -> None:
        self._record = record

    async def fetch(self, *, approval_id: str) -> ApprovalRecord | None:
        return self._record if approval_id == self._record.approval_id else None

    async def consume(self, *, approval_id: str, action_fingerprint: str) -> bool:
        return (
            approval_id == self._record.approval_id
            and action_fingerprint == self._record.action_fingerprint
        )


@dataclass(frozen=True, kw_only=True)
class ReferenceRuntime:
    application: Application
    catalog: ToolCatalog
    audit: JourneyAuditSink
    telemetry: JourneyTelemetry
    observability: RuntimeObservability
    approval_id: str


def _metadata(
    *,
    name: str,
    title: str,
    description: str,
    effect: ToolEffect,
    approval: ApprovalRequirement,
    idempotency: IdempotencyRequirement,
    scopes: tuple[str, ...],
    capability: str,
) -> ToolMetadata:
    return ToolMetadata(
        name=name,
        title=title,
        description=description,
        effect=effect,
        approval=approval,
        idempotency=idempotency,
        required_scopes=scopes,
        discovery=ToolDiscoveryMetadata(
            summary=description,
            when_to_use=description,
            capabilities=(capability,),
            rate_class="integration",
            lifecycle="active",
            examples=(),
        ),
    )


def build_reference_runtime(
    *,
    transport: ApplicationTransport,
    backing: BackingClient,
    wall_clock: Callable[[], float] = time.time,
    emit_audit: Callable[[Mapping[str, JsonValue]], None] | None = None,
    emit_telemetry: Callable[[Mapping[str, JsonValue]], None] | None = None,
) -> ReferenceRuntime:
    definitions: tuple[JourneyTool, ...] = (
        JourneyTool(
            backing=backing,
            metadata=_metadata(
                name="journey.approve_order",
                title="Approve order",
                description="Approve one known order after explicit review.",
                effect=ToolEffect.EXTERNAL_EFFECT,
                approval=ApprovalRequirement.REQUIRED,
                idempotency=IdempotencyRequirement.REQUIRED,
                scopes=("journey:approve", "journey:write"),
                capability="cap/order-approval",
            ),
            operation=_Operation.APPROVE,
            input_schema=_ORDER_INPUT,
            output_schema=_ORDER_OUTPUT,
        ),
        JourneyTool(
            backing=backing,
            metadata=_metadata(
                name="journey.fail",
                title="Fail safely",
                description="Return one deterministic safe failure.",
                effect=ToolEffect.READ,
                approval=ApprovalRequirement.NOT_REQUIRED,
                idempotency=IdempotencyRequirement.NOT_APPLICABLE,
                scopes=("journey:read",),
                capability="cap/safe-failure",
            ),
            operation=_Operation.FAIL,
            input_schema=_EMPTY_SCHEMA,
            output_schema=_FAIL_OUTPUT,
        ),
        JourneyTool(
            backing=backing,
            metadata=_metadata(
                name="journey.read_order",
                title="Read order",
                description="Read one tenant-scoped order.",
                effect=ToolEffect.READ,
                approval=ApprovalRequirement.NOT_REQUIRED,
                idempotency=IdempotencyRequirement.NOT_APPLICABLE,
                scopes=("journey:read",),
                capability="cap/order-read",
            ),
            operation=_Operation.READ,
            input_schema=_ORDER_INPUT,
            output_schema=_ORDER_OUTPUT,
        ),
        JourneyTool(
            backing=backing,
            metadata=_metadata(
                name="journey.secret_canary",
                title="Redact canary",
                description="Prove final-boundary result redaction.",
                effect=ToolEffect.READ,
                approval=ApprovalRequirement.NOT_REQUIRED,
                idempotency=IdempotencyRequirement.NOT_APPLICABLE,
                scopes=("journey:read",),
                capability="cap/redaction-proof",
            ),
            operation=_Operation.SECRET,
            input_schema=_EMPTY_SCHEMA,
            output_schema=_CANARY_OUTPUT,
        ),
        JourneyTool(
            backing=backing,
            metadata=_metadata(
                name="journey.slow",
                title="Bound deadline",
                description="Exercise one bounded invocation deadline.",
                effect=ToolEffect.READ,
                approval=ApprovalRequirement.NOT_REQUIRED,
                idempotency=IdempotencyRequirement.NOT_APPLICABLE,
                scopes=("journey:read",),
                capability="cap/deadline-proof",
            ),
            operation=_Operation.SLOW,
            input_schema=_SLOW_INPUT,
            output_schema=_SLOW_OUTPUT,
        ),
        JourneyTool(
            backing=backing,
            metadata=_metadata(
                name="journey.write_order",
                title="Write order",
                description="Write one order with replay-safe idempotency.",
                effect=ToolEffect.WRITE,
                approval=ApprovalRequirement.NOT_REQUIRED,
                idempotency=IdempotencyRequirement.REQUIRED,
                scopes=("journey:write",),
                capability="cap/order-write",
            ),
            operation=_Operation.WRITE,
            input_schema=_WRITE_INPUT,
            output_schema=_ORDER_OUTPUT,
        ),
    )
    catalog = ToolCatalog(definitions)
    approval_manifest = next(
        manifest
        for manifest in catalog.manifests
        if manifest.metadata.name == "journey.approve_order"
    )
    approval = ApprovalRecord.for_action(
        approval_id=JOURNEY_APPROVAL_ID,
        tenant="tenant-a",
        subject="subject-a",
        manifest=approval_manifest,
        arguments={"order_id": "order-001"},
        expires_at=wall_clock() + 900,
        use=ApprovalUse.REUSABLE,
    )
    audit = JourneyAuditSink(emit_audit)
    rules: list[ToolPolicyRule] = []
    for manifest in catalog.manifests:
        fingerprint = tool_policy_fingerprint(manifest)
        review = None
        if manifest.metadata.effect is not ToolEffect.READ:
            review = ToolReview(
                review_id=f"review-{manifest.normalized_name}",
                author_subject="journey-author",
                reviewer_subject="journey-reviewer",
                reviewed_fingerprint=fingerprint,
            )
        rules.append(
            ToolPolicyRule(
                tool_name=manifest.metadata.name,
                reviewed_fingerprint=fingerprint,
                allowed_scopes=manifest.metadata.required_scopes,
                state=ToolPolicyState.ACTIVE,
                review=review,
            )
        )
    redactor = SecretRedactor(known_secrets=(SecretValue(JOURNEY_CANARY),))
    policy = ToolPolicy(
        catalog=catalog,
        server_scopes=("journey:approve", "journey:read", "journey:write"),
        rules=rules,
        audit_sink=audit,
        approval_store=JourneyApprovalStore(approval),
        wall_clock=wall_clock,
        redactor=redactor,
    )
    telemetry = JourneyTelemetry(emit_telemetry)
    observability = RuntimeObservability(server_name="journey-mcp")
    application = Application(
        catalog=catalog,
        authorizer=policy,
        transport=transport,
        telemetry=telemetry,
        limits=ApplicationLimits(drain_timeout=5.0),
        clock=SystemClock(),
        execution_limits=ExecutionLimits(
            max_call_seconds=2.0,
            max_tool_seconds=2.0,
            max_attempts=1,
        ),
        redactor=redactor,
        observability=observability,
        lifecycle=(backing,),
    )
    return ReferenceRuntime(
        application=application,
        catalog=catalog,
        audit=audit,
        telemetry=telemetry,
        observability=observability,
        approval_id=JOURNEY_APPROVAL_ID,
    )


def _emit(kind: str) -> Callable[[Mapping[str, JsonValue]], None]:
    def emit(document: Mapping[str, JsonValue]) -> None:
        print(
            json.dumps(
                {"event": kind, "value": dict(document)},
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            flush=True,
        )

    return emit


async def serve(arguments: argparse.Namespace) -> None:
    jwks = JourneyJWKSFetcher(endpoint=arguments.jwks_endpoint)
    verified_provider = GatewayJWTContextProvider(
        GatewayIdentityConfig(
            issuer=arguments.issuer,
            audience=arguments.audience,
            jwks_url="https://identity.journey.invalid/jwks.json",
            jwks_allowed_hosts=("identity.journey.invalid",),
            trusted_proxy_cidrs=(arguments.gateway_cidr,),
        ),
        jwks_fetcher=jwks,
    )
    context_provider: HTTPCallContextProvider = (
        RejectingContextProvider()
        if arguments.reject_all
        else TenantBoundContextProvider(verified_provider, tenant=arguments.tenant)
    )
    telemetry = JourneyTelemetry(_emit("protocol"))
    transport = StreamableHTTPTransport(
        config=StreamableHTTPConfig(
            host=arguments.host,
            port=arguments.port,
            allowed_hosts=tuple(arguments.allowed_host),
            allowed_origins=tuple(arguments.allowed_origin),
        ),
        limits=StreamableHTTPLimits(max_tools=6, tool_page_size=6, max_tool_pages=1),
        context_provider=context_provider,
        telemetry=telemetry,
        redactor=SecretRedactor(known_secrets=(SecretValue(JOURNEY_CANARY),)),
    )
    runtime = build_reference_runtime(
        transport=transport,
        backing=BackingClient(endpoint=arguments.backing_endpoint),
        emit_audit=_emit("audit"),
        emit_telemetry=_emit("runtime_error"),
    )
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for received_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(received_signal, stopping.set)
    await runtime.application.start()
    try:
        await stopping.wait()
    finally:
        await runtime.application.drain()
        await runtime.application.stop()
        await jwks.stop()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--allowed-host", action="append", default=["runtime:8000"])
    parser.add_argument("--allowed-origin", action="append", required=True)
    parser.add_argument("--backing-endpoint", default="http://backing:8082")
    parser.add_argument("--jwks-endpoint", default="http://identity:8081/jwks.json")
    parser.add_argument("--issuer", default="https://identity.journey.invalid")
    parser.add_argument("--audience", default="tesserix-mcp-journey")
    parser.add_argument("--tenant", default="tenant-a")
    parser.add_argument("--gateway-cidr", default="172.30.0.0/24")
    parser.add_argument("--reject-all", action="store_true")
    arguments = parser.parse_args()
    asyncio.run(serve(arguments))


if __name__ == "__main__":
    main()


__all__ = [
    "JOURNEY_APPROVAL_ID",
    "BackingClient",
    "JourneyJWKSFetcher",
    "ReferenceRuntime",
    "TenantBoundContextProvider",
    "build_reference_runtime",
]
