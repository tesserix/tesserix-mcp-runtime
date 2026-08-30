from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass

import pytest

from tesserix_mcp_runtime import (
    Application,
    ApplicationLimits,
    ApprovalRecord,
    ApprovalRequirement,
    ApprovalUse,
    AuthenticatedIdentity,
    CallContext,
    ErrorCode,
    IdempotencyRequirement,
    JsonValue,
    RuntimeFailure,
    ScrubbedError,
    SystemClock,
    ToolCatalog,
    ToolEffect,
    ToolHandler,
    ToolMetadata,
    ToolPolicy,
    ToolPolicyAuditEvent,
    ToolPolicyConfigurationError,
    ToolPolicyDecision,
    ToolPolicyRule,
    ToolPolicyState,
    ToolReview,
    tool_policy_fingerprint,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport


@dataclass(frozen=True, slots=True)
class PolicyInput:
    value: str


@dataclass(frozen=True, slots=True)
class PolicyOutput:
    value: str


class PolicyHandler:
    async def __call__(
        self,
        input_model: PolicyInput,
        *,
        context: CallContext,
    ) -> PolicyOutput:
        del context
        return PolicyOutput(value=input_model.value)


class PolicyTool:
    input_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {"value": {"type": "string", "maxLength": 64}},
        "required": ["value"],
        "additionalProperties": False,
    }
    output_schema = input_schema
    handler: ToolHandler[PolicyInput, PolicyOutput] = PolicyHandler()

    def __init__(
        self,
        *,
        name: str = "orders.read",
        effect: ToolEffect = ToolEffect.READ,
        approval: ApprovalRequirement = ApprovalRequirement.NOT_REQUIRED,
        required_scopes: tuple[str, ...] = ("orders:read",),
        handler: ToolHandler[PolicyInput, PolicyOutput] | None = None,
    ) -> None:
        self.metadata = ToolMetadata(
            name=name,
            title="Policy test tool",
            description="Exercise one synthetic policy decision.",
            effect=effect,
            approval=approval,
            idempotency=(
                IdempotencyRequirement.NOT_APPLICABLE
                if effect is ToolEffect.READ
                else IdempotencyRequirement.REQUIRED
            ),
            required_scopes=required_scopes,
        )
        if handler is not None:
            self.handler = handler

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> PolicyInput:
        value = arguments.get("value")
        if not isinstance(value, str):
            raise ValueError("value must be text")
        return PolicyInput(value=value)

    def serialize_output(self, output_model: PolicyOutput) -> JsonValue:
        return {"value": output_model.value}


class FakeIdempotentBackingAPI:
    def __init__(self) -> None:
        self.first_started = asyncio.Event()
        self.duplicate_seen = asyncio.Event()
        self.release = asyncio.Event()
        self.effect_count = 0
        self.received_keys: list[str] = []
        self._lock = asyncio.Lock()
        self._in_flight: dict[tuple[str, str], tuple[str, asyncio.Future[PolicyOutput]]] = {}

    async def update(
        self,
        input_model: PolicyInput,
        *,
        context: CallContext,
    ) -> PolicyOutput:
        idempotency_key = context.idempotency_key
        if idempotency_key is None:
            raise RuntimeFailure(ErrorCode.CONFLICT)
        self.received_keys.append(idempotency_key)
        key = (context.tenant, idempotency_key)
        async with self._lock:
            existing = self._in_flight.get(key)
            if existing is None:
                result = asyncio.get_running_loop().create_future()
                self._in_flight[key] = (input_model.value, result)
                owner = True
            else:
                original_value, result = existing
                if original_value != input_model.value:
                    raise RuntimeFailure(ErrorCode.CONFLICT)
                owner = False
                self.duplicate_seen.set()
        if owner:
            self.first_started.set()
            await self.release.wait()
            self.effect_count += 1
            result.set_result(PolicyOutput(value=f"effect-{self.effect_count}:{input_model.value}"))
        return await asyncio.shield(result)


class IdempotentWriteTool(PolicyTool):
    def __init__(self, backing_api: FakeIdempotentBackingAPI) -> None:
        super().__init__(
            name="orders.concurrent-update",
            effect=ToolEffect.WRITE,
            required_scopes=("orders:write",),
        )
        self.handler = backing_api.update


class CountingPolicyHandler(PolicyHandler):
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(
        self,
        input_model: PolicyInput,
        *,
        context: CallContext,
    ) -> PolicyOutput:
        self.calls += 1
        return await super().__call__(input_model, context=context)


class RecordingAuditSink:
    def __init__(self) -> None:
        self.events: list[ToolPolicyAuditEvent] = []

    def append(self, event: ToolPolicyAuditEvent) -> None:
        self.events.append(event)


class RecordingErrorTelemetry:
    def __init__(self) -> None:
        self.events: list[ScrubbedError] = []

    def emit(self, event: ScrubbedError) -> None:
        self.events.append(event)


class FailingAuditSink:
    def append(self, event: ToolPolicyAuditEvent) -> None:
        del event
        raise RuntimeError("audit-sink-secret")


class ApprovalMemoryStore:
    def __init__(self, records: tuple[ApprovalRecord, ...]) -> None:
        self._records = {record.approval_id: record for record in records}
        self._consumed: set[tuple[str, str]] = set()
        self.consume_calls: list[tuple[str, str]] = []

    async def fetch(self, *, approval_id: str) -> ApprovalRecord | None:
        return self._records.get(approval_id)

    async def consume(self, *, approval_id: str, action_fingerprint: str) -> bool:
        key = (approval_id, action_fingerprint)
        self.consume_calls.append(key)
        if key in self._consumed:
            return False
        self._consumed.add(key)
        return True


class FailingApprovalStore(ApprovalMemoryStore):
    async def fetch(self, *, approval_id: str) -> ApprovalRecord | None:
        del approval_id
        raise RuntimeError("approval-backend-secret")


class FailingConsumeApprovalStore(ApprovalMemoryStore):
    async def consume(self, *, approval_id: str, action_fingerprint: str) -> bool:
        del approval_id, action_fingerprint
        raise RuntimeError("approval-consume-secret")


def failing_wall_clock() -> float:
    raise RuntimeError("wall-clock-secret")


def context(
    *,
    scopes: tuple[str, ...],
    tenant: str = "tenant-blue",
    subject: str = "subject-example",
    idempotency_key: str | None = None,
    approval_id: str | None = None,
    request_id: str = "request-example",
) -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant=tenant,
            subject=subject,
            issuer="https://identity.example.invalid",
            scopes=scopes,
        ),
        request_id=request_id,
        run_id="run-example",
        idempotency_key=idempotency_key,
        approval_id=approval_id,
    )


def test_tool_policy_intersects_verified_caller_server_and_tool_scopes() -> None:
    async def exercise() -> None:
        tool = PolicyTool(required_scopes=("orders:read", "tenant:member"))
        catalog = ToolCatalog([tool])
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:read", "tenant:member", "server:admin"),
            rules=(
                ToolPolicyRule(
                    tool_name=tool.metadata.name,
                    reviewed_fingerprint=tool_policy_fingerprint(catalog.manifests[0]),
                    allowed_scopes=("orders:read", "tenant:member"),
                    state=ToolPolicyState.ACTIVE,
                ),
            ),
            audit_sink=audit,
        )

        await policy.authorize(
            tool=tool,
            arguments={"value": "allowed"},
            context=context(scopes=("orders:read", "tenant:member", "ignored:scope")),
        )
        with pytest.raises(RuntimeFailure) as missing_caller_scope:
            await policy.authorize(
                tool=tool,
                arguments={"value": "denied"},
                context=context(scopes=("orders:read",)),
            )

        assert missing_caller_scope.value.code is ErrorCode.INVALID_INPUT
        assert [event.decision for event in audit.events] == [
            ToolPolicyDecision.ALLOWED,
            ToolPolicyDecision.SCOPE_DENIED,
        ]

    asyncio.run(exercise())


@pytest.mark.parametrize("missing_ceiling", ["server", "tool"])
def test_required_scope_must_exist_in_every_policy_ceiling(missing_ceiling: str) -> None:
    async def exercise() -> None:
        tool = PolicyTool(required_scopes=("orders:read", "tenant:member"))
        catalog = ToolCatalog([tool])
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=(
                ("orders:read",)
                if missing_ceiling == "server"
                else ("orders:read", "tenant:member")
            ),
            rules=(
                ToolPolicyRule(
                    tool_name=tool.metadata.name,
                    reviewed_fingerprint=tool_policy_fingerprint(catalog.manifests[0]),
                    allowed_scopes=(
                        ("orders:read",)
                        if missing_ceiling == "tool"
                        else ("orders:read", "tenant:member")
                    ),
                    state=ToolPolicyState.ACTIVE,
                ),
            ),
            audit_sink=audit,
        )

        with pytest.raises(RuntimeFailure) as denied:
            await policy.authorize(
                tool=tool,
                arguments={"value": "denied"},
                context=context(scopes=("orders:read", "tenant:member")),
            )

        assert denied.value.code is ErrorCode.INVALID_INPUT
        assert [event.decision for event in audit.events] == [ToolPolicyDecision.SCOPE_DENIED]

    asyncio.run(exercise())


def test_active_policy_rule_must_match_the_exact_reviewed_tool_contract() -> None:
    reviewed_tool = PolicyTool(required_scopes=("orders:read",))
    reviewed_catalog = ToolCatalog([reviewed_tool])
    changed_catalog = ToolCatalog([PolicyTool(required_scopes=("orders:read", "tenant:member"))])

    with pytest.raises(ToolPolicyConfigurationError) as raised:
        ToolPolicy(
            catalog=changed_catalog,
            server_scopes=("orders:read", "tenant:member"),
            rules=(
                ToolPolicyRule(
                    tool_name="orders.read",
                    reviewed_fingerprint=tool_policy_fingerprint(reviewed_catalog.manifests[0]),
                    allowed_scopes=("orders:read", "tenant:member"),
                    state=ToolPolicyState.ACTIVE,
                ),
            ),
            audit_sink=RecordingAuditSink(),
        )

    assert raised.value.code == "review_mismatch"
    assert raised.value.path == "rules[0].reviewed_fingerprint"


@pytest.mark.parametrize("effect", [ToolEffect.WRITE, ToolEffect.EXTERNAL_EFFECT])
def test_mutating_tool_cannot_activate_without_independent_review(
    effect: ToolEffect,
) -> None:
    tool = PolicyTool(
        name=f"orders.{effect.value}",
        effect=effect,
        approval=(
            ApprovalRequirement.REQUIRED
            if effect is ToolEffect.EXTERNAL_EFFECT
            else ApprovalRequirement.NOT_REQUIRED
        ),
        required_scopes=("orders:write",),
    )
    catalog = ToolCatalog([tool])
    rule = ToolPolicyRule(
        tool_name=tool.metadata.name,
        reviewed_fingerprint=tool_policy_fingerprint(catalog.manifests[0]),
        allowed_scopes=("orders:write",),
        state=ToolPolicyState.ACTIVE,
    )

    with pytest.raises(ToolPolicyConfigurationError) as raised:
        ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:write",),
            rules=(rule,),
            audit_sink=RecordingAuditSink(),
        )

    assert raised.value.code == "independent_review_required"
    assert raised.value.path == "rules[0].review"


def test_approval_required_tool_cannot_activate_without_an_approval_store() -> None:
    tool = PolicyTool(
        name="orders.approval-store-required",
        effect=ToolEffect.WRITE,
        approval=ApprovalRequirement.REQUIRED,
        required_scopes=("orders:write",),
    )
    catalog = ToolCatalog([tool])

    with pytest.raises(ToolPolicyConfigurationError) as raised:
        ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:write",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:write",)),),
            audit_sink=RecordingAuditSink(),
        )

    assert raised.value.code == "approval_store_required"
    assert raised.value.path == "approval_store"


def reviewed_rule(catalog: ToolCatalog, *, allowed_scopes: tuple[str, ...]) -> ToolPolicyRule:
    manifest = catalog.manifests[0]
    reviewed_fingerprint = tool_policy_fingerprint(manifest)
    return ToolPolicyRule(
        tool_name=manifest.metadata.name,
        reviewed_fingerprint=reviewed_fingerprint,
        allowed_scopes=allowed_scopes,
        state=ToolPolicyState.ACTIVE,
        review=ToolReview(
            review_id="review-example",
            author_subject="author-example",
            reviewer_subject="reviewer-example",
            reviewed_fingerprint=reviewed_fingerprint,
        ),
    )


def test_write_requires_and_propagates_a_stable_idempotency_key() -> None:
    async def exercise() -> None:
        tool = PolicyTool(
            name="orders.update",
            effect=ToolEffect.WRITE,
            required_scopes=("orders:write",),
        )
        catalog = ToolCatalog([tool])
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:write",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:write",)),),
            audit_sink=audit,
        )

        with pytest.raises(RuntimeFailure) as missing_key:
            await policy.authorize(
                tool=tool,
                arguments={"value": "first"},
                context=context(scopes=("orders:write",)),
            )
        trusted_context = context(
            scopes=("orders:write",),
            idempotency_key="idempotency-example",
        )
        await policy.authorize(
            tool=tool,
            arguments={"value": "second"},
            context=trusted_context,
        )

        assert missing_key.value.code is ErrorCode.CONFLICT
        assert [event.decision for event in audit.events] == [
            ToolPolicyDecision.IDEMPOTENCY_REQUIRED,
            ToolPolicyDecision.ALLOWED,
        ]
        assert audit.events[0].idempotency_key_hash is None
        assert audit.events[1].idempotency_key_hash is not None
        assert "idempotency-example" not in repr(audit.events[1])

    asyncio.run(exercise())


def test_one_time_approval_is_bound_to_the_exact_action_and_consumed_once() -> None:
    async def exercise() -> None:
        tool = PolicyTool(
            name="orders.notify",
            effect=ToolEffect.EXTERNAL_EFFECT,
            approval=ApprovalRequirement.REQUIRED,
            required_scopes=("orders:notify",),
        )
        catalog = ToolCatalog([tool])
        arguments = {"value": "send"}
        record = ApprovalRecord.for_action(
            approval_id="approval-example",
            tenant="tenant-blue",
            subject="subject-example",
            manifest=catalog.manifests[0],
            arguments=arguments,
            expires_at=110.0,
            use=ApprovalUse.ONE_TIME,
        )
        approvals = ApprovalMemoryStore((record,))
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:notify",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:notify",)),),
            approval_store=approvals,
            audit_sink=audit,
            wall_clock=lambda: 100.0,
        )

        with pytest.raises(RuntimeFailure) as missing:
            await policy.authorize(
                tool=tool,
                arguments={**arguments, "confirm": True},
                context=context(
                    scopes=("orders:notify",),
                    idempotency_key="idempotency-missing-approval",
                ),
            )
        approved_context = context(
            scopes=("orders:notify",),
            idempotency_key="idempotency-approved",
            approval_id="approval-example",
        )
        await policy.authorize(
            tool=tool,
            arguments=arguments,
            context=approved_context,
        )
        with pytest.raises(RuntimeFailure) as replayed:
            await policy.authorize(
                tool=tool,
                arguments=arguments,
                context=approved_context,
            )

        assert missing.value.code is ErrorCode.APPROVAL_REQUIRED
        assert replayed.value.code is ErrorCode.APPROVAL_REQUIRED
        assert approvals.consume_calls == [
            ("approval-example", record.action_fingerprint),
            ("approval-example", record.action_fingerprint),
        ]
        assert [event.decision for event in audit.events] == [
            ToolPolicyDecision.APPROVAL_REQUIRED,
            ToolPolicyDecision.ALLOWED,
            ToolPolicyDecision.APPROVAL_DENIED,
        ]

    asyncio.run(exercise())


def test_unknown_approval_identifier_is_denied_without_consumption() -> None:
    async def exercise() -> None:
        tool = PolicyTool(
            name="orders.unknown-approval",
            effect=ToolEffect.WRITE,
            approval=ApprovalRequirement.REQUIRED,
            required_scopes=("orders:write",),
        )
        catalog = ToolCatalog([tool])
        approvals = ApprovalMemoryStore(())
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:write",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:write",)),),
            approval_store=approvals,
            audit_sink=audit,
            wall_clock=lambda: 100.0,
        )

        with pytest.raises(RuntimeFailure) as denied:
            await policy.authorize(
                tool=tool,
                arguments={"value": "update"},
                context=context(
                    scopes=("orders:write",),
                    idempotency_key="idempotency-unknown-approval",
                    approval_id="approval-unknown",
                ),
            )

        assert denied.value.code is ErrorCode.APPROVAL_REQUIRED
        assert approvals.consume_calls == []
        assert [event.decision for event in audit.events] == [ToolPolicyDecision.APPROVAL_DENIED]

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "boundary",
    ["tenant", "subject", "tool", "arguments", "expired"],
)
def test_approval_rejects_every_cross_action_and_expiry_boundary(boundary: str) -> None:
    async def exercise() -> None:
        tool = PolicyTool(
            name="orders.notify",
            effect=ToolEffect.EXTERNAL_EFFECT,
            approval=ApprovalRequirement.REQUIRED,
            required_scopes=("orders:notify",),
        )
        catalog = ToolCatalog([tool])
        record_manifest = catalog.manifests[0]
        if boundary == "tool":
            record_manifest = ToolCatalog(
                [
                    PolicyTool(
                        name="orders.notify-other",
                        effect=ToolEffect.EXTERNAL_EFFECT,
                        approval=ApprovalRequirement.REQUIRED,
                        required_scopes=("orders:notify",),
                    )
                ]
            ).manifests[0]
        record_arguments = {"value": "different" if boundary == "arguments" else "send"}
        record = ApprovalRecord.for_action(
            approval_id="approval-boundary",
            tenant="tenant-blue",
            subject="subject-example",
            manifest=record_manifest,
            arguments=record_arguments,
            expires_at=100.0 if boundary == "expired" else 110.0,
            use=ApprovalUse.ONE_TIME,
        )
        approvals = ApprovalMemoryStore((record,))
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:notify",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:notify",)),),
            approval_store=approvals,
            audit_sink=audit,
            wall_clock=lambda: 100.0,
        )

        with pytest.raises(RuntimeFailure) as denied:
            await policy.authorize(
                tool=tool,
                arguments={"value": "send"},
                context=context(
                    scopes=("orders:notify",),
                    tenant="tenant-red" if boundary == "tenant" else "tenant-blue",
                    subject=("subject-other" if boundary == "subject" else "subject-example"),
                    idempotency_key="idempotency-boundary",
                    approval_id="approval-boundary",
                ),
            )

        assert denied.value.code is ErrorCode.APPROVAL_REQUIRED
        assert approvals.consume_calls == []
        assert [event.decision for event in audit.events] == [ToolPolicyDecision.APPROVAL_DENIED]

    asyncio.run(exercise())


def test_reusable_approval_can_repeat_only_until_its_expiry() -> None:
    async def exercise() -> None:
        tool = PolicyTool(
            name="orders.repeat-notification",
            effect=ToolEffect.EXTERNAL_EFFECT,
            approval=ApprovalRequirement.REQUIRED,
            required_scopes=("orders:notify",),
        )
        catalog = ToolCatalog([tool])
        arguments = {"value": "send"}
        record = ApprovalRecord.for_action(
            approval_id="approval-reusable",
            tenant="tenant-blue",
            subject="subject-example",
            manifest=catalog.manifests[0],
            arguments=arguments,
            expires_at=110.0,
            use=ApprovalUse.REUSABLE,
        )
        approvals = ApprovalMemoryStore((record,))
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:notify",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:notify",)),),
            approval_store=approvals,
            audit_sink=audit,
            wall_clock=lambda: 100.0,
        )
        approved_context = context(
            scopes=("orders:notify",),
            idempotency_key="idempotency-reusable",
            approval_id="approval-reusable",
        )

        await policy.authorize(tool=tool, arguments=arguments, context=approved_context)
        await policy.authorize(tool=tool, arguments=arguments, context=approved_context)

        assert approvals.consume_calls == []
        assert [event.decision for event in audit.events] == [
            ToolPolicyDecision.ALLOWED,
            ToolPolicyDecision.ALLOWED,
        ]

    asyncio.run(exercise())


def test_approval_backend_failure_fails_closed_and_emits_a_safe_fault_decision() -> None:
    async def exercise() -> None:
        tool = PolicyTool(
            name="orders.notify-failure",
            effect=ToolEffect.EXTERNAL_EFFECT,
            approval=ApprovalRequirement.REQUIRED,
            required_scopes=("orders:notify",),
        )
        catalog = ToolCatalog([tool])
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:notify",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:notify",)),),
            approval_store=FailingApprovalStore(()),
            audit_sink=audit,
            wall_clock=lambda: 100.0,
        )

        with pytest.raises(RuntimeFailure) as failed:
            await policy.authorize(
                tool=tool,
                arguments={"value": "send"},
                context=context(
                    scopes=("orders:notify",),
                    idempotency_key="idempotency-failure",
                    approval_id="approval-failure",
                ),
            )

        assert failed.value.code is ErrorCode.UNAVAILABLE
        assert [event.decision for event in audit.events] == [
            ToolPolicyDecision.POLICY_BACKEND_UNAVAILABLE
        ]
        assert "approval-backend-secret" not in repr(audit.events)

    asyncio.run(exercise())


def test_approval_consume_failure_fails_closed_and_never_becomes_reusable() -> None:
    async def exercise() -> None:
        tool = PolicyTool(
            name="orders.consume-failure",
            effect=ToolEffect.WRITE,
            approval=ApprovalRequirement.REQUIRED,
            required_scopes=("orders:write",),
        )
        catalog = ToolCatalog([tool])
        arguments = {"value": "update"}
        record = ApprovalRecord.for_action(
            approval_id="approval-consume-failure",
            tenant="tenant-blue",
            subject="subject-example",
            manifest=catalog.manifests[0],
            arguments=arguments,
            expires_at=110.0,
            use=ApprovalUse.ONE_TIME,
        )
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:write",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:write",)),),
            approval_store=FailingConsumeApprovalStore((record,)),
            audit_sink=audit,
            wall_clock=lambda: 100.0,
        )

        with pytest.raises(RuntimeFailure) as failed:
            await policy.authorize(
                tool=tool,
                arguments=arguments,
                context=context(
                    scopes=("orders:write",),
                    idempotency_key="idempotency-consume-failure",
                    approval_id="approval-consume-failure",
                ),
            )

        assert failed.value.code is ErrorCode.UNAVAILABLE
        assert [event.decision for event in audit.events] == [
            ToolPolicyDecision.POLICY_BACKEND_UNAVAILABLE
        ]
        assert "approval-consume-secret" not in repr(audit.events)

    asyncio.run(exercise())


def test_policy_audit_event_contains_identifiers_and_hashes_but_no_payload() -> None:
    async def exercise() -> None:
        tool = PolicyTool(
            name="orders.audit-update",
            effect=ToolEffect.WRITE,
            required_scopes=("orders:write",),
        )
        catalog = ToolCatalog([tool])
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:write",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:write",)),),
            audit_sink=audit,
            wall_clock=lambda: 100.0,
        )

        await policy.authorize(
            tool=tool,
            arguments={"value": "payload-secret-marker"},
            context=context(
                scopes=("orders:write",),
                subject="subject-private-marker",
                idempotency_key="idempotency-private-marker",
            ),
        )

        assert len(audit.events) == 1
        document = json.dumps(audit.events[0].to_dict(), sort_keys=True)
        assert set(audit.events[0].to_dict()) == {
            "approval_id",
            "decision",
            "effect",
            "idempotency_key_hash",
            "occurred_at",
            "request_id",
            "run_id",
            "scopes",
            "subject_hash",
            "tenant",
            "tool_fingerprint",
            "tool_name",
        }
        for private_value in (
            "payload-secret-marker",
            "subject-private-marker",
            "idempotency-private-marker",
        ):
            assert private_value not in document

    asyncio.run(exercise())


def test_audit_sink_failure_fails_closed_without_leaking_sink_details() -> None:
    async def exercise() -> None:
        tool = PolicyTool()
        catalog = ToolCatalog([tool])
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:read",),
            rules=(
                ToolPolicyRule(
                    tool_name=tool.metadata.name,
                    reviewed_fingerprint=tool_policy_fingerprint(catalog.manifests[0]),
                    allowed_scopes=("orders:read",),
                    state=ToolPolicyState.ACTIVE,
                ),
            ),
            audit_sink=FailingAuditSink(),
        )

        with pytest.raises(RuntimeFailure) as failed:
            await policy.authorize(
                tool=tool,
                arguments={"value": "never-runs"},
                context=context(scopes=("orders:read",)),
            )

        assert failed.value.code is ErrorCode.UNAVAILABLE
        assert "audit-sink-secret" not in repr(failed.value)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "wall_clock",
    [failing_wall_clock, lambda: float("nan"), lambda: -1.0],
    ids=["exception", "non-finite", "negative"],
)
def test_policy_clock_failure_fails_closed_before_a_decision_is_appended(
    wall_clock: Callable[[], float],
) -> None:
    async def exercise() -> None:
        tool = PolicyTool()
        catalog = ToolCatalog([tool])
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:read",),
            rules=(
                ToolPolicyRule(
                    tool_name=tool.metadata.name,
                    reviewed_fingerprint=tool_policy_fingerprint(catalog.manifests[0]),
                    allowed_scopes=("orders:read",),
                    state=ToolPolicyState.ACTIVE,
                ),
            ),
            audit_sink=audit,
            wall_clock=wall_clock,
        )

        with pytest.raises(RuntimeFailure) as failed:
            await policy.authorize(
                tool=tool,
                arguments={"value": "never-runs"},
                context=context(scopes=("orders:read",)),
            )

        assert failed.value.code is ErrorCode.UNAVAILABLE
        assert "wall-clock-secret" not in repr(failed.value)
        assert audit.events == []

    asyncio.run(exercise())


def test_unknown_and_experimental_tools_are_unlisted_and_indistinguishable() -> None:
    async def exercise() -> None:
        active = PolicyTool(name="orders.active")
        experimental = PolicyTool(name="orders.experimental")
        catalog = ToolCatalog([active, experimental])
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:read",),
            rules=(
                ToolPolicyRule(
                    tool_name="orders.active",
                    reviewed_fingerprint=tool_policy_fingerprint(catalog.manifests[0]),
                    allowed_scopes=("orders:read",),
                    state=ToolPolicyState.ACTIVE,
                ),
                ToolPolicyRule(
                    tool_name="orders.experimental",
                    reviewed_fingerprint=tool_policy_fingerprint(catalog.manifests[1]),
                    allowed_scopes=("orders:read",),
                ),
            ),
            audit_sink=audit,
        )
        transport = InProcessTransport()
        telemetry = RecordingErrorTelemetry()
        application = Application(
            catalog=catalog,
            authorizer=policy,
            transport=transport,
            telemetry=telemetry,
            limits=ApplicationLimits(drain_timeout=1.0),
            clock=SystemClock(),
        )
        await application.start()

        listed = await transport.list_tools()
        manifests = application.list_tool_manifests()
        unknown = await transport.invoke(
            "orders.unknown",
            {"value": "same"},
            context=context(scopes=("orders:read",)),
        )
        unexported = await transport.invoke(
            "orders.experimental",
            {"value": "same"},
            context=context(scopes=("orders:read",)),
        )

        assert listed == ("orders.active",)
        assert tuple(manifest.metadata.name for manifest in manifests) == ("orders.active",)
        assert unknown == unexported
        assert unknown.error is not None
        assert unknown.error.code is ErrorCode.INVALID_INPUT
        assert [event.decision for event in audit.events] == [ToolPolicyDecision.POLICY_DENIED]

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_denied_tool_remains_unknown_when_audit_sink_is_unavailable() -> None:
    async def exercise() -> None:
        experimental = PolicyTool(name="orders.experimental")
        catalog = ToolCatalog([experimental])
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:read",),
            rules=(
                ToolPolicyRule(
                    tool_name=experimental.metadata.name,
                    reviewed_fingerprint=tool_policy_fingerprint(catalog.manifests[0]),
                    allowed_scopes=("orders:read",),
                ),
            ),
            audit_sink=FailingAuditSink(),
        )
        transport = InProcessTransport()
        application = Application(
            catalog=catalog,
            authorizer=policy,
            transport=transport,
            telemetry=RecordingErrorTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            clock=SystemClock(),
        )
        await application.start()

        call_context = context(scopes=("orders:read",))
        unknown = await transport.invoke(
            "orders.unknown",
            {"value": "same"},
            context=call_context,
        )
        unexported = await transport.invoke(
            experimental.metadata.name,
            {"value": "same"},
            context=call_context,
        )

        assert unknown == unexported
        assert unknown.error is not None
        assert unknown.error.code is ErrorCode.INVALID_INPUT

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_confirm_argument_never_substitutes_for_approval_or_runs_the_handler() -> None:
    async def exercise() -> None:
        handler = CountingPolicyHandler()
        tool = PolicyTool(
            name="orders.confirm-is-not-approval",
            effect=ToolEffect.EXTERNAL_EFFECT,
            approval=ApprovalRequirement.REQUIRED,
            required_scopes=("orders:notify",),
            handler=handler,
        )
        catalog = ToolCatalog([tool])
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:notify",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:notify",)),),
            approval_store=ApprovalMemoryStore(()),
            audit_sink=audit,
        )
        transport = InProcessTransport()
        telemetry = RecordingErrorTelemetry()
        application = Application(
            catalog=catalog,
            authorizer=policy,
            transport=transport,
            telemetry=telemetry,
            limits=ApplicationLimits(drain_timeout=1.0),
            clock=SystemClock(),
        )
        await application.start()

        result = await transport.invoke(
            "orders.confirm-is-not-approval",
            {"value": "send", "confirm": True},
            context=context(
                scopes=("orders:notify",),
                idempotency_key="idempotency-confirm",
            ),
        )

        assert result.error is not None
        assert result.error.code is ErrorCode.APPROVAL_REQUIRED
        assert handler.calls == 0
        assert [event.code for event in telemetry.events] == [ErrorCode.APPROVAL_REQUIRED]
        assert [event.decision for event in audit.events] == [ToolPolicyDecision.APPROVAL_REQUIRED]

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_concurrent_duplicate_write_returns_the_original_backing_result_once() -> None:
    async def exercise() -> None:
        backing_api = FakeIdempotentBackingAPI()
        tool = IdempotentWriteTool(backing_api)
        catalog = ToolCatalog([tool])
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:write",),
            rules=(reviewed_rule(catalog, allowed_scopes=("orders:write",)),),
            audit_sink=audit,
        )
        transport = InProcessTransport()
        application = Application(
            catalog=catalog,
            authorizer=policy,
            transport=transport,
            telemetry=RecordingErrorTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            clock=SystemClock(),
        )
        await application.start()
        first_context = context(
            scopes=("orders:write",),
            idempotency_key="idempotency-concurrent",
            request_id="request-first",
        )
        second_context = context(
            scopes=("orders:write",),
            idempotency_key="idempotency-concurrent",
            request_id="request-second",
        )

        async with asyncio.TaskGroup() as tasks:
            first = tasks.create_task(
                transport.invoke(
                    "orders.concurrent-update",
                    {"value": "updated"},
                    context=first_context,
                )
            )
            await backing_api.first_started.wait()
            second = tasks.create_task(
                transport.invoke(
                    "orders.concurrent-update",
                    {"value": "updated"},
                    context=second_context,
                )
            )
            await backing_api.duplicate_seen.wait()
            backing_api.release.set()

        assert first.result() == second.result()
        assert first.result().value == {"value": "effect-1:updated"}
        assert backing_api.effect_count == 1
        assert backing_api.received_keys == [
            "idempotency-concurrent",
            "idempotency-concurrent",
        ]
        assert [event.decision for event in audit.events] == [
            ToolPolicyDecision.ALLOWED,
            ToolPolicyDecision.ALLOWED,
        ]

        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_tool_cannot_replace_its_metadata_to_broaden_policy_at_runtime() -> None:
    async def exercise() -> None:
        active = PolicyTool(name="orders.active")
        experimental = PolicyTool(name="orders.experimental")
        catalog = ToolCatalog([active, experimental])
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:read",),
            rules=(
                ToolPolicyRule(
                    tool_name="orders.active",
                    reviewed_fingerprint=tool_policy_fingerprint(catalog.manifests[0]),
                    allowed_scopes=("orders:read",),
                    state=ToolPolicyState.ACTIVE,
                ),
            ),
            audit_sink=audit,
        )
        experimental.metadata = active.metadata

        with pytest.raises(RuntimeFailure) as denied:
            await policy.authorize(
                tool=experimental,
                arguments={"value": "forged"},
                context=context(scopes=("orders:read",)),
            )

        assert denied.value.code is ErrorCode.INVALID_INPUT
        assert [event.decision for event in audit.events] == [ToolPolicyDecision.POLICY_DENIED]

    asyncio.run(exercise())


def test_mutating_review_digest_cannot_be_reused_after_contract_change() -> None:
    reviewed_tool = PolicyTool(
        name="orders.reviewed-update",
        effect=ToolEffect.WRITE,
        required_scopes=("orders:write",),
    )
    reviewed_catalog = ToolCatalog([reviewed_tool])
    reviewed_fingerprint = tool_policy_fingerprint(reviewed_catalog.manifests[0])
    changed_tool = PolicyTool(
        name="orders.reviewed-update",
        effect=ToolEffect.WRITE,
        required_scopes=("orders:write", "tenant:member"),
    )
    changed_catalog = ToolCatalog([changed_tool])
    changed_fingerprint = tool_policy_fingerprint(changed_catalog.manifests[0])

    with pytest.raises(ToolPolicyConfigurationError) as raised:
        ToolPolicy(
            catalog=changed_catalog,
            server_scopes=("orders:write", "tenant:member"),
            rules=(
                ToolPolicyRule(
                    tool_name=changed_tool.metadata.name,
                    reviewed_fingerprint=changed_fingerprint,
                    allowed_scopes=("orders:write", "tenant:member"),
                    state=ToolPolicyState.ACTIVE,
                    review=ToolReview(
                        review_id="review-old-contract",
                        author_subject="author-example",
                        reviewer_subject="reviewer-example",
                        reviewed_fingerprint=reviewed_fingerprint,
                    ),
                ),
            ),
            audit_sink=RecordingAuditSink(),
        )

    assert raised.value.code == "review_mismatch"
    assert raised.value.path == "rules[0].review.reviewed_fingerprint"


@pytest.mark.parametrize(
    (
        "effect",
        "approval",
        "caller_scopes",
        "present_approval",
        "expected_code",
        "expected_decision",
    ),
    [
        pytest.param(
            ToolEffect.READ,
            ApprovalRequirement.NOT_REQUIRED,
            ("orders:read",),
            False,
            None,
            ToolPolicyDecision.ALLOWED,
            id="reader-can-read",
        ),
        pytest.param(
            ToolEffect.READ,
            ApprovalRequirement.NOT_REQUIRED,
            ("orders:write",),
            False,
            ErrorCode.INVALID_INPUT,
            ToolPolicyDecision.SCOPE_DENIED,
            id="writer-role-cannot-assume-reader-scope",
        ),
        pytest.param(
            ToolEffect.WRITE,
            ApprovalRequirement.NOT_REQUIRED,
            ("orders:write",),
            False,
            None,
            ToolPolicyDecision.ALLOWED,
            id="writer-can-write-with-key",
        ),
        pytest.param(
            ToolEffect.WRITE,
            ApprovalRequirement.NOT_REQUIRED,
            ("orders:read",),
            False,
            ErrorCode.INVALID_INPUT,
            ToolPolicyDecision.SCOPE_DENIED,
            id="reader-role-cannot-write",
        ),
        pytest.param(
            ToolEffect.WRITE,
            ApprovalRequirement.REQUIRED,
            ("orders:write",),
            False,
            ErrorCode.APPROVAL_REQUIRED,
            ToolPolicyDecision.APPROVAL_REQUIRED,
            id="approved-write-missing-approval",
        ),
        pytest.param(
            ToolEffect.WRITE,
            ApprovalRequirement.REQUIRED,
            ("orders:write",),
            True,
            None,
            ToolPolicyDecision.ALLOWED,
            id="approved-write-valid-approval",
        ),
        pytest.param(
            ToolEffect.EXTERNAL_EFFECT,
            ApprovalRequirement.REQUIRED,
            ("orders:notify",),
            False,
            ErrorCode.APPROVAL_REQUIRED,
            ToolPolicyDecision.APPROVAL_REQUIRED,
            id="external-effect-missing-approval",
        ),
        pytest.param(
            ToolEffect.EXTERNAL_EFFECT,
            ApprovalRequirement.REQUIRED,
            ("orders:notify",),
            True,
            None,
            ToolPolicyDecision.ALLOWED,
            id="external-effect-valid-approval",
        ),
    ],
)
def test_role_scope_effect_and_approval_matrix(
    effect: ToolEffect,
    approval: ApprovalRequirement,
    caller_scopes: tuple[str, ...],
    present_approval: bool,
    expected_code: ErrorCode | None,
    expected_decision: ToolPolicyDecision,
) -> None:
    async def exercise() -> None:
        required_scope = "orders:read" if effect is ToolEffect.READ else "orders:write"
        if effect is ToolEffect.EXTERNAL_EFFECT:
            required_scope = "orders:notify"
        tool = PolicyTool(
            name=f"orders.matrix-{effect.value}-{approval.value}",
            effect=effect,
            approval=approval,
            required_scopes=(required_scope,),
        )
        catalog = ToolCatalog([tool])
        arguments = {"value": "matrix"}
        record = ApprovalRecord.for_action(
            approval_id="approval-matrix",
            tenant="tenant-blue",
            subject="subject-example",
            manifest=catalog.manifests[0],
            arguments=arguments,
            expires_at=110.0,
            use=ApprovalUse.ONE_TIME,
        )
        approvals = ApprovalMemoryStore((record,))
        audit = RecordingAuditSink()
        policy = ToolPolicy(
            catalog=catalog,
            server_scopes=("orders:read", "orders:write", "orders:notify"),
            rules=(
                (
                    reviewed_rule(catalog, allowed_scopes=(required_scope,))
                    if effect is not ToolEffect.READ
                    else ToolPolicyRule(
                        tool_name=tool.metadata.name,
                        reviewed_fingerprint=tool_policy_fingerprint(catalog.manifests[0]),
                        allowed_scopes=(required_scope,),
                        state=ToolPolicyState.ACTIVE,
                    )
                ),
            ),
            approval_store=(approvals if approval is ApprovalRequirement.REQUIRED else None),
            audit_sink=audit,
            wall_clock=lambda: 100.0,
        )
        call_context = context(
            scopes=caller_scopes,
            idempotency_key=("idempotency-matrix" if effect is not ToolEffect.READ else None),
            approval_id="approval-matrix" if present_approval else None,
        )

        if expected_code is None:
            await policy.authorize(tool=tool, arguments=arguments, context=call_context)
        else:
            with pytest.raises(RuntimeFailure) as denied:
                await policy.authorize(tool=tool, arguments=arguments, context=call_context)
            assert denied.value.code is expected_code
        assert [event.decision for event in audit.events] == [expected_decision]

    asyncio.run(exercise())
