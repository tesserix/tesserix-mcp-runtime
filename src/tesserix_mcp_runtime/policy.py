from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Never, Protocol, Self, cast, runtime_checkable

from tesserix_mcp_runtime.contracts import (
    ApprovalRequirement,
    CallContext,
    ErrorCode,
    JsonValue,
    ToolDefinition,
    ToolEffect,
)
from tesserix_mcp_runtime.contracts import require_text as _require_text
from tesserix_mcp_runtime.contracts import runtime_instance as _is_runtime_instance
from tesserix_mcp_runtime.errors import RuntimeFailure
from tesserix_mcp_runtime.redaction import DEFAULT_REDACTION_POLICY, RedactionPolicy
from tesserix_mcp_runtime.tool import ToolCatalog
from tesserix_mcp_runtime.tool_manifest import (
    ToolManifest,
)
from tesserix_mcp_runtime.tool_manifest import canonical_json as _canonical_json
from tesserix_mcp_runtime.tool_manifest import digest_text as _digest

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _require_text_tuple(name: str, values: object) -> None:
    if not isinstance(values, tuple):
        raise ValueError(f"{name} must be a bounded immutable tuple")
    items = cast(tuple[object, ...], values)
    if len(items) > 32:
        raise ValueError(f"{name} must be a bounded immutable tuple")
    for value in items:
        _require_text(name, value, maximum=256)
    if len(set(items)) != len(items):
        raise ValueError(f"{name} must not contain duplicates")


def _canonical_fingerprint(value: Mapping[str, JsonValue]) -> str:
    return _digest(_canonical_json(value))


class ToolPolicyState(StrEnum):
    EXPERIMENTAL = "experimental"
    ACTIVE = "active"
    DISABLED = "disabled"


class ApprovalUse(StrEnum):
    ONE_TIME = "one_time"
    REUSABLE = "reusable"


class ToolPolicyDecision(StrEnum):
    ALLOWED = "allowed"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_REQUIRED = "approval_required"
    IDEMPOTENCY_REQUIRED = "idempotency_required"
    POLICY_BACKEND_UNAVAILABLE = "policy_backend_unavailable"
    POLICY_DENIED = "policy_denied"
    SCOPE_DENIED = "scope_denied"


class ToolPolicyConfigurationError(ValueError):
    def __init__(self, *, code: str, path: str) -> None:
        self.code = code
        self.path = path
        super().__init__(code)


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolReview:
    review_id: str
    author_subject: str
    reviewer_subject: str
    reviewed_fingerprint: str

    def __post_init__(self) -> None:
        _require_text("review_id", self.review_id, maximum=256)
        _require_text("author_subject", self.author_subject, maximum=512)
        _require_text("reviewer_subject", self.reviewer_subject, maximum=512)
        if self.author_subject == self.reviewer_subject:
            raise ValueError("review must be independent")
        if _DIGEST.fullmatch(self.reviewed_fingerprint) is None:
            raise ValueError("reviewed_fingerprint must be a lowercase SHA-256 digest")


def _approval_action_fingerprint(
    *,
    tenant: str,
    subject: str,
    tool_name: str,
    tool_fingerprint: str,
    arguments_fingerprint: str,
) -> str:
    return _canonical_fingerprint(
        {
            "tenant": tenant,
            "subject": subject,
            "tool_name": tool_name,
            "tool_fingerprint": tool_fingerprint,
            "arguments_fingerprint": arguments_fingerprint,
        }
    )


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ApprovalRecord:
    approval_id: str
    action_fingerprint: str
    tenant: str
    subject: str
    tool_name: str
    tool_fingerprint: str
    arguments_fingerprint: str
    expires_at: float
    use: ApprovalUse

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("approval_id", self.approval_id, 256),
            ("tenant", self.tenant, 256),
            ("subject", self.subject, 512),
            ("tool_name", self.tool_name, 128),
        ):
            _require_text(name, value, maximum=maximum)
        for name, value in (
            ("action_fingerprint", self.action_fingerprint),
            ("tool_fingerprint", self.tool_fingerprint),
            ("arguments_fingerprint", self.arguments_fingerprint),
        ):
            if not _is_runtime_instance(value, str) or _DIGEST.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        expected = _approval_action_fingerprint(
            tenant=self.tenant,
            subject=self.subject,
            tool_name=self.tool_name,
            tool_fingerprint=self.tool_fingerprint,
            arguments_fingerprint=self.arguments_fingerprint,
        )
        if self.action_fingerprint != expected:
            raise ValueError("action_fingerprint must bind the exact approval fields")
        if (
            isinstance(self.expires_at, bool)
            or not (
                _is_runtime_instance(self.expires_at, int)
                or _is_runtime_instance(self.expires_at, float)
            )
            or not math.isfinite(self.expires_at)
            or self.expires_at < 0
        ):
            raise ValueError("expires_at must be a finite non-negative timestamp")
        if not _is_runtime_instance(self.use, ApprovalUse):
            raise ValueError("use must be an ApprovalUse")

    @classmethod
    def for_action(
        cls,
        *,
        approval_id: str,
        tenant: str,
        subject: str,
        manifest: ToolManifest,
        arguments: Mapping[str, JsonValue],
        expires_at: float,
        use: ApprovalUse,
    ) -> Self:
        tool_fingerprint = tool_policy_fingerprint(manifest)
        arguments_fingerprint = _canonical_fingerprint(arguments)
        action_fingerprint = _approval_action_fingerprint(
            tenant=tenant,
            subject=subject,
            tool_name=manifest.metadata.name,
            tool_fingerprint=tool_fingerprint,
            arguments_fingerprint=arguments_fingerprint,
        )
        return cls(
            approval_id=approval_id,
            action_fingerprint=action_fingerprint,
            tenant=tenant,
            subject=subject,
            tool_name=manifest.metadata.name,
            tool_fingerprint=tool_fingerprint,
            arguments_fingerprint=arguments_fingerprint,
            expires_at=expires_at,
            use=use,
        )


@runtime_checkable
class ApprovalStore(Protocol):
    async def fetch(self, *, approval_id: str) -> ApprovalRecord | None: ...

    async def consume(self, *, approval_id: str, action_fingerprint: str) -> bool: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolPolicyRule:
    tool_name: str
    reviewed_fingerprint: str
    allowed_scopes: tuple[str, ...]
    state: ToolPolicyState = ToolPolicyState.EXPERIMENTAL
    review: ToolReview | None = None

    def __post_init__(self) -> None:
        _require_text("tool_name", self.tool_name, maximum=128)
        if (
            not _is_runtime_instance(self.reviewed_fingerprint, str)
            or _DIGEST.fullmatch(self.reviewed_fingerprint) is None
        ):
            raise ValueError("reviewed_fingerprint must be a lowercase SHA-256 digest")
        _require_text_tuple("allowed_scopes", self.allowed_scopes)


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolPolicyAuditEvent:
    decision: ToolPolicyDecision
    request_id: str
    run_id: str
    tenant: str
    subject_hash: str
    tool_name: str
    tool_fingerprint: str
    effect: ToolEffect
    scopes: tuple[str, ...]
    approval_id: str | None
    idempotency_key_hash: str | None
    occurred_at: float

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "decision": self.decision.value,
            "request_id": self.request_id,
            "run_id": self.run_id,
            "tenant": self.tenant,
            "subject_hash": self.subject_hash,
            "tool_name": self.tool_name,
            "tool_fingerprint": self.tool_fingerprint,
            "effect": self.effect.value,
            "scopes": list(self.scopes),
            "approval_id": self.approval_id,
            "idempotency_key_hash": self.idempotency_key_hash,
            "occurred_at": self.occurred_at,
        }


@runtime_checkable
class ToolPolicyAuditSink(Protocol):
    def append(self, event: ToolPolicyAuditEvent) -> None: ...


def tool_policy_fingerprint(manifest: ToolManifest) -> str:
    return _canonical_fingerprint(manifest.to_dict())


class ToolPolicy:
    def __init__(
        self,
        *,
        catalog: ToolCatalog,
        server_scopes: tuple[str, ...],
        rules: Iterable[ToolPolicyRule],
        audit_sink: ToolPolicyAuditSink,
        approval_store: ApprovalStore | None = None,
        wall_clock: Callable[[], float] = time.time,
        redactor: RedactionPolicy = DEFAULT_REDACTION_POLICY,
    ) -> None:
        _require_text_tuple("server_scopes", server_scopes)
        if not _is_runtime_instance(audit_sink, ToolPolicyAuditSink):
            raise TypeError("audit_sink must implement ToolPolicyAuditSink")
        if approval_store is not None and not _is_runtime_instance(approval_store, ApprovalStore):
            raise TypeError("approval_store must implement ApprovalStore")
        if not _is_runtime_instance(redactor, RedactionPolicy):
            raise TypeError("redactor must implement RedactionPolicy")
        resolved_rules = tuple(rules)
        if len({rule.tool_name for rule in resolved_rules}) != len(resolved_rules):
            raise ValueError("rules must not contain duplicate tool names")

        catalog_manifests = catalog.manifests
        manifests = {manifest.metadata.name: manifest for manifest in catalog_manifests}
        fingerprints = {
            name: tool_policy_fingerprint(manifest) for name, manifest in manifests.items()
        }
        for index, rule in enumerate(resolved_rules):
            if rule.state is not ToolPolicyState.ACTIVE:
                continue
            manifest = manifests.get(rule.tool_name)
            if manifest is None:
                raise ToolPolicyConfigurationError(
                    code="unknown_tool",
                    path=f"rules[{index}].tool_name",
                )
            if fingerprints[rule.tool_name] != rule.reviewed_fingerprint:
                raise ToolPolicyConfigurationError(
                    code="review_mismatch",
                    path=f"rules[{index}].reviewed_fingerprint",
                )
            if manifest.metadata.effect is not ToolEffect.READ and rule.review is None:
                raise ToolPolicyConfigurationError(
                    code="independent_review_required",
                    path=f"rules[{index}].review",
                )
            if (
                rule.review is not None
                and rule.review.reviewed_fingerprint != rule.reviewed_fingerprint
            ):
                raise ToolPolicyConfigurationError(
                    code="review_mismatch",
                    path=f"rules[{index}].review.reviewed_fingerprint",
                )
            if (
                manifest.metadata.approval is ApprovalRequirement.REQUIRED
                and approval_store is None
            ):
                raise ToolPolicyConfigurationError(
                    code="approval_store_required",
                    path="approval_store",
                )

        self._server_scopes = frozenset(server_scopes)
        self._rules = {rule.tool_name: rule for rule in resolved_rules}
        self._fingerprints = fingerprints
        self._manifest_by_definition = {
            id(definition): manifest
            for definition, manifest in zip(catalog, catalog_manifests, strict=True)
        }
        self._audit_sink = audit_sink
        self._approval_store = approval_store
        self._wall_clock = wall_clock
        self._redactor = redactor

    def is_exported(self, tool_name: str) -> bool:
        rule = self._rules.get(tool_name)
        return rule is not None and rule.state is ToolPolicyState.ACTIVE

    async def authorize(
        self,
        *,
        tool: ToolDefinition[Any, Any],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        manifest = self._manifest_by_definition.get(id(tool))
        name = manifest.metadata.name if manifest is not None else tool.metadata.name
        rule = self._rules.get(name)
        if manifest is None or rule is None or rule.state is not ToolPolicyState.ACTIVE:
            self._deny(
                decision=ToolPolicyDecision.POLICY_DENIED,
                code=ErrorCode.INVALID_INPUT,
                manifest=manifest,
                context=context,
                fallback_tool=tool,
            )
        authority = set(context.scopes) & self._server_scopes & set(rule.allowed_scopes)
        if not set(manifest.metadata.required_scopes) <= authority:
            self._deny(
                decision=ToolPolicyDecision.SCOPE_DENIED,
                code=ErrorCode.INVALID_INPUT,
                manifest=manifest,
                context=context,
                fallback_tool=tool,
            )
        if manifest.metadata.effect is not ToolEffect.READ and context.idempotency_key is None:
            self._deny(
                decision=ToolPolicyDecision.IDEMPOTENCY_REQUIRED,
                code=ErrorCode.CONFLICT,
                manifest=manifest,
                context=context,
                fallback_tool=tool,
            )
        if manifest.metadata.approval is ApprovalRequirement.REQUIRED:
            await self._authorize_approval(
                manifest=manifest,
                arguments=arguments,
                context=context,
                fallback_tool=tool,
            )
        self._append(
            self._event(
                decision=ToolPolicyDecision.ALLOWED,
                manifest=manifest,
                context=context,
            )
        )

    def _deny(
        self,
        *,
        decision: ToolPolicyDecision,
        code: ErrorCode,
        manifest: ToolManifest | None,
        context: CallContext,
        fallback_tool: ToolDefinition[Any, Any],
    ) -> Never:
        resolved_manifest = manifest
        if resolved_manifest is None:
            metadata = fallback_tool.metadata
            fallback = ToolManifest(
                metadata=metadata,
                normalized_name=metadata.name.casefold(),
                input_schema=fallback_tool.input_schema,
                output_schema=fallback_tool.output_schema,
            )
            resolved_manifest = fallback
        try:
            self._append(
                self._event(
                    decision=decision,
                    manifest=resolved_manifest,
                    context=context,
                )
            )
        except RuntimeFailure:
            raise RuntimeFailure(code) from None
        raise RuntimeFailure(code)

    async def _authorize_approval(
        self,
        *,
        manifest: ToolManifest,
        arguments: Mapping[str, JsonValue],
        context: CallContext,
        fallback_tool: ToolDefinition[Any, Any],
    ) -> None:
        approval_id = context.approval_id
        if approval_id is None:
            self._deny(
                decision=ToolPolicyDecision.APPROVAL_REQUIRED,
                code=ErrorCode.APPROVAL_REQUIRED,
                manifest=manifest,
                context=context,
                fallback_tool=fallback_tool,
            )
        store = cast(ApprovalStore, self._approval_store)
        try:
            record = await store.fetch(approval_id=approval_id)
        except Exception:
            self._backend_unavailable(manifest=manifest, context=context)
        if not isinstance(record, ApprovalRecord):
            self._deny(
                decision=ToolPolicyDecision.APPROVAL_DENIED,
                code=ErrorCode.APPROVAL_REQUIRED,
                manifest=manifest,
                context=context,
                fallback_tool=fallback_tool,
            )
        arguments_fingerprint = _canonical_fingerprint(arguments)
        tool_fingerprint = self._fingerprints[manifest.metadata.name]
        action_fingerprint = _approval_action_fingerprint(
            tenant=context.tenant,
            subject=context.subject,
            tool_name=manifest.metadata.name,
            tool_fingerprint=tool_fingerprint,
            arguments_fingerprint=arguments_fingerprint,
        )
        if (
            record.approval_id != approval_id
            or record.tenant != context.tenant
            or record.subject != context.subject
            or record.tool_name != manifest.metadata.name
            or record.tool_fingerprint != tool_fingerprint
            or record.arguments_fingerprint != arguments_fingerprint
            or record.action_fingerprint != action_fingerprint
            or record.expires_at <= self._now()
        ):
            self._deny(
                decision=ToolPolicyDecision.APPROVAL_DENIED,
                code=ErrorCode.APPROVAL_REQUIRED,
                manifest=manifest,
                context=context,
                fallback_tool=fallback_tool,
            )
        if record.use is ApprovalUse.ONE_TIME:
            try:
                consumed = await store.consume(
                    approval_id=approval_id,
                    action_fingerprint=action_fingerprint,
                )
            except Exception:
                self._backend_unavailable(manifest=manifest, context=context)
            if not consumed:
                self._deny(
                    decision=ToolPolicyDecision.APPROVAL_DENIED,
                    code=ErrorCode.APPROVAL_REQUIRED,
                    manifest=manifest,
                    context=context,
                    fallback_tool=fallback_tool,
                )

    def _backend_unavailable(
        self,
        *,
        manifest: ToolManifest,
        context: CallContext,
    ) -> Never:
        self._append(
            self._event(
                decision=ToolPolicyDecision.POLICY_BACKEND_UNAVAILABLE,
                manifest=manifest,
                context=context,
            )
        )
        raise RuntimeFailure(ErrorCode.UNAVAILABLE)

    def _event(
        self,
        *,
        decision: ToolPolicyDecision,
        manifest: ToolManifest,
        context: CallContext,
    ) -> ToolPolicyAuditEvent:
        tool_fingerprint = self._fingerprints.get(manifest.metadata.name)
        if tool_fingerprint is None:
            tool_fingerprint = tool_policy_fingerprint(manifest)
        return ToolPolicyAuditEvent(
            decision=decision,
            request_id=self._redact_audit_text(context.request_id),
            run_id=self._redact_audit_text(context.run_id),
            tenant=self._redact_audit_text(context.tenant),
            subject_hash=_digest(context.subject),
            tool_name=self._redact_audit_text(manifest.metadata.name),
            tool_fingerprint=tool_fingerprint,
            effect=manifest.metadata.effect,
            scopes=tuple(self._redact_audit_text(scope) for scope in sorted(context.scopes)),
            approval_id=(
                self._redact_audit_text(context.approval_id)
                if context.approval_id is not None
                else None
            ),
            idempotency_key_hash=(
                _digest(context.idempotency_key) if context.idempotency_key is not None else None
            ),
            occurred_at=self._now(),
        )

    def _redact_audit_text(self, value: str) -> str:
        try:
            return self._redactor.redact_text(value)
        except Exception:
            raise RuntimeFailure(ErrorCode.UNAVAILABLE) from None

    def _now(self) -> float:
        try:
            now = self._wall_clock()
        except Exception:
            raise RuntimeFailure(ErrorCode.UNAVAILABLE) from None
        if (
            isinstance(now, bool)
            or not (_is_runtime_instance(now, int) or _is_runtime_instance(now, float))
            or not math.isfinite(now)
            or now < 0
        ):
            raise RuntimeFailure(ErrorCode.UNAVAILABLE)
        return now

    def _append(self, event: ToolPolicyAuditEvent) -> None:
        try:
            self._audit_sink.append(event)
        except Exception:
            raise RuntimeFailure(ErrorCode.UNAVAILABLE) from None


__all__ = [
    "ApprovalRecord",
    "ApprovalStore",
    "ApprovalUse",
    "ToolPolicy",
    "ToolPolicyAuditEvent",
    "ToolPolicyAuditSink",
    "ToolPolicyConfigurationError",
    "ToolPolicyDecision",
    "ToolPolicyRule",
    "ToolPolicyState",
    "ToolReview",
    "tool_policy_fingerprint",
]
