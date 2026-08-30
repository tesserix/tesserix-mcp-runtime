from __future__ import annotations

import math
from dataclasses import FrozenInstanceError, replace
from typing import Any

import pytest

from tesserix_mcp_runtime import (
    ApprovalRecord,
    ApprovalRequirement,
    ApprovalUse,
    IdempotencyRequirement,
    JsonValue,
    ToolEffect,
    ToolManifest,
    ToolMetadata,
    ToolPolicyAuditEvent,
    ToolPolicyDecision,
    ToolPolicyRule,
    ToolPolicyState,
    ToolReview,
    tool_policy_fingerprint,
)


def manifest(*, description: str = "Read one synthetic order.") -> ToolManifest:
    schema: dict[str, JsonValue] = {
        "type": "object",
        "properties": {"value": {"type": "string", "maxLength": 64}},
        "required": ["value"],
        "additionalProperties": False,
    }
    return ToolManifest(
        metadata=ToolMetadata(
            name="orders.read",
            title="Read an order",
            description=description,
            effect=ToolEffect.READ,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=IdempotencyRequirement.NOT_APPLICABLE,
            required_scopes=("orders:read",),
        ),
        normalized_name="orders.read",
        input_schema=schema,
        output_schema=schema,
    )


def approval_record() -> ApprovalRecord:
    return ApprovalRecord.for_action(
        approval_id="approval-example",
        tenant="tenant-blue",
        subject="subject-example",
        manifest=manifest(),
        arguments={"value": "example"},
        expires_at=100.0,
        use=ApprovalUse.ONE_TIME,
    )


def audit_event() -> ToolPolicyAuditEvent:
    return ToolPolicyAuditEvent(
        decision=ToolPolicyDecision.ALLOWED,
        request_id="request-example",
        run_id="run-example",
        tenant="tenant-blue",
        subject_hash="a" * 64,
        tool_name="orders.read",
        tool_fingerprint="b" * 64,
        effect=ToolEffect.READ,
        scopes=("orders:read",),
        approval_id=None,
        idempotency_key_hash=None,
        occurred_at=100.0,
    )


def test_tool_review_is_independent_and_bound_to_one_digest() -> None:
    digest = "a" * 64
    review = ToolReview(
        review_id="review-example",
        author_subject="author-example",
        reviewer_subject="reviewer-example",
        reviewed_fingerprint=digest,
    )

    assert review.reviewed_fingerprint == digest
    with pytest.raises(FrozenInstanceError):
        review.review_id = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError, match="independent"):
        replace(review, reviewer_subject="author-example")
    with pytest.raises(ValueError, match="SHA-256"):
        replace(review, reviewed_fingerprint="not-a-digest")
    for field in ("review_id", "author_subject", "reviewer_subject"):
        with pytest.raises(ValueError):
            replace(review, **{field: ""})


@pytest.mark.parametrize(
    "overrides",
    [
        {"approval_id": ""},
        {"action_fingerprint": "not-a-digest"},
        {"action_fingerprint": "0" * 64},
        {"expires_at": -1.0},
        {"expires_at": math.inf},
        {"expires_at": math.nan},
        {"expires_at": True},
        {"use": "sometimes"},
    ],
    ids=[
        "empty-id",
        "invalid-digest",
        "mismatched-digest",
        "negative-expiry",
        "infinite-expiry",
        "nan-expiry",
        "boolean-expiry",
        "invalid-use",
    ],
)
def test_approval_record_rejects_invalid_or_unbound_values(
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        replace(approval_record(), **overrides)


def test_approval_record_repr_redacts_bound_identifiers() -> None:
    record = approval_record()

    assert "subject-example" not in repr(record)
    assert "approval-example" not in repr(record)


@pytest.mark.parametrize(
    "overrides",
    [
        {"tool_name": ""},
        {"reviewed_fingerprint": "not-a-digest"},
        {"allowed_scopes": ["orders:read"]},
        {"allowed_scopes": ("orders:read", "orders:read")},
        {"allowed_scopes": tuple(f"scope:{index}" for index in range(33))},
    ],
    ids=[
        "empty-tool",
        "invalid-fingerprint",
        "mutable-scopes",
        "duplicate-scopes",
        "excessive-scopes",
    ],
)
def test_tool_policy_rule_rejects_invalid_values(overrides: dict[str, Any]) -> None:
    values: dict[str, Any] = {
        "tool_name": "orders.read",
        "reviewed_fingerprint": "a" * 64,
        "allowed_scopes": ("orders:read",),
        "state": ToolPolicyState.ACTIVE,
    }
    values.update(overrides)

    with pytest.raises(ValueError):
        ToolPolicyRule(**values)


def test_policy_fingerprint_is_stable_and_binds_metadata() -> None:
    first = manifest()
    reordered = ToolManifest(
        metadata=first.metadata,
        normalized_name=first.normalized_name,
        input_schema={
            "required": ["value"],
            "additionalProperties": False,
            "properties": {"value": {"maxLength": 64, "type": "string"}},
            "type": "object",
        },
        output_schema=first.output_schema,
    )

    assert tool_policy_fingerprint(first) == tool_policy_fingerprint(reordered)
    assert tool_policy_fingerprint(first) != tool_policy_fingerprint(
        manifest(description="Changed reviewed behavior.")
    )
