from __future__ import annotations

import math
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from tesserix_mcp_runtime import AuthenticatedIdentity, CallContext, TraceContext


def test_call_context_separates_verified_identity_from_arguments() -> None:
    identity = AuthenticatedIdentity(
        tenant="tenant-example",
        subject="subject-example",
        issuer="https://identity.example.invalid",
        scopes=("orders:read",),
    )
    context = CallContext(
        identity=identity,
        request_id="request-example",
        run_id="run-example",
        trace_context=TraceContext(
            traceparent="00-00000000000000000000000000000001-0000000000000001-01"
        ),
        deadline=42.0,
        idempotency_key=None,
    )

    assert context.tenant == "tenant-example"
    assert context.subject == "subject-example"
    assert context.issuer == "https://identity.example.invalid"
    assert context.scopes == ("orders:read",)
    assert context.cancelled is False

    with pytest.raises(FrozenInstanceError):
        context.request_id = "changed"  # type: ignore[misc]

    model_arguments: dict[str, Any] = {
        "tenant": "tenant-other",
        "subject": "model-controlled",
        "issuer": "https://untrusted.example.invalid",
        "scopes": ["orders:write"],
        "request_id": "argument-controlled",
        "run_id": "argument-controlled",
    }
    with pytest.raises(TypeError):
        CallContext(**model_arguments)


@pytest.mark.parametrize(
    ("traceparent", "tracestate"),
    [
        ("not-a-traceparent", None),
        ("00-00000000000000000000000000000000-0000000000000001-01", None),
        ("00-00000000000000000000000000000001-0000000000000000-01", None),
        (None, "vendor=value"),
        (
            "00-00000000000000000000000000000001-0000000000000001-01",
            "vendor=" + "v" * 513,
        ),
        (
            "00-00000000000000000000000000000001-0000000000000001-01",
            "vendor=value,vendor=duplicate",
        ),
        (
            "00-00000000000000000000000000000001-0000000000000001-01",
            "vendor=bad=value",
        ),
    ],
    ids=[
        "malformed-traceparent",
        "zero-trace-id",
        "zero-parent-id",
        "orphan-tracestate",
        "oversized-tracestate",
        "duplicate-tracestate-key",
        "forbidden-tracestate-character",
    ],
)
def test_trace_context_rejects_malformed_or_unbounded_fields(
    traceparent: str | None,
    tracestate: str | None,
) -> None:
    with pytest.raises(ValueError):
        TraceContext(traceparent=traceparent, tracestate=tracestate)


def test_trace_context_exposes_valid_propagation_as_an_immutable_mapping() -> None:
    context = TraceContext(
        traceparent="00-22222222222222222222222222222222-2222222222222222-01",
        tracestate="vendor=value,tenant@system=opaque",
    )

    propagation = context.as_mapping()

    assert dict(propagation) == {
        "traceparent": "00-22222222222222222222222222222222-2222222222222222-01",
        "tracestate": "vendor=value,tenant@system=opaque",
    }
    with pytest.raises(TypeError):
        propagation["traceparent"] = "changed"  # type: ignore[index]


@pytest.mark.parametrize(
    "identity_values",
    [
        {
            "tenant": "",
            "subject": "subject-example",
            "issuer": "https://identity.example.invalid",
            "scopes": (),
        },
        {
            "tenant": "tenant-example",
            "subject": " subject-example",
            "issuer": "https://identity.example.invalid",
            "scopes": (),
        },
        {
            "tenant": "tenant-example",
            "subject": "subject-example",
            "issuer": "",
            "scopes": (),
        },
        {
            "tenant": "tenant-example",
            "subject": "subject-example",
            "issuer": "https://identity.example.invalid",
            "scopes": ["orders:read"],
        },
        {
            "tenant": "tenant-example",
            "subject": "subject-example",
            "issuer": "https://identity.example.invalid",
            "scopes": ("orders:read", "orders:read"),
        },
    ],
    ids=[
        "empty-tenant",
        "padded-subject",
        "empty-issuer",
        "mutable-scopes",
        "duplicate-scopes",
    ],
)
def test_authenticated_identity_rejects_ambiguous_or_mutable_values(
    identity_values: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        AuthenticatedIdentity(**identity_values)


@pytest.mark.parametrize(
    "overrides",
    [
        {"identity": {"tenant": "model-controlled"}},
        {"request_id": ""},
        {"run_id": " run-example"},
        {"trace_context": {"traceparent": "model-controlled"}},
        {"deadline": -1.0},
        {"deadline": math.inf},
        {"deadline": math.nan},
        {"idempotency_key": ""},
        {"approval_id": ""},
        {"cancellation": {"cancelled": False}},
    ],
    ids=[
        "unverified-identity",
        "empty-request",
        "padded-run",
        "mutable-trace",
        "negative-deadline",
        "infinite-deadline",
        "nan-deadline",
        "empty-idempotency-key",
        "empty-approval-id",
        "invalid-cancellation",
    ],
)
def test_call_context_rejects_invalid_authority_fields(
    overrides: dict[str, Any],
) -> None:
    values: dict[str, Any] = {
        "identity": AuthenticatedIdentity(
            tenant="tenant-example",
            subject="subject-example",
            issuer="https://identity.example.invalid",
            scopes=(),
        ),
        "request_id": "request-example",
        "run_id": "run-example",
    }
    values.update(overrides)

    with pytest.raises(ValueError):
        CallContext(**values)
