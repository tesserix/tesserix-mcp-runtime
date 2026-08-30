from __future__ import annotations

import json
from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tesserix_mcp_runtime import JsonValue
from tesserix_mcp_runtime.redaction import (
    RedactionError,
    RedactionLimits,
    RedactionPolicy,
    SecretRedactor,
    SecretValue,
)

CANARY = "synthetic-secret-canary-7Qv9"
REDACTED = "[REDACTED]"


def redactor(*, limits: RedactionLimits | None = None) -> SecretRedactor:
    return SecretRedactor(
        known_secrets=(SecretValue(CANARY),),
        limits=limits or RedactionLimits(),
    )


def test_secret_value_renders_redacted_by_construction() -> None:
    secret = SecretValue(CANARY)

    assert str(secret) == REDACTED
    assert repr(secret) == "SecretValue('[REDACTED]')"
    assert f"{secret}" == REDACTED
    assert format(secret, ">20").strip() == REDACTED
    assert CANARY not in repr(secret)
    assert secret.reveal() == CANARY


@pytest.mark.parametrize("value", ["", " ", "abc", REDACTED, "line\nbreak"])
def test_secret_value_rejects_values_that_are_not_bounded_credentials(value: str) -> None:
    with pytest.raises(ValueError, match="secret value"):
        SecretValue(value)


def test_redactor_removes_exact_secrets_and_sensitive_structured_shapes() -> None:
    original: dict[str, JsonValue] = {
        "safe": f"before {CANARY} after",
        "authorization": f"Bearer {CANARY}",
        "nested": [
            {"api_key": CANARY},
            {"dbPassword": CANARY},
            {CANARY: "key-canary"},
        ],
    }

    result = redactor().redact(original)
    document = json.dumps(result, sort_keys=True)

    assert CANARY not in document
    assert document.count(REDACTED) >= 5
    assert original["safe"] == f"before {CANARY} after"


@pytest.mark.parametrize(
    ("text", "visible_prefix"),
    [
        (f"Authorization: Bearer {CANARY}", "Authorization:"),
        (f"proxy-authorization=Basic {CANARY}", "proxy-authorization="),
        (f"access_token={CANARY}", "access_token="),
        (f'{{"refreshToken": "{CANARY}"}}', '"refreshToken":'),
        (f"credential: {CANARY}", "credential:"),
        ("eyJhbGciOiJIUzI1NiJ9.c3ludGhldGljLXBheWxvYWQ.c2lnbmF0dXJl", ""),
        (
            "-----BEGIN PRIVATE KEY-----\nsynthetic-material\n-----END PRIVATE KEY-----",
            "",
        ),
    ],
)
def test_text_redaction_handles_supported_secret_shapes(
    text: str,
    visible_prefix: str,
) -> None:
    result = redactor().redact_text(text)

    assert CANARY not in result
    assert "synthetic-material" not in result
    assert "eyJhbGci" not in result
    assert REDACTED in result
    assert visible_prefix in result


def test_redactor_uses_longest_exact_secret_first() -> None:
    policy = SecretRedactor(
        known_secrets=(
            SecretValue("synthetic-long-secret"),
            SecretValue("synthetic-long-secret-suffix"),
        )
    )

    assert policy.redact_text("synthetic-long-secret-suffix") == REDACTED
    assert "synthetic-long-secret" not in repr(policy)
    assert not hasattr(policy, "__dict__")


def test_default_redactor_removes_unlabelled_values_under_token_shaped_keys() -> None:
    result = SecretRedactor().redact(
        {
            "dependencyApiToken": "unlabelled-value",
            "awsAccessKeyId": "unlabelled-key",
        }
    )

    assert result == {
        "dependencyApiToken": REDACTED,
        "awsAccessKeyId": REDACTED,
    }


def test_redactor_resolves_redacted_key_collisions_without_leaking() -> None:
    result = redactor().redact({CANARY: "first", REDACTED: "second"})

    assert isinstance(result, dict)
    assert len(result) == 2
    assert CANARY not in json.dumps(result)


def test_redaction_policy_is_independently_replaceable() -> None:
    policy: RedactionPolicy = redactor()

    assert isinstance(policy, RedactionPolicy)
    assert policy.redact_text(CANARY) == REDACTED


def test_redactor_rejects_unsupported_runtime_values_without_rendering_them() -> None:
    unusual = cast(JsonValue, object())

    with pytest.raises(RedactionError) as captured:
        redactor().redact(unusual)

    assert CANARY not in str(captured.value)
    assert repr(unusual) not in str(captured.value)


def test_redactor_enforces_depth_node_and_text_ceilings() -> None:
    depth_policy = redactor(limits=RedactionLimits(max_depth=2))
    node_policy = redactor(limits=RedactionLimits(max_nodes=3))
    text_policy = redactor(limits=RedactionLimits(max_text_bytes=16))

    with pytest.raises(RedactionError, match="redaction limit exceeded"):
        depth_policy.redact({"one": {"two": {"three": CANARY}}})
    with pytest.raises(RedactionError, match="redaction limit exceeded"):
        node_policy.redact([1, 2, 3])
    with pytest.raises(RedactionError, match="redaction limit exceeded"):
        text_policy.redact_text("x" * 17)


@pytest.mark.parametrize(
    "limits",
    [
        RedactionLimits(max_depth=1),
        RedactionLimits(max_nodes=1),
        RedactionLimits(max_text_bytes=1),
    ],
)
def test_redaction_limits_accept_safe_lower_operator_bounds(limits: RedactionLimits) -> None:
    assert SecretRedactor(limits=limits).limits == limits


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_depth": 0},
        {"max_depth": 65},
        {"max_nodes": 0},
        {"max_nodes": 65_537},
        {"max_text_bytes": 0},
        {"max_text_bytes": 1_048_577},
    ],
)
def test_redaction_limits_reject_invalid_or_bypass_values(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="redaction limit"):
        RedactionLimits(**kwargs)


json_scalars = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(
        allow_nan=False,
        allow_infinity=False,
    )
    | st.text(max_size=32)
)
json_values = st.recursive(
    json_scalars,
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(st.text(min_size=1, max_size=16), children, max_size=4)
    ),
    max_leaves=24,
)


@given(json_values)
def test_structured_redaction_fuzz_never_releases_a_nested_canary(value: JsonValue) -> None:
    wrapped: JsonValue = {
        "payload": value,
        "credential": CANARY,
        "text": f"prefix {CANARY} suffix",
    }

    result = redactor().redact(wrapped)

    assert CANARY not in json.dumps(result, sort_keys=True, ensure_ascii=False)
