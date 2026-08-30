from __future__ import annotations

from dataclasses import replace

import pytest

from tesserix_mcp_runtime import ExecutionLimits


def test_execution_limits_have_safe_finite_defaults() -> None:
    limits = ExecutionLimits()

    assert limits.max_input_bytes == 65_536
    assert limits.max_result_bytes == 524_288
    assert limits.max_json_depth == 16
    assert limits.max_object_properties == 128
    assert limits.max_array_items == 1_024
    assert limits.max_json_nodes == 4_096
    assert limits.max_tools == 128
    assert limits.max_global_concurrency == 64
    assert limits.max_server_concurrency == 64
    assert limits.max_tool_concurrency == 32
    assert limits.max_tenant_concurrency == 16
    assert limits.max_call_seconds == 30.0
    assert limits.max_tool_seconds == 30.0
    assert limits.cancellation_grace_seconds == 1.0
    assert limits.max_attempts == 3
    assert limits.retry_base_delay_seconds == 0.05
    assert limits.retry_max_delay_seconds == 0.5


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_input_bytes", 65_537),
        ("max_result_bytes", 524_289),
        ("max_json_depth", 33),
        ("max_object_properties", 257),
        ("max_array_items", 4_097),
        ("max_json_nodes", 16_385),
        ("max_tools", 129),
        ("max_global_concurrency", 257),
        ("max_server_concurrency", 257),
        ("max_tool_concurrency", 129),
        ("max_tenant_concurrency", 65),
        ("max_call_seconds", 300.001),
        ("max_tool_seconds", 300.001),
        ("cancellation_grace_seconds", 5.001),
        ("max_attempts", 6),
        ("retry_base_delay_seconds", 1.001),
        ("retry_max_delay_seconds", 5.001),
    ],
)
def test_execution_limits_reject_values_above_server_enforced_maxima(
    field: str,
    value: int | float,
) -> None:
    with pytest.raises(ValueError, match=field):
        replace(
            ExecutionLimits(),
            **{field: value},  # type: ignore[arg-type]  # parametrized dataclass field
        )


@pytest.mark.parametrize(
    "value",
    [0, -1, True],
    ids=["zero", "negative", "boolean"],
)
def test_execution_limits_reject_non_positive_or_ambiguous_values(
    value: int | bool,
) -> None:
    for field in (
        "max_input_bytes",
        "max_result_bytes",
        "max_json_depth",
        "max_object_properties",
        "max_array_items",
        "max_json_nodes",
        "max_tools",
        "max_global_concurrency",
        "max_server_concurrency",
        "max_tool_concurrency",
        "max_tenant_concurrency",
        "max_attempts",
    ):
        with pytest.raises(ValueError, match=field):
            replace(ExecutionLimits(), **{field: value})
