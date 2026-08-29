from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tesserix_mcp_runtime import (
    ErrorCode,
    ErrorResponse,
    InvocationResult,
    InvocationStatus,
    MappedError,
    Retryability,
    RuntimeFailure,
    ScrubbedError,
    TerminalEmitter,
    map_exception,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_every_stable_error_code_matches_the_golden_public_shape() -> None:
    assert {code.value for code in ErrorCode} == {
        "invalid_input",
        "unauthenticated",
        "forbidden",
        "approval_required",
        "conflict",
        "timeout",
        "cancelled",
        "unavailable",
        "internal_failure",
    }
    expected = json.loads((FIXTURES / "error-responses.json").read_text(encoding="utf-8"))

    actual = [
        ErrorResponse.from_code(code, request_id="request-example").to_dict() for code in ErrorCode
    ]

    assert actual == expected


def test_unknown_exception_maps_to_scrubbed_internal_failure() -> None:
    marker = "never-return-example-secret"

    mapped = map_exception(RuntimeError(marker), request_id="request-example")

    assert mapped.response.code is ErrorCode.INTERNAL_FAILURE
    assert mapped.response.message == "The operation failed."
    assert mapped.audit.to_dict() == {
        "code": "internal_failure",
        "exception_type": "RuntimeError",
        "request_id": "request-example",
    }
    serialized = json.dumps(
        {"response": mapped.response.to_dict(), "audit": mapped.audit.to_dict()}
    )
    assert marker not in serialized


def test_scrubbed_error_rejects_arbitrary_exception_text() -> None:
    with pytest.raises(ValueError):
        ScrubbedError(
            code=ErrorCode.INTERNAL_FAILURE,
            exception_type="RuntimeError: never-return-example-secret",
            request_id="request-example",
        )


def test_exception_mapping_normalizes_an_unsafe_dynamic_type_name() -> None:
    unsafe_error = type(
        "RuntimeError: never-return-example-secret",
        (Exception,),
        {},
    )()

    mapped = map_exception(unsafe_error, request_id="request-example")

    assert mapped.audit.exception_type == "Exception"


def test_mapped_error_requires_matching_public_and_audit_identity() -> None:
    response = ErrorResponse.from_code(
        ErrorCode.INTERNAL_FAILURE,
        request_id="request-example",
    )
    mismatched_audit = ScrubbedError(
        code=ErrorCode.UNAVAILABLE,
        exception_type="RuntimeError",
        request_id="request-other",
    )

    with pytest.raises(ValueError):
        MappedError(response=response, audit=mismatched_audit)


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (RuntimeFailure(ErrorCode.INVALID_INPUT), ErrorCode.INVALID_INPUT),
        (RuntimeFailure(ErrorCode.UNAUTHENTICATED), ErrorCode.UNAUTHENTICATED),
        (RuntimeFailure(ErrorCode.FORBIDDEN), ErrorCode.FORBIDDEN),
        (RuntimeFailure(ErrorCode.APPROVAL_REQUIRED), ErrorCode.APPROVAL_REQUIRED),
        (RuntimeFailure(ErrorCode.CONFLICT), ErrorCode.CONFLICT),
        (TimeoutError(), ErrorCode.TIMEOUT),
        (asyncio.CancelledError(), ErrorCode.CANCELLED),
        (RuntimeFailure(ErrorCode.UNAVAILABLE), ErrorCode.UNAVAILABLE),
    ],
)
def test_known_failures_map_to_their_stable_code(
    error: BaseException,
    expected_code: ErrorCode,
) -> None:
    mapped = map_exception(error, request_id="request-example")

    assert mapped.response.code is expected_code
    assert mapped.audit.code is expected_code


def test_error_response_rejects_arbitrary_public_text() -> None:
    with pytest.raises(ValueError):
        ErrorResponse(
            code=ErrorCode.INTERNAL_FAILURE,
            message="internal dependency detail",
            request_id="request-example",
            retryability=Retryability.NEVER,
        )


def test_invocation_result_has_exactly_one_terminal_shape() -> None:
    error = ErrorResponse.from_code(
        ErrorCode.CANCELLED,
        request_id="request-example",
    )

    assert InvocationResult.success(None) == InvocationResult(
        status=InvocationStatus.SUCCESS,
        value=None,
        error=None,
    )
    assert InvocationResult.failure(error) == InvocationResult(
        status=InvocationStatus.FAILURE,
        value=None,
        error=error,
    )
    with pytest.raises(ValueError):
        InvocationResult(
            status=InvocationStatus.SUCCESS,
            value={"unexpected": True},
            error=error,
        )
    with pytest.raises(ValueError):
        InvocationResult(
            status=InvocationStatus.FAILURE,
            value={"unexpected": True},
            error=None,
        )
    malformed_error: Any = object()
    with pytest.raises(ValueError):
        InvocationResult(
            status=InvocationStatus.FAILURE,
            value=None,
            error=malformed_error,
        )


def test_cancellation_racing_completion_emits_one_terminal_result() -> None:
    async def race() -> None:
        emitter = TerminalEmitter()
        ready = asyncio.Event()
        completed = InvocationResult.success({"status": "completed"})
        cancelled = InvocationResult.failure(
            ErrorResponse.from_code(
                ErrorCode.CANCELLED,
                request_id="request-example",
            )
        )

        async def contend(result: InvocationResult) -> bool:
            await ready.wait()
            return await emitter.emit(result)

        completed_task = asyncio.create_task(contend(completed))
        cancelled_task = asyncio.create_task(contend(cancelled))
        ready.set()
        accepted = await asyncio.gather(completed_task, cancelled_task)

        assert accepted.count(True) == 1
        assert accepted.count(False) == 1
        assert await emitter.result() in (completed, cancelled)

    asyncio.run(race())


@given(internal_text=st.text(max_size=1024))
def test_arbitrary_exception_text_never_enters_public_or_audit_data(
    internal_text: str,
) -> None:
    marker = f"private-marker:{internal_text}:end-private-marker"
    mapped = map_exception(RuntimeError(marker), request_id="request-example")

    assert marker not in mapped.response.to_dict().values()
    assert marker not in mapped.audit.to_dict().values()
