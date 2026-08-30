from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass

from tesserix_mcp_runtime import (
    Application,
    ApplicationLimits,
    ApprovalRequirement,
    AuthenticatedIdentity,
    CallContext,
    ErrorCode,
    IdempotencyRequirement,
    JsonValue,
    ScrubbedError,
    SystemClock,
    ToolCatalog,
    ToolEffect,
    ToolMetadata,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport
from tesserix_mcp_runtime.redaction import (
    RedactionLimits,
    RedactionPolicy,
    SecretRedactor,
    SecretValue,
)

CANARY = "SyntheticSecretCanary7Qv9"


@dataclass(frozen=True, slots=True)
class LeakInput:
    mode: str


@dataclass(frozen=True, slots=True)
class LeakOutput:
    value: JsonValue


class LeakHandler:
    async def __call__(
        self,
        input_model: LeakInput,
        *,
        context: CallContext,
    ) -> LeakOutput:
        del context
        if input_model.mode == "raise":
            exception_type = type(CANARY, (Exception,), {})
            raise exception_type(f"{CANARY} internal.example SQL httpx/0.28 traceback raw body")
        return LeakOutput(
            value={
                "authorization": f"Bearer {CANARY}",
                "nested": {"credential": CANARY},
            }
        )


class LeakTool:
    metadata = ToolMetadata(
        name="security.leak-probe",
        title="Leak probe",
        description="Return synthetic canaries for redaction verification.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("security:probe",),
    )
    input_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {"mode": {"type": "string", "maxLength": 16}},
        "required": ["mode"],
        "additionalProperties": False,
    }
    output_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {
            "authorization": {"type": "string", "maxLength": 128},
            "nested": {
                "type": "object",
                "properties": {"credential": {"type": "string", "maxLength": 128}},
                "required": ["credential"],
                "additionalProperties": False,
            },
        },
        "required": ["authorization", "nested"],
        "additionalProperties": False,
    }
    handler = LeakHandler()

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> LeakInput:
        mode = arguments.get("mode")
        if not isinstance(mode, str):
            raise ValueError("mode required")
        return LeakInput(mode=mode)

    def serialize_output(self, output_model: LeakOutput) -> JsonValue:
        return output_model.value


class AllowAll:
    async def authorize(self, **kwargs: object) -> None:
        del kwargs


class RecordingTelemetry:
    def __init__(self) -> None:
        self.events: list[ScrubbedError] = []

    def emit(self, event: ScrubbedError) -> None:
        self.events.append(event)


class FailingResultRedactor:
    limits = RedactionLimits()

    def redact_text(self, value: str) -> str:
        return value

    def redact(self, value: JsonValue) -> JsonValue:
        del value
        raise RuntimeError(CANARY)


class ExpandingRedactor:
    limits = RedactionLimits()

    def redact_text(self, value: str) -> str:
        return value

    def redact(self, value: JsonValue) -> JsonValue:
        del value
        return "x" * 1_048_577


def context(*, request_id: str = "request-redaction") -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant="tenant-redaction",
            subject="subject-redaction",
            issuer="https://identity.example.invalid",
            scopes=("security:probe",),
        ),
        request_id=request_id,
        run_id="run-redaction",
    )


def application(
    redactor: RedactionPolicy,
    telemetry: RecordingTelemetry,
) -> tuple[Application, InProcessTransport]:
    transport = InProcessTransport()
    return (
        Application(
            catalog=ToolCatalog([LeakTool()]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=telemetry,
            limits=ApplicationLimits(drain_timeout=1.0),
            clock=SystemClock(),
            redactor=redactor,
        ),
        transport,
    )


def test_secret_canary_is_removed_from_every_success_representation() -> None:
    async def exercise() -> None:
        telemetry = RecordingTelemetry()
        runtime, transport = application(
            SecretRedactor(known_secrets=(SecretValue(CANARY),)),
            telemetry,
        )
        await runtime.start()

        result = await transport.invoke(
            "security.leak-probe",
            {"mode": "success"},
            context=context(),
        )

        assert result.error is None
        assert CANARY not in json.dumps(result.value, sort_keys=True)
        assert CANARY not in repr(result)
        assert telemetry.events == []
        await runtime.drain()
        await runtime.stop()

    asyncio.run(exercise())


def test_errors_and_telemetry_redact_request_and_exception_canaries() -> None:
    async def exercise() -> None:
        telemetry = RecordingTelemetry()
        runtime, transport = application(
            SecretRedactor(known_secrets=(SecretValue(CANARY),)),
            telemetry,
        )
        await runtime.start()

        result = await transport.invoke(
            "security.leak-probe",
            {"mode": "raise"},
            context=context(request_id=f"request-{CANARY}"),
        )

        assert result.error is not None
        assert result.error.code is ErrorCode.INTERNAL_FAILURE
        assert CANARY not in json.dumps(result.error.to_dict(), sort_keys=True)
        assert len(telemetry.events) == 1
        assert CANARY not in json.dumps(telemetry.events[0].to_dict(), sort_keys=True)
        assert telemetry.events[0].exception_type == "RedactedException"
        await runtime.drain()
        await runtime.stop()

    asyncio.run(exercise())


def test_not_ready_error_also_redacts_the_caller_request_identifier() -> None:
    telemetry = RecordingTelemetry()
    runtime, _ = application(
        SecretRedactor(known_secrets=(SecretValue(CANARY),)),
        telemetry,
    )

    result = asyncio.run(
        runtime.invoke(
            "security.leak-probe",
            {"mode": "success"},
            context=context(request_id=f"request-{CANARY}"),
        )
    )

    assert result.error is not None
    assert result.error.code is ErrorCode.UNAVAILABLE
    assert CANARY not in result.error.request_id


def test_redaction_failure_fails_closed_with_a_safe_internal_diagnostic() -> None:
    async def exercise() -> None:
        telemetry = RecordingTelemetry()
        runtime, transport = application(FailingResultRedactor(), telemetry)
        await runtime.start()

        result = await transport.invoke(
            "security.leak-probe",
            {"mode": "success"},
            context=context(),
        )

        assert result.error is not None
        assert result.error.code is ErrorCode.INTERNAL_FAILURE
        assert result.value is None
        assert len(telemetry.events) == 1
        assert telemetry.events[0].exception_type == "RedactionError"
        assert CANARY not in repr(result)
        assert CANARY not in repr(telemetry.events)
        await runtime.drain()
        await runtime.stop()

    asyncio.run(exercise())


def test_replacement_redactor_cannot_expand_past_the_result_ceiling() -> None:
    async def exercise() -> None:
        telemetry = RecordingTelemetry()
        runtime, transport = application(ExpandingRedactor(), telemetry)
        await runtime.start()

        result = await transport.invoke(
            "security.leak-probe",
            {"mode": "success"},
            context=context(),
        )

        assert result.error is not None
        assert result.error.code is ErrorCode.RESULT_TOO_LARGE
        await runtime.drain()
        await runtime.stop()

    asyncio.run(exercise())
