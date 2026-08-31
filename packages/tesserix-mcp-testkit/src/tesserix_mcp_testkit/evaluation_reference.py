from __future__ import annotations

from tesserix_mcp_runtime.contracts import JsonValue
from tesserix_mcp_testkit.evaluation import (
    SECRET_CANARY_PLACEHOLDER,
    TENANT_CANARY_PLACEHOLDER,
    AssertionOperator,
    AssertionsExpectation,
    CancellationExpectation,
    ErrorExpectation,
    EvaluationApproval,
    EvaluationAssertion,
    EvaluationBundle,
    EvaluationCase,
    EvaluationContext,
    EvaluationInvocation,
    EvaluationMetric,
    EvaluationMode,
    EvaluationObservation,
    StructuredResultExpectation,
    TelemetryExpectation,
)

_REFERENCE_EFFECT_DIGEST = "sha256:" + "a" * 64


def _context(
    *,
    scopes: tuple[str, ...] = ("evaluation:read",),
    approval: EvaluationApproval | None = None,
    idempotency_key: str | None = None,
) -> EvaluationContext:
    return EvaluationContext(
        tenant="tenant-reference",
        scopes=scopes,
        approval=approval or EvaluationApproval(required=False, granted=False),
        idempotency_key=idempotency_key,
    )


def reference_evaluation_bundle() -> EvaluationBundle:
    completed = TelemetryExpectation(required_events=("evaluation.completed",))
    return EvaluationBundle(
        name="tesserix-runtime-reference",
        version="1.0.0",
        cases=(
            EvaluationCase(
                case_id="reference.happy",
                tool="evaluation.happy",
                arguments={},
                expectation=StructuredResultExpectation(value={"status": "ready"}),
                tags=("happy",),
                context=_context(),
                metrics=(
                    EvaluationMetric.AVAILABILITY,
                    EvaluationMetric.CORRECTNESS,
                    EvaluationMetric.LATENCY,
                    EvaluationMetric.SCHEMA_CONFORMANCE,
                ),
                blocking_metrics=(
                    EvaluationMetric.AVAILABILITY,
                    EvaluationMetric.CORRECTNESS,
                    EvaluationMetric.LATENCY,
                    EvaluationMetric.SCHEMA_CONFORMANCE,
                ),
                telemetry=completed,
                latency_budget_ms=250,
                timeout_ms=1_000,
            ),
            EvaluationCase(
                case_id="reference.boundary",
                tool="evaluation.boundary",
                arguments={"size": 0},
                expectation=StructuredResultExpectation(value={"accepted": True, "size": 0}),
                tags=("boundary",),
                context=_context(),
                metrics=(EvaluationMetric.CORRECTNESS, EvaluationMetric.SCHEMA_CONFORMANCE),
                blocking_metrics=(
                    EvaluationMetric.CORRECTNESS,
                    EvaluationMetric.SCHEMA_CONFORMANCE,
                ),
                telemetry=completed,
                latency_budget_ms=250,
                timeout_ms=1_000,
            ),
            EvaluationCase(
                case_id="reference.denial",
                tool="evaluation.denied",
                arguments={"operation": "delete"},
                expectation=ErrorExpectation(code="forbidden"),
                tags=("denial",),
                context=_context(
                    scopes=(),
                    approval=EvaluationApproval(required=True, granted=False),
                ),
                metrics=(EvaluationMetric.AUTHORIZATION_DENIAL,),
                blocking_metrics=(EvaluationMetric.AUTHORIZATION_DENIAL,),
                telemetry=TelemetryExpectation(required_events=("evaluation.denied",)),
                latency_budget_ms=250,
                timeout_ms=1_000,
            ),
            EvaluationCase(
                case_id="reference.duplicate",
                tool="evaluation.idempotent",
                arguments={"value": "create-once"},
                expectation=StructuredResultExpectation(value={"created": True}),
                tags=("duplicate",),
                context=_context(idempotency_key="reference-idempotency-key"),
                metrics=(EvaluationMetric.CORRECTNESS, EvaluationMetric.IDEMPOTENCY),
                blocking_metrics=(EvaluationMetric.CORRECTNESS, EvaluationMetric.IDEMPOTENCY),
                telemetry=completed,
                latency_budget_ms=250,
                timeout_ms=1_000,
                attempts=2,
            ),
            EvaluationCase(
                case_id="reference.timeout",
                tool="evaluation.timeout",
                arguments={"deadline_ms": 1},
                expectation=ErrorExpectation(code="timeout"),
                tags=("timeout",),
                context=_context(),
                metrics=(EvaluationMetric.CORRECTNESS,),
                blocking_metrics=(EvaluationMetric.CORRECTNESS,),
                telemetry=TelemetryExpectation(required_events=("evaluation.timeout",)),
                latency_budget_ms=250,
                timeout_ms=1_000,
            ),
            EvaluationCase(
                case_id="reference.cancellation",
                tool="evaluation.cancel",
                arguments={},
                expectation=CancellationExpectation(),
                tags=("cancellation",),
                context=_context(),
                metrics=(EvaluationMetric.CORRECTNESS,),
                blocking_metrics=(EvaluationMetric.CORRECTNESS,),
                telemetry=TelemetryExpectation(required_events=("evaluation.cancelled",)),
                latency_budget_ms=250,
                timeout_ms=1_000,
            ),
            EvaluationCase(
                case_id="reference.tenant-canary",
                tool="evaluation.tenant",
                arguments={"other_tenant_marker": TENANT_CANARY_PLACEHOLDER},
                expectation=AssertionsExpectation(
                    assertions=(
                        EvaluationAssertion(
                            pointer="/items",
                            operator=AssertionOperator.EQUALS,
                            value=[],
                        ),
                    )
                ),
                tags=("tenant-canary",),
                context=_context(),
                metrics=(EvaluationMetric.TENANT_ISOLATION,),
                blocking_metrics=(EvaluationMetric.TENANT_ISOLATION,),
                telemetry=completed,
                latency_budget_ms=250,
                timeout_ms=1_000,
            ),
            EvaluationCase(
                case_id="reference.secret-canary",
                tool="evaluation.secret",
                arguments={"credential": SECRET_CANARY_PLACEHOLDER},
                expectation=AssertionsExpectation(
                    assertions=(
                        EvaluationAssertion(
                            pointer="/accepted",
                            operator=AssertionOperator.EQUALS,
                            value=True,
                        ),
                    )
                ),
                tags=("secret-canary",),
                context=_context(),
                metrics=(EvaluationMetric.SECRET_LEAKAGE,),
                blocking_metrics=(EvaluationMetric.SECRET_LEAKAGE,),
                telemetry=completed,
                latency_budget_ms=250,
                timeout_ms=1_000,
            ),
        ),
    )


class ReferenceEvaluationTarget:
    def __init__(
        self,
        *,
        defect: EvaluationMetric | None = None,
        mode: EvaluationMode = EvaluationMode.IN_PROCESS,
    ) -> None:
        self.defect = defect
        self.mode = mode

    async def observe(self, invocation: EvaluationInvocation) -> EvaluationObservation:
        if invocation.tool == "evaluation.happy":
            observation = EvaluationObservation(
                structured_result={
                    "status": ("wrong" if self.defect is EvaluationMetric.CORRECTNESS else "ready")
                },
                schema_valid=self.defect is not EvaluationMetric.SCHEMA_CONFORMANCE,
                available=self.defect is not EvaluationMetric.AVAILABILITY,
                telemetry_events=("evaluation.completed",),
            )
        elif invocation.tool == "evaluation.boundary":
            observation = EvaluationObservation(
                structured_result={"accepted": True, "size": 0},
                schema_valid=True,
                telemetry_events=("evaluation.completed",),
            )
        elif invocation.tool == "evaluation.denied":
            if self.defect is EvaluationMetric.AUTHORIZATION_DENIAL:
                observation = EvaluationObservation(
                    structured_result={"deleted": True},
                    schema_valid=True,
                    telemetry_events=("evaluation.denied",),
                )
            else:
                observation = EvaluationObservation(
                    error_code="forbidden",
                    schema_valid=True,
                    telemetry_events=("evaluation.denied",),
                )
        elif invocation.tool == "evaluation.idempotent":
            side_effect_digest = _REFERENCE_EFFECT_DIGEST
            if self.defect is EvaluationMetric.IDEMPOTENCY and invocation.attempt > 1:
                side_effect_digest = "sha256:" + "b" * 64
            observation = EvaluationObservation(
                structured_result={"created": True},
                schema_valid=True,
                side_effect_digest=side_effect_digest,
                telemetry_events=("evaluation.completed",),
            )
        elif invocation.tool == "evaluation.timeout":
            observation = EvaluationObservation(
                error_code="timeout",
                schema_valid=True,
                telemetry_events=("evaluation.timeout",),
            )
        elif invocation.tool == "evaluation.cancel":
            observation = EvaluationObservation(
                cancelled=True,
                schema_valid=True,
                telemetry_events=("evaluation.cancelled",),
            )
        elif invocation.tool == "evaluation.tenant":
            items: list[JsonValue] = []
            if self.defect is EvaluationMetric.TENANT_ISOLATION:
                items.append({"marker": invocation.arguments["other_tenant_marker"]})
            observation = EvaluationObservation(
                structured_result={"items": items},
                schema_valid=True,
                telemetry_events=("evaluation.completed",),
            )
        elif invocation.tool == "evaluation.secret":
            result: dict[str, JsonValue] = {"accepted": True}
            if self.defect is EvaluationMetric.SECRET_LEAKAGE:
                result["echo"] = invocation.arguments["credential"]
            observation = EvaluationObservation(
                structured_result=result,
                schema_valid=True,
                telemetry_events=("evaluation.completed",),
            )
        else:
            raise ValueError("unknown reference evaluation tool")
        return observation
