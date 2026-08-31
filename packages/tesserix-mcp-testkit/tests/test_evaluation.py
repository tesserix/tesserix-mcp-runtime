from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from importlib import resources
from typing import cast

import httpx2 as httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.server.mcpserver import MCPServer
from tesserix_mcp_testkit import (
    SECRET_CANARY_PLACEHOLDER,
    TENANT_CANARY_PLACEHOLDER,
    AssertionOperator,
    AssertionsExpectation,
    CancellationExpectation,
    ErrorExpectation,
    EvaluationApproval,
    EvaluationArtifactBinding,
    EvaluationAssertion,
    EvaluationBundle,
    EvaluationCase,
    EvaluationContext,
    EvaluationContractError,
    EvaluationInvocation,
    EvaluationMetric,
    EvaluationMode,
    EvaluationObservation,
    EvaluationPromotionPolicy,
    EvaluationQuarantine,
    EvaluationReport,
    EvaluationReview,
    EvaluationReviewer,
    EvaluationRunner,
    EvaluationStatus,
    EvaluationVerificationError,
    PromotionMetricGate,
    PromotionStage,
    PromotionStagePolicy,
    ReviewerRole,
    StreamableHttpEvaluationTarget,
    StructuredResultExpectation,
    TelemetryExpectation,
    assess_evaluation_promotion,
    evaluation_bundle_json_schema,
    load_evaluation_bundle,
    sign_evaluation_report,
    verify_evaluation_report,
)


def _case(*, scopes: tuple[str, ...] = ("orders:read",)) -> EvaluationCase:
    return EvaluationCase(
        case_id="orders.happy",
        tool="orders.get",
        arguments={"order_id": "order-123"},
        expectation=StructuredResultExpectation(value={"order_id": "order-123", "status": "ready"}),
        tags=("happy",),
        context=EvaluationContext(
            tenant="tenant-a",
            scopes=scopes,
            approval=EvaluationApproval(required=False, granted=False),
        ),
        metrics=(
            EvaluationMetric.CORRECTNESS,
            EvaluationMetric.SCHEMA_CONFORMANCE,
            EvaluationMetric.AVAILABILITY,
        ),
        blocking_metrics=(
            EvaluationMetric.CORRECTNESS,
            EvaluationMetric.SCHEMA_CONFORMANCE,
        ),
        latency_budget_ms=250,
    )


def test_bundle_digest_changes_when_authority_or_expectation_changes() -> None:
    original = EvaluationBundle(name="orders", version="1.0.0", cases=(_case(),))
    changed_scope = EvaluationBundle(
        name="orders",
        version="1.0.0",
        cases=(_case(scopes=("orders:write",)),),
    )
    changed_expectation = EvaluationBundle(
        name="orders",
        version="1.0.0",
        cases=(
            _case().model_copy(
                update={
                    "expectation": StructuredResultExpectation(
                        value={"order_id": "order-123", "status": "cancelled"}
                    )
                }
            ),
        ),
    )

    assert original.dataset_digest != changed_scope.dataset_digest
    assert original.dataset_digest != changed_expectation.dataset_digest
    assert original.dataset_digest.startswith("sha256:")


def test_bundle_round_trips_every_versioned_case_contract_field() -> None:
    cases = (
        _case(),
        _case().model_copy(
            update={
                "case_id": "orders.boundary",
                "expectation": AssertionsExpectation(
                    assertions=(
                        EvaluationAssertion(
                            pointer="/items/0/status",
                            operator=AssertionOperator.EQUALS,
                            value="ready",
                        ),
                    )
                ),
                "telemetry": TelemetryExpectation(
                    required_events=("tool.completed",),
                    forbidden_events=("secret.exposed",),
                ),
            }
        ),
        _case().model_copy(
            update={
                "case_id": "orders.denied",
                "expectation": ErrorExpectation(code="forbidden"),
                "context": _case().context.model_copy(
                    update={
                        "approval": EvaluationApproval(required=True, granted=False),
                    }
                ),
            }
        ),
        _case().model_copy(
            update={
                "case_id": "orders.cancelled",
                "expectation": CancellationExpectation(),
                "attempts": 2,
                "quarantine": EvaluationQuarantine(
                    owner="runtime-team",
                    issue="https://github.com/tesserix/tesserix-mcp-runtime/issues/28",
                    reason="upstream cancellation race",
                ),
            }
        ),
    )
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=cases)

    loaded = load_evaluation_bundle(bundle.model_dump_json())

    assert loaded == bundle
    assert loaded.cases[1].telemetry.required_events == ("tool.completed",)
    assert loaded.cases[2].context.approval.required is True
    assert loaded.cases[3].quarantine is not None
    assert loaded.model_json_schema()["properties"]["schema_version"]["const"] == 1


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def test_artifact_binding_rejects_stale_dataset_evidence() -> None:
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(_case(),))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )

    binding.assert_matches(bundle)

    changed = EvaluationBundle(
        name="orders",
        version="1.0.0",
        cases=(_case(scopes=("orders:write",)),),
    )
    try:
        binding.assert_matches(changed)
    except ValueError as error:
        assert getattr(error, "code", None) == "dataset_digest_mismatch"
    else:
        raise AssertionError("stale dataset evidence was accepted")


class _RecordingTarget:
    mode = EvaluationMode.IN_PROCESS

    def __init__(self) -> None:
        self.invocations: list[object] = []

    async def observe(self, invocation: object) -> EvaluationObservation:
        self.invocations.append(invocation)
        return EvaluationObservation(
            structured_result={"order_id": "order-123", "status": "ready"},
            schema_valid=True,
            telemetry_events=("tool.completed",),
        )


def test_in_process_runner_emits_sanitized_per_metric_evidence() -> None:
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(_case(),))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    target = _RecordingTarget()
    ticks = iter((10.0, 10.010))
    runner = EvaluationRunner(
        bundle=bundle,
        binding=binding,
        target=target,
        now=lambda: datetime(2026, 8, 31, 1, 2, 3, tzinfo=UTC),
        monotonic=lambda: next(ticks),
    )

    report = asyncio.run(runner.run())

    assert report.complete is True
    assert report.passed is True
    assert report.mode is EvaluationMode.IN_PROCESS
    assert report.cases[0].status is EvaluationStatus.PASSED
    assert report.metric(EvaluationMetric.CORRECTNESS).score == 1.0
    assert report.metric(EvaluationMetric.SCHEMA_CONFORMANCE).score == 1.0
    assert report.metric(EvaluationMetric.AVAILABILITY).score == 1.0
    assert len(target.invocations) == 1
    rendered = report.to_json()
    assert "order-123" not in rendered
    assert "tenant-a" not in rendered
    assert '"dataset_digest":"' + bundle.dataset_digest + '"' in rendered


class _CancelledTarget:
    mode = EvaluationMode.IN_PROCESS

    async def observe(self, invocation: object) -> EvaluationObservation:
        del invocation
        raise asyncio.CancelledError


def test_expected_target_cancellation_is_recorded_without_cancelling_runner() -> None:
    case = _case().model_copy(
        update={
            "case_id": "orders.cancelled",
            "expectation": CancellationExpectation(),
        }
    )
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(case,))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    ticks = iter((20.0, 20.001))

    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=_CancelledTarget(),
            monotonic=lambda: next(ticks),
        ).run()
    )

    assert report.complete is True
    assert report.passed is True
    assert report.cases[0].status is EvaluationStatus.PASSED


class _TimeoutTarget:
    mode = EvaluationMode.IN_PROCESS

    async def observe(self, invocation: object) -> EvaluationObservation:
        del invocation
        raise TimeoutError("private-token-must-not-enter-evidence")


def test_runner_timeout_is_incomplete_and_cannot_pass_a_gate() -> None:
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(_case(),))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    ticks = iter((30.0, 30.250))

    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=_TimeoutTarget(),
            monotonic=lambda: next(ticks),
        ).run()
    )

    assert report.complete is False
    assert report.passed is False
    assert report.cases[0].status is EvaluationStatus.INCOMPLETE
    assert report.cases[0].failure_codes == ("timeout",)
    assert report.metric(EvaluationMetric.CORRECTNESS).score == 0.0
    assert "private-token" not in report.to_json()


def test_real_secret_in_bundle_fails_before_target_execution() -> None:
    case = _case().model_copy(
        update={"arguments": {"authorization": "Bearer live-secret-value-123456"}}
    )
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(case,))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    target = _RecordingTarget()

    with pytest.raises(EvaluationContractError) as captured:
        asyncio.run(EvaluationRunner(bundle=bundle, binding=binding, target=target).run())

    assert captured.value.code == "unsafe_bundle"
    assert target.invocations == []


class _LeakingCanaryTarget:
    mode = EvaluationMode.IN_PROCESS

    def __init__(self) -> None:
        self.canary = ""

    async def observe(self, invocation: EvaluationInvocation) -> EvaluationObservation:
        value = invocation.arguments["value"]
        assert isinstance(value, str)
        self.canary = value
        return EvaluationObservation(
            structured_result={"echo": value},
            schema_valid=True,
            telemetry_events=("tool.completed",),
        )


def test_secret_canary_leak_fails_blocking_metric_without_entering_report() -> None:
    case_document = _case().model_dump(mode="json")
    case_document.update(
        {
            "case_id": "orders.secret-canary",
            "arguments": {"value": SECRET_CANARY_PLACEHOLDER},
            "expectation": {
                "kind": "assertions",
                "assertions": [{"pointer": "/echo", "operator": "exists", "value": None}],
            },
            "metrics": ["correctness", "secret_leakage"],
            "blocking_metrics": ["secret_leakage"],
        }
    )
    case = EvaluationCase.model_validate(case_document)
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(case,))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    target = _LeakingCanaryTarget()

    report = asyncio.run(EvaluationRunner(bundle=bundle, binding=binding, target=target).run())

    assert target.canary != SECRET_CANARY_PLACEHOLDER
    assert report.passed is False
    assert report.cases[0].status is EvaluationStatus.FAILED
    assert report.metric(EvaluationMetric.CORRECTNESS).score == 1.0
    assert report.metric(EvaluationMetric.SECRET_LEAKAGE).score == 0.0
    assert target.canary not in report.to_json()


class _LeakingTenantTarget:
    mode = EvaluationMode.IN_PROCESS

    def __init__(self) -> None:
        self.canary = ""

    async def observe(self, invocation: EvaluationInvocation) -> EvaluationObservation:
        value = invocation.arguments["other_tenant_marker"]
        assert isinstance(value, str)
        self.canary = value
        return EvaluationObservation(
            structured_result={"items": [{"marker": value}]},
            schema_valid=True,
        )


def test_tenant_canary_leak_fails_isolation_even_when_shape_is_correct() -> None:
    case_document = _case().model_dump(mode="json")
    case_document.update(
        {
            "case_id": "orders.tenant-canary",
            "arguments": {"other_tenant_marker": TENANT_CANARY_PLACEHOLDER},
            "expectation": {
                "kind": "assertions",
                "assertions": [{"pointer": "/items", "operator": "exists", "value": None}],
            },
            "metrics": ["correctness", "tenant_isolation"],
            "blocking_metrics": ["tenant_isolation"],
        }
    )
    case = EvaluationCase.model_validate(case_document)
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(case,))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    target = _LeakingTenantTarget()

    report = asyncio.run(EvaluationRunner(bundle=bundle, binding=binding, target=target).run())

    assert report.metric(EvaluationMetric.CORRECTNESS).score == 1.0
    assert report.metric(EvaluationMetric.TENANT_ISOLATION).score == 0.0
    assert report.passed is False
    assert target.canary not in report.to_json()


class _DuplicateSideEffectTarget:
    mode = EvaluationMode.IN_PROCESS

    def __init__(self) -> None:
        self.calls = 0

    async def observe(self, invocation: EvaluationInvocation) -> EvaluationObservation:
        self.calls += 1
        assert invocation.context.idempotency_key == "same"
        return EvaluationObservation(
            structured_result={"order_id": "order-123", "status": "ready"},
            schema_valid=True,
            side_effect_digest=_digest("a" if self.calls == 1 else "b"),
        )


def test_duplicate_side_effect_fails_idempotency_despite_matching_results() -> None:
    case_document = _case().model_dump(mode="json")
    case_document.update(
        {
            "case_id": "orders.duplicate",
            "attempts": 2,
            "context": {
                **case_document["context"],
                "idempotency_key": "same",
            },
            "metrics": ["correctness", "idempotency"],
            "blocking_metrics": ["idempotency"],
        }
    )
    case = EvaluationCase.model_validate(case_document)
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(case,))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    target = _DuplicateSideEffectTarget()
    ticks = iter((1.0, 1.001, 2.0, 2.001))

    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=target,
            monotonic=lambda: next(ticks),
        ).run()
    )

    assert target.calls == 2
    assert report.metric(EvaluationMetric.CORRECTNESS).score == 1.0
    assert report.metric(EvaluationMetric.IDEMPOTENCY).score == 0.0
    assert report.passed is False


def test_authorization_metric_requires_an_explicit_denial_expectation() -> None:
    case_document = _case().model_dump(mode="json")
    case_document.update(
        {
            "metrics": ["authorization_denial"],
            "blocking_metrics": ["authorization_denial"],
        }
    )

    with pytest.raises(ValueError, match="authorization denial"):
        EvaluationCase.model_validate(case_document)


def test_signed_report_rejects_any_post_run_evidence_mutation() -> None:
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(_case(),))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    ticks = iter((1.0, 1.001))
    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=_RecordingTarget(),
            monotonic=lambda: next(ticks),
        ).run()
    )
    private_key = Ed25519PrivateKey.generate()
    signed = sign_evaluation_report(report, key_id="ci-evaluation", private_key=private_key)

    verify_evaluation_report(
        signed,
        bundle=bundle,
        binding=binding,
        public_keys={"ci-evaluation": private_key.public_key()},
    )

    tampered = signed.model_copy(update={"passed": False})
    with pytest.raises(EvaluationVerificationError) as captured:
        verify_evaluation_report(
            tampered,
            bundle=bundle,
            binding=binding,
            public_keys={"ci-evaluation": private_key.public_key()},
        )
    assert captured.value.code == "signature_invalid"

    inconsistent = report.model_copy(
        update={
            "cases": (report.cases[0].model_copy(update={"status": EvaluationStatus.FAILED}),),
        }
    )
    signed_inconsistent = sign_evaluation_report(
        inconsistent,
        key_id="ci-evaluation",
        private_key=private_key,
    )
    with pytest.raises(EvaluationVerificationError) as captured:
        verify_evaluation_report(
            signed_inconsistent,
            bundle=bundle,
            binding=binding,
            public_keys={"ci-evaluation": private_key.public_key()},
        )
    assert captured.value.code == "report_inconsistent"


class _OneBrokenTarget:
    mode = EvaluationMode.IN_PROCESS

    async def observe(self, invocation: EvaluationInvocation) -> EvaluationObservation:
        status = "ready" if invocation.case_id == "orders.happy" else "wrong"
        return EvaluationObservation(
            structured_result={"order_id": "order-123", "status": status},
            schema_valid=True,
        )


def test_promotion_never_averages_away_a_failed_blocking_case() -> None:
    policy = EvaluationPromotionPolicy(
        stages=(
            PromotionStagePolicy(
                stage=PromotionStage.EXPERIMENTAL,
                gates=(
                    PromotionMetricGate(
                        metric=EvaluationMetric.CORRECTNESS,
                        minimum_score=0.5,
                    ),
                ),
                allowed_modes=(EvaluationMode.IN_PROCESS,),
                required_reviewer_roles=(ReviewerRole.EVALUATION_OWNER,),
                minimum_reviewers=1,
                allow_quarantine=True,
            ),
        )
    )
    bundle = EvaluationBundle(
        name="orders",
        version="1.0.0",
        cases=(
            _case(),
            _case().model_copy(update={"case_id": "orders.broken"}),
        ),
        promotion_policy=policy,
    )
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    ticks = iter((1.0, 1.001, 2.0, 2.001))
    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=_OneBrokenTarget(),
            monotonic=lambda: next(ticks),
        ).run()
    )
    private_key = Ed25519PrivateKey.generate()
    signed = sign_evaluation_report(report, key_id="ci-evaluation", private_key=private_key)
    review = EvaluationReview(
        author="runtime-author",
        reviewers=(
            EvaluationReviewer(
                subject="quality-reviewer",
                roles=(ReviewerRole.EVALUATION_OWNER,),
            ),
        ),
    )

    decision = assess_evaluation_promotion(
        signed,
        bundle=bundle,
        binding=binding,
        public_keys={"ci-evaluation": private_key.public_key()},
        stage=PromotionStage.EXPERIMENTAL,
        review=review,
    )

    assert report.metric(EvaluationMetric.CORRECTNESS).score == 0.5
    assert decision.approved is False
    assert "blocking_case_failed" in decision.reasons


def test_same_bundle_runs_over_real_streamable_http_client_path() -> None:
    server = MCPServer("evaluation-target")

    def get_order(order_id: str) -> dict[str, str]:
        return {"order_id": order_id, "status": "ready"}

    server.add_tool(get_order, name="orders.get", structured_output=True)
    app = server.streamable_http_app(stateless_http=True, json_response=True)
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(_case(),))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )

    observed_tenants: list[str] = []

    @asynccontextmanager
    async def client_factory(
        context: EvaluationContext,
    ) -> AsyncGenerator[httpx.AsyncClient]:
        observed_tenants.append(context.tenant)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8000",
        ) as client:
            yield client

    async def exercise() -> EvaluationReport:
        async with app.router.lifespan_context(app):
            target = StreamableHttpEvaluationTarget(
                url="http://127.0.0.1:8000/mcp",
                http_client_factory=client_factory,
            )
            return await EvaluationRunner(
                bundle=bundle,
                binding=binding,
                target=target,
            ).run()

    report = asyncio.run(exercise())

    assert report.mode is EvaluationMode.STREAMABLE_HTTP
    assert report.passed is True
    assert observed_tenants == ["tenant-a"]


def test_markdown_report_contains_only_sanitized_evidence() -> None:
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(_case(),))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    ticks = iter((1.0, 1.001))
    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=_RecordingTarget(),
            monotonic=lambda: next(ticks),
        ).run()
    )

    markdown = report.to_markdown()

    assert "# Evaluation: orders 1.0.0" in markdown
    assert "| orders.happy | passed |" in markdown
    assert bundle.dataset_digest in markdown
    assert "order-123" not in markdown
    assert "tenant-a" not in markdown


def test_owned_quarantine_cannot_satisfy_a_blocking_gate() -> None:
    case = _case().model_copy(
        update={
            "quarantine": EvaluationQuarantine(
                owner="runtime-team",
                issue="https://github.com/tesserix/tesserix-mcp-runtime/issues/28",
                reason="nondeterministic upstream behavior",
            )
        }
    )
    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(case,))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    ticks = iter((1.0, 1.001))

    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=_RecordingTarget(),
            monotonic=lambda: next(ticks),
        ).run()
    )

    assert report.cases[0].status is EvaluationStatus.QUARANTINED
    assert report.metric(EvaluationMetric.CORRECTNESS).score == 0.0
    assert report.passed is False


def test_network_owned_streamable_http_target_requires_explicit_host_allowlist() -> None:
    with pytest.raises(EvaluationContractError) as captured:
        StreamableHttpEvaluationTarget(url="https://169.254.169.254/mcp")

    assert captured.value.code == "streamable_http_host"

    target = StreamableHttpEvaluationTarget(
        url="https://gateway.internal.example/mcp",
        allowed_hosts=("gateway.internal.example",),
    )
    assert target.mode is EvaluationMode.STREAMABLE_HTTP


def test_evaluation_bundle_publishes_stable_v1_json_schema() -> None:
    schema = evaluation_bundle_json_schema()
    properties = cast(dict[str, object], schema["properties"])
    version_schema = cast(dict[str, object], properties["schema_version"])
    definitions = cast(dict[str, object], schema["$defs"])

    assert schema["$id"] == "https://schemas.tesserix.dev/mcp/evaluation-bundle/v1"
    assert version_schema["const"] == 1
    assert schema["additionalProperties"] is False
    assert "EvaluationCase" in definitions


def test_packaged_schema_is_identical_to_runtime_contract() -> None:
    resource = resources.files("tesserix_mcp_testkit").joinpath(
        "schemas/evaluation-bundle-v1.schema.json"
    )

    assert json.loads(resource.read_text(encoding="utf-8")) == evaluation_bundle_json_schema()


@pytest.mark.parametrize("mutation", ("duplicate", "non_finite"))
def test_bundle_loader_rejects_ambiguous_json_before_execution(mutation: str) -> None:
    encoded = EvaluationBundle(
        name="orders",
        version="1.0.0",
        cases=(_case(),),
    ).model_dump_json()
    if mutation == "duplicate":
        encoded = encoded.replace('"name":"orders"', '"name":"orders","name":"other"')
    else:
        encoded = encoded.replace('"order_id":"order-123"', '"order_id":NaN', 1)

    with pytest.raises(EvaluationContractError) as captured:
        load_evaluation_bundle(encoded)

    assert captured.value.code == "invalid_json"


def test_bundle_loader_rejects_excessive_json_depth() -> None:
    document = EvaluationBundle(
        name="orders",
        version="1.0.0",
        cases=(_case(),),
    ).model_dump(mode="json")
    nested: object = "value"
    for _ in range(70):
        nested = [nested]
    document["cases"][0]["arguments"] = {"nested": nested}

    with pytest.raises(EvaluationContractError) as captured:
        load_evaluation_bundle(json.dumps(document))

    assert captured.value.code == "bundle_too_complex"


def test_runner_revalidates_nonvalidating_model_copies_before_execution() -> None:
    invalid_case = _case().model_copy(
        update={
            "metrics": (EvaluationMetric.AUTHORIZATION_DENIAL,),
            "blocking_metrics": (EvaluationMetric.AUTHORIZATION_DENIAL,),
        }
    )
    bundle = EvaluationBundle(
        name="orders",
        version="1.0.0",
        cases=(_case(),),
    ).model_copy(update={"cases": (invalid_case,)})
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )

    with pytest.raises(EvaluationContractError) as captured:
        EvaluationRunner(bundle=bundle, binding=binding, target=_RecordingTarget())

    assert captured.value.code == "invalid_bundle"


class _CrashThenRecoverTarget:
    mode = EvaluationMode.IN_PROCESS

    def __init__(self) -> None:
        self.calls = 0

    async def observe(self, invocation: EvaluationInvocation) -> EvaluationObservation:
        del invocation
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("Bearer private-crash-token-123456")
        return EvaluationObservation(
            structured_result={"order_id": "order-123", "status": "ready"},
            schema_valid=True,
        )


def test_target_crash_is_incomplete_sanitized_and_later_cases_continue() -> None:
    bundle = EvaluationBundle(
        name="orders",
        version="1.0.0",
        cases=(
            _case().model_copy(update={"case_id": "orders.crash"}),
            _case().model_copy(update={"case_id": "orders.after-crash"}),
        ),
    )
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )
    target = _CrashThenRecoverTarget()
    ticks = iter((1.0, 1.001, 2.0, 2.001))

    report = asyncio.run(
        EvaluationRunner(
            bundle=bundle,
            binding=binding,
            target=target,
            monotonic=lambda: next(ticks),
        ).run()
    )

    assert target.calls == 2
    assert [case.status for case in report.cases] == [
        EvaluationStatus.INCOMPLETE,
        EvaluationStatus.PASSED,
    ]
    assert report.complete is False
    assert report.passed is False
    assert "private-crash-token" not in report.to_json()


def test_external_runner_cancellation_is_never_swallowed() -> None:
    started = asyncio.Event()

    class BlockingTarget:
        mode = EvaluationMode.IN_PROCESS

        async def observe(self, invocation: EvaluationInvocation) -> EvaluationObservation:
            del invocation
            started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    bundle = EvaluationBundle(name="orders", version="1.0.0", cases=(_case(),))
    binding = EvaluationArtifactBinding(
        source_digest=_digest("1"),
        runtime_digest=_digest("2"),
        manifest_digest=_digest("3"),
        image_digest=_digest("4"),
        dataset_digest=bundle.dataset_digest,
    )

    async def exercise() -> None:
        task = asyncio.create_task(
            EvaluationRunner(bundle=bundle, binding=binding, target=BlockingTarget()).run()
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())
