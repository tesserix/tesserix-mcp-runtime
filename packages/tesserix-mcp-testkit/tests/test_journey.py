from __future__ import annotations

import json
from dataclasses import replace

import pytest
from tesserix_mcp_testkit import (
    JOURNEY_CONTRACT_VERSION,
    REQUIRED_JOURNEY_ASSERTIONS,
    JourneyArtifact,
    JourneyAssertion,
    JourneyComponent,
    JourneyEvidence,
    JourneyEvidenceError,
    JourneyPhase,
    JourneyState,
    make_journey_assertion,
    scan_journey_surfaces,
)

KNOWN_GOOD_DIGEST = f"sha256:{'a' * 64}"
KNOWN_GOOD_ARTIFACT_DIGEST = f"sha256:{'b' * 64}"
KNOWN_GOOD_REF = "mcpservers/tenant-a/io.github.tesserix/journey@1.0.0"
TRACE_ID = "1" * 32


def _assertion(code: str) -> JourneyAssertion:
    state = JourneyState.HEALTHY
    phase = JourneyPhase.INVOKED
    ref = ""
    digest = ""
    trace_id = ""
    if code.startswith("publication."):
        phase = JourneyPhase.PUBLISHED
    elif code.startswith("discovery.") or code == "tenant.search_non_disclosure":
        phase = JourneyPhase.DISCOVERED
    elif code.startswith("activation."):
        phase = JourneyPhase.ROUTE_ACCEPTED
    elif code == "outage.registry_last_known_good":
        phase = JourneyPhase.OUTAGE
        state = JourneyState.CONTROL_PLANE_DEGRADED
    elif code == "outage.gateway_visible":
        phase = JourneyPhase.OUTAGE
        state = JourneyState.GATEWAY_UNAVAILABLE
    elif code == "outage.backing_visible":
        phase = JourneyPhase.OUTAGE
        state = JourneyState.BACKING_UNAVAILABLE
    elif code == "rollback.known_good":
        phase = JourneyPhase.ROLLBACK
        state = JourneyState.ROLLED_BACK

    if code == "activation.authenticated_probe":
        phase = JourneyPhase.PROBE_AUTHENTICATED
    elif code == "activation.bad_probe_rejected":
        phase = JourneyPhase.FAILED_CANDIDATE
        state = JourneyState.PROBE_FAILED

    if code in {
        "publication.immutable",
        "publication.replay",
        "discovery.exact_fetch",
        "activation.route_accepted",
        "activation.authenticated_probe",
        "invocation.structured_result",
        "outage.registry_last_known_good",
        "rollback.known_good",
    }:
        ref = KNOWN_GOOD_REF
        digest = KNOWN_GOOD_DIGEST

    if code.startswith(("invocation.", "observability.")):
        trace_id = TRACE_ID

    return JourneyAssertion(
        code=code,
        phase=phase,
        state=state,
        passed=True,
        elapsed_ms=17,
        request_id="request-journey-001",
        trace_id=trace_id,
        ref=ref,
        digest=digest,
    )


def complete_evidence() -> JourneyEvidence:
    return JourneyEvidence(
        run_id="journey-20260831-001",
        created_at="2026-08-31T12:34:56Z",
        components=(
            JourneyComponent(
                name="agentgateway",
                version="1.4.1",
                revision=f"sha256:{'c' * 64}",
            ),
            JourneyComponent(
                name="agentic-registry",
                version="6921474",
                revision="6921474591b6c59e89025370c310c7f85859246f",
            ),
            JourneyComponent(
                name="runtime",
                version="0.0.1.dev0",
                revision=f"sha256:{'d' * 64}",
            ),
        ),
        known_good=JourneyArtifact(
            ref=KNOWN_GOOD_REF,
            registry_digest=KNOWN_GOOD_DIGEST,
            artifact_digest=KNOWN_GOOD_ARTIFACT_DIGEST,
            version="1.0.0",
        ),
        assertions=tuple(_assertion(code) for code in reversed(REQUIRED_JOURNEY_ASSERTIONS)),
    )


def test_complete_journey_is_canonical_bounded_and_payload_free() -> None:
    evidence = complete_evidence()

    first = evidence.to_json(
        surfaces=(
            "gateway condition accepted=true",
            b'trace={"status":"ok"}',
            "metric journey_calls_total 1",
            "audit event=tool_completed",
        ),
        canaries=("SyntheticCanary8Kq3",),
    )
    second = replace(
        evidence,
        assertions=tuple(reversed(evidence.assertions)),
        components=tuple(reversed(evidence.components)),
    ).to_json(canaries=("SyntheticCanary8Kq3",))

    assert first == second
    assert len(first) < 1024 * 1024
    assert first.endswith(b"\n")
    document = json.loads(first)
    assert document["contract_version"] == "1.0"
    assert document["known_good"] == {
        "artifact_digest": KNOWN_GOOD_ARTIFACT_DIGEST,
        "ref": KNOWN_GOOD_REF,
        "registry_digest": KNOWN_GOOD_DIGEST,
        "version": "1.0.0",
    }
    assert [item["code"] for item in document["assertions"]] == sorted(REQUIRED_JOURNEY_ASSERTIONS)
    assert "SyntheticCanary8Kq3" not in first.decode()


@pytest.mark.parametrize(
    "surface",
    [
        "result=SyntheticCanary8Kq3",
        "authorization: " + "".join(("Bea", "rer ")) + ".".join(("header", "payload", "signature")),
        "api_key=journey-value-that-must-not-escape",
        "password: journey-value-that-must-not-escape",
    ],
    ids=["configured-canary", "bearer", "api-key", "password"],
)
def test_forbidden_material_in_any_surface_fails_without_echoing_it(surface: str) -> None:
    with pytest.raises(JourneyEvidenceError) as captured:
        complete_evidence().to_json(
            surfaces=(surface,),
            canaries=("SyntheticCanary8Kq3",),
        )

    assert captured.value.code == "forbidden_material"
    assert str(captured.value) == "journey_evidence:forbidden_material"
    assert surface not in str(captured.value)


def test_scanner_checks_each_surface_without_returning_payloads() -> None:
    scan_journey_surfaces(
        ("registry stub", b"generated manifest", "sanitized component log"),
        canaries=("SyntheticCanary8Kq3",),
    )


def test_incomplete_journey_reports_only_stable_missing_assertion_codes() -> None:
    evidence = replace(
        complete_evidence(),
        assertions=tuple(
            item for item in complete_evidence().assertions if item.code != "outage.gateway_visible"
        ),
    )

    with pytest.raises(JourneyEvidenceError) as captured:
        evidence.to_json()

    assert captured.value.code == "missing:outage.gateway_visible"
    assert str(captured.value) == "journey_evidence:missing:outage.gateway_visible"


def test_digest_continuity_is_required_at_every_immutable_checkpoint() -> None:
    evidence = complete_evidence()
    assertions = tuple(
        replace(item, digest=f"sha256:{'e' * 64}")
        if item.code == "activation.route_accepted"
        else item
        for item in evidence.assertions
    )

    with pytest.raises(JourneyEvidenceError) as captured:
        replace(evidence, assertions=assertions).to_json()

    assert captured.value.code == "identity_mismatch:activation.route_accepted"


def test_failed_assertion_cannot_be_published_as_release_evidence() -> None:
    evidence = complete_evidence()
    assertions = tuple(
        replace(item, passed=False) if item.code == "invocation.write_replay" else item
        for item in evidence.assertions
    )

    with pytest.raises(JourneyEvidenceError) as captured:
        replace(evidence, assertions=assertions).to_json()

    assert captured.value.code == "failed:invocation.write_replay"


def test_duplicate_assertion_code_is_rejected() -> None:
    evidence = complete_evidence()

    with pytest.raises(ValueError, match="assertion codes must be unique"):
        replace(evidence, assertions=(*evidence.assertions, evidence.assertions[0]))


@pytest.mark.parametrize(
    ("build", "message"),
    [
        (
            lambda: JourneyComponent(name="Agent Gateway", version="1.4.1", revision="main"),
            "component",
        ),
        (
            lambda: JourneyArtifact(
                ref="latest",
                registry_digest=KNOWN_GOOD_DIGEST,
                artifact_digest=KNOWN_GOOD_ARTIFACT_DIGEST,
                version="latest",
            ),
            "artifact",
        ),
        (
            lambda: replace(_assertion("invocation.safe_failure"), elapsed_ms=600_001),
            "assertion",
        ),
        (
            lambda: replace(_assertion("invocation.safe_failure"), trace_id="not-a-trace"),
            "assertion",
        ),
        (
            lambda: replace(complete_evidence(), created_at="2026-08-31 12:34:56"),
            "evidence",
        ),
    ],
    ids=["component", "artifact", "elapsed", "trace", "timestamp"],
)
def test_boundary_values_are_strict_and_bounded(build: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        assert callable(build)
        build()


def test_contract_vocabulary_is_stable_and_complete() -> None:
    assert JOURNEY_CONTRACT_VERSION == "1.0"
    assert set(REQUIRED_JOURNEY_ASSERTIONS) == {
        "activation.authenticated_probe",
        "activation.bad_probe_rejected",
        "activation.route_accepted",
        "discovery.exact_fetch",
        "discovery.semantic_match",
        "invocation.approval_required",
        "invocation.deadline",
        "invocation.safe_failure",
        "invocation.structured_result",
        "invocation.write_replay",
        "observability.audit",
        "observability.correlation",
        "outage.backing_visible",
        "outage.gateway_visible",
        "outage.registry_last_known_good",
        "publication.immutable",
        "publication.replay",
        "redaction.canary_absent",
        "rollback.known_good",
        "tenant.invocation_non_disclosure",
        "tenant.search_non_disclosure",
    }


def test_assertion_factory_reuses_contract_phase_state_and_identity_rules() -> None:
    artifact = JourneyArtifact(
        ref="mcpservers/tenant-a/io.github.tesserix/journey@1.0.0",
        registry_digest=KNOWN_GOOD_DIGEST,
        artifact_digest=KNOWN_GOOD_ARTIFACT_DIGEST,
        version="1.0.0",
    )

    publication = make_journey_assertion(
        code="publication.immutable",
        passed=True,
        elapsed_ms=12,
        request_id="request-publication",
        known_good=artifact,
    )
    outage = make_journey_assertion(
        code="outage.gateway_visible",
        passed=True,
        elapsed_ms=18,
        request_id="request-outage",
    )

    assert publication.phase is JourneyPhase.PUBLISHED
    assert publication.state is JourneyState.HEALTHY
    assert publication.ref == artifact.ref
    assert publication.digest == artifact.registry_digest
    assert outage.phase is JourneyPhase.OUTAGE
    assert outage.state is JourneyState.GATEWAY_UNAVAILABLE
    assert outage.ref == outage.digest == ""


def test_assertion_factory_requires_identity_for_identity_checkpoints() -> None:
    with pytest.raises(ValueError, match="known_good"):
        make_journey_assertion(
            code="discovery.exact_fetch",
            passed=True,
            elapsed_ms=1,
            request_id="request-discovery",
        )
    assert {phase.value for phase in JourneyPhase} == {
        "discovered",
        "failed_candidate",
        "invoked",
        "outage",
        "probe_authenticated",
        "published",
        "rollback",
        "route_accepted",
    }
    assert {state.value for state in JourneyState} == {
        "activation_timed_out",
        "backing_unavailable",
        "control_plane_degraded",
        "gateway_unavailable",
        "healthy",
        "probe_failed",
        "rolled_back",
    }
