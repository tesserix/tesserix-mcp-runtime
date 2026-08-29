from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[2]
CHECKER = ROOT / "security" / "check_threat_model.py"
MODEL = ROOT / "security" / "threat-model.json"
REQUIRED_THREAT_CATEGORIES = {
    "audit_tampering",
    "authentication",
    "capability_drift",
    "confused_deputy",
    "cross_tenant_pooling",
    "decompression_bomb",
    "denial_of_service",
    "idor",
    "object_authorization",
    "prompt_injection",
    "replay",
    "schema_bomb",
    "secret_exposure",
    "semantic_poisoning",
    "ssrf",
    "supply_chain_substitution",
}
REQUIRED_COMPROMISE_SCENARIOS = {
    "backing_api",
    "dependency",
    "gateway",
    "publisher",
    "runtime_image",
}
REQUIRED_SECRET_CLASSES = {
    "access_token",
    "downstream_credential",
    "gateway_client_secret",
    "publisher_client_secret",
    "signing_key",
}
REQUIRED_INCIDENT_SCENARIOS = {
    "audit_integrity_loss",
    "credential_exposure",
    "cross_tenant_access",
    "gateway_compromise",
    "malicious_artifact",
}


def boundary() -> dict[str, Any]:
    return {
        "id": "P01",
        "name": "source to CI",
        "path": "publish",
        "from": "developer",
        "to": "canonical CI",
        "data": ["source revision"],
        "validation": ["review the exact revision"],
        "authentication": ["verify the GitHub identity"],
        "authorization": ["restrict release jobs to the canonical repository"],
        "limits": ["bound job time and permissions"],
        "audit": ["record repository, workflow, ref, and commit"],
        "trusted_claims": ["repository_id", "workflow_ref", "sha"],
        "never_trust": ["a tenant in submitted source"],
        "owner": {
            "repository": "tesserix/tesserix-mcp-runtime",
            "tracking_issue": "https://github.com/tesserix/tesserix-mcp-runtime/issues/27",
        },
    }


def threats(*, exclude: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = exclude or set()
    return [
        {
            "id": f"T-{category}",
            "category": category,
            "scenario": f"Fake {category} scenario",
            "assets": ["publishing authority"],
            "boundaries": ["P01"],
            "controls": [
                {
                    "id": f"CTL-{category}",
                    "description": f"Control {category}",
                    "owner": {
                        "repository": "tesserix/tesserix-mcp-runtime",
                        "tracking_issue": "https://github.com/tesserix/tesserix-mcp-runtime/issues/30",
                    },
                }
            ],
            "negative_tests": [f"NEG-{category}"],
            "residual_risk": "Bounded fake residual risk",
        }
        for category in sorted(REQUIRED_THREAT_CATEGORIES - excluded)
    ]


def negative_tests() -> list[dict[str, Any]]:
    threat_tests = [
        {
            "id": f"NEG-{category}",
            "name": f"rejects {category}",
            "future_test": f"tests/security/test_negative.py::test_{category}",
            "expected": "request is rejected without disclosing protected state",
            "owner": {
                "repository": "tesserix/tesserix-mcp-runtime",
                "tracking_issue": "https://github.com/tesserix/tesserix-mcp-runtime/issues/30",
            },
        }
        for category in sorted(REQUIRED_THREAT_CATEGORIES)
    ]
    compromise_tests = [
        {
            "id": f"NEG-COMP-{component}",
            "name": f"contains a compromised {component}",
            "future_test": f"tests/security/test_compromise.py::test_{component}",
            "expected": "blast radius is bounded and the event is auditable",
            "owner": {
                "repository": "tesserix/tesserix-mcp-runtime",
                "tracking_issue": "https://github.com/tesserix/tesserix-mcp-runtime/issues/30",
            },
        }
        for component in sorted(REQUIRED_COMPROMISE_SCENARIOS)
    ]
    return [*threat_tests, *compromise_tests]


def compromise_scenarios(*, exclude: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = exclude or set()
    return [
        {
            "id": f"C-{component}",
            "component": component,
            "scenario": f"Fake compromised {component} scenario",
            "controls": [
                {
                    "id": f"CTL-COMP-{component}",
                    "description": f"Contain {component}",
                    "owner": {
                        "repository": "tesserix/tesserix-mcp-runtime",
                        "tracking_issue": "https://github.com/tesserix/tesserix-mcp-runtime/issues/30",
                    },
                }
            ],
            "negative_tests": [f"NEG-COMP-{component}"],
            "residual_risk": "Bounded fake residual risk",
        }
        for component in sorted(REQUIRED_COMPROMISE_SCENARIOS - excluded)
    ]


def effect_classes() -> list[dict[str, Any]]:
    review = {
        "required": True,
        "independent_reviewer": True,
        "binds": [
            "description_digest",
            "effect",
            "schema_digest",
            "tool_name",
            "version",
        ],
        "reapprove_on_change": True,
        "per_call_approval_remains_enforced": True,
    }
    return [
        {"effect": "read", "security_review": {"required": False}},
        {"effect": "write", "security_review": dict(review)},
        {"effect": "external_effect", "security_review": dict(review)},
    ]


def review_examples() -> list[dict[str, Any]]:
    return [
        {
            "id": "EX-01",
            "fake": True,
            "request": {
                "url": "https://gateway.example.invalid/mcp/tenant-blue/server",
                "headers": {"Authorization": "Bearer <fake-token>"},
            },
            "expected": "401 with no claim or route disclosure",
        }
    ]


def secret_classes() -> list[dict[str, Any]]:
    return [
        {
            "class": secret_class,
            "storage": "approved fake secret store; never source, manifest, or logs",
            "lifetime": "bounded and shorter than the authority it protects",
            "rotation": "overlap, cut over, revoke, and verify old material fails",
            "redaction": "redact by type before logs, errors, traces, or results",
            "incident_action": "revoke, rotate, preserve audit evidence, and scope impact",
            "owner": {
                "repository": "tesserix/tesserix-mcp-runtime",
                "tracking_issue": "https://github.com/tesserix/tesserix-mcp-runtime/issues/15",
            },
        }
        for secret_class in sorted(REQUIRED_SECRET_CLASSES)
    ]


def incident_scenarios() -> list[dict[str, Any]]:
    return [
        {
            "scenario": scenario,
            "detection": "alert on a fake security signal",
            "containment": "fail closed and isolate the affected identity or digest",
            "eradication": "revoke the cause and remove the vulnerable revision",
            "recovery": "restore a verified last-known-good revision",
            "evidence": "preserve immutable identifiers, decisions, and provenance",
            "notification": "notify security and affected owners under the incident policy",
            "owner": {
                "repository": "tesserix/tesserix-mcp-runtime",
                "tracking_issue": "https://github.com/tesserix/tesserix-mcp-runtime/issues/30",
            },
        }
        for scenario in sorted(REQUIRED_INCIDENT_SCENARIOS)
    ]


def run_checker(model: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--model", str(model)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )


def test_checked_in_threat_model_is_complete_and_traceable() -> None:
    completed = run_checker(MODEL)

    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert result["passed"] is True
    assert result["violations"] == []
    assert result["summary"]["trust_boundaries"] >= 20
    assert result["summary"]["threats"] >= len(REQUIRED_THREAT_CATEGORIES)
    assert result["summary"]["compromise_scenarios"] == len(
        REQUIRED_COMPROMISE_SCENARIOS
    )
    assert result["summary"]["negative_tests"] >= 30
    assert result["summary"]["review_examples"] >= 5


def test_rejects_a_trust_boundary_without_audit_behavior(tmp_path: Path) -> None:
    crossing = boundary()
    crossing.pop("audit")
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [crossing],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": negative_tests(),
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    result = json.loads(completed.stdout)
    assert result["passed"] is False
    assert result["summary"]["trust_boundaries"] == 1
    assert {
        "id": "P01",
        "reason": "trust boundary missing audit",
    } in result["violations"]


def test_rejects_a_trust_boundary_without_an_issue_owner(tmp_path: Path) -> None:
    crossing = boundary()
    crossing["owner"].pop("tracking_issue")
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [crossing],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": negative_tests(),
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "P01",
        "reason": "trust boundary missing owner.tracking_issue",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_boundary_without_explicit_trusted_claims(tmp_path: Path) -> None:
    crossing = boundary()
    crossing.pop("trusted_claims")
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [crossing],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": negative_tests(),
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "P01",
        "reason": "trust boundary missing trusted_claims",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_model_without_a_required_threat_category(tmp_path: Path) -> None:
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": threats(exclude={"ssrf"}),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": negative_tests(),
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "ssrf",
        "reason": "required threat category missing",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_model_without_a_required_compromise_scenario(
    tmp_path: Path,
) -> None:
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(exclude={"gateway"}),
                "negative_tests": negative_tests(),
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "gateway",
        "reason": "required compromise scenario missing",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_compromise_scenario_without_an_owned_control(
    tmp_path: Path,
) -> None:
    scenarios = compromise_scenarios()
    scenarios[0]["controls"] = []
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": threats(),
                "compromise_scenarios": scenarios,
                "negative_tests": negative_tests(),
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "C-backing_api",
        "reason": "compromise scenario missing controls",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_negative_test_without_an_issue_owner(tmp_path: Path) -> None:
    inventory = negative_tests()
    inventory[0]["owner"].pop("tracking_issue")
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": inventory,
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "NEG-audit_tampering",
        "reason": "negative test missing owner.tracking_issue",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_negative_test_without_a_future_ci_test_name(
    tmp_path: Path,
) -> None:
    inventory = negative_tests()
    inventory[0].pop("future_test")
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": inventory,
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "NEG-audit_tampering",
        "reason": "negative test missing future_test",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_threat_with_an_unowned_negative_test_reference(
    tmp_path: Path,
) -> None:
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": negative_tests()[1:],
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "T-audit_tampering",
        "reason": "threat references unknown negative test NEG-audit_tampering",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_threat_without_an_owned_control(tmp_path: Path) -> None:
    modeled_threats = threats()
    modeled_threats[0]["controls"] = []
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": modeled_threats,
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": negative_tests(),
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "T-audit_tampering",
        "reason": "threat missing controls",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_an_external_effect_without_independent_security_review(
    tmp_path: Path,
) -> None:
    effects = effect_classes()
    effects[-1]["security_review"]["independent_reviewer"] = False
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": negative_tests(),
                "effect_classes": effects,
                "review_examples": review_examples(),
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "external_effect",
        "reason": "effect requires independent security review",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_review_example_that_contains_token_shaped_material(
    tmp_path: Path,
) -> None:
    examples = review_examples()
    examples[0]["request"]["headers"]["Authorization"] = (
        "Bearer eyJhbGciOiJSUzI1NiJ9.fakepayloadsegment000000.fakesignaturesegment0000"
    )
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": negative_tests(),
                "effect_classes": effect_classes(),
                "review_examples": examples,
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "EX-01",
        "reason": "review example contains token-shaped material",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_secret_class_without_a_lifetime(tmp_path: Path) -> None:
    secrets = secret_classes()
    secrets[0].pop("lifetime")
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": negative_tests(),
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
                "secret_classes": secrets,
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "access_token",
        "reason": "secret class missing lifetime",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_an_incident_scenario_without_evidence_preservation(
    tmp_path: Path,
) -> None:
    incidents = incident_scenarios()
    incidents[0].pop("evidence")
    model = tmp_path / "threat-model.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [boundary()],
                "threats": threats(),
                "compromise_scenarios": compromise_scenarios(),
                "negative_tests": negative_tests(),
                "effect_classes": effect_classes(),
                "review_examples": review_examples(),
                "secret_classes": secret_classes(),
                "incident_scenarios": incidents,
            }
        ),
        encoding="utf-8",
    )

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "audit_integrity_loss",
        "reason": "incident scenario missing evidence",
    } in json.loads(completed.stdout)["violations"]


@pytest.mark.parametrize(
    "section",
    [
        "reviewed_on",
        "scope",
        "assets",
        "actors",
        "assumptions",
        "current_gaps",
        "trust_boundaries",
        "threats",
        "compromise_scenarios",
        "negative_tests",
        "effect_classes",
        "secret_classes",
        "incident_scenarios",
        "review_examples",
    ],
)
def test_rejects_a_reviewed_model_without_a_required_section(
    tmp_path: Path,
    section: str,
) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document.pop(section)
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "model",
        "reason": f"reviewed model missing {section}",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_an_unsupported_schema_version(tmp_path: Path) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document["schema_version"] = 2
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "model",
        "reason": "unsupported schema_version 2",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_threat_model_that_is_not_reviewed(tmp_path: Path) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document["status"] = "draft"
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "model",
        "reason": "threat model status must be reviewed",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_duplicate_identities(tmp_path: Path) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document["negative_tests"][1]["id"] = document["negative_tests"][0]["id"]
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "NEG-001",
        "reason": "duplicate identity in threat model",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_future_test_without_a_pytest_node(tmp_path: Path) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document["negative_tests"][0]["future_test"] = "tests/security/test_auth.py"
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "NEG-001",
        "reason": "negative test future_test must contain a pytest node",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_an_unreferenced_negative_test(tmp_path: Path) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document["negative_tests"].append(
        {
            "id": "NEG-999",
            "name": "synthetic unreferenced test",
            "future_test": "tests/security/test_inventory.py::test_synthetic",
            "expected": "fail closed",
            "owner": {
                "repository": "tesserix/tesserix-mcp-runtime",
                "tracking_issue": (
                    "https://github.com/tesserix/tesserix-mcp-runtime/issues/30"
                ),
            },
        }
    )
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "NEG-999",
        "reason": "negative test is not referenced by a threat or compromise scenario",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_review_example_not_marked_fake(tmp_path: Path) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document["review_examples"][0]["fake"] = False
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "EX-01",
        "reason": "review example must be explicitly fake",
    } in json.loads(completed.stdout)["violations"]


@pytest.mark.parametrize(
    ("section", "record_name", "field"),
    [
        ("assets", "asset", "owner"),
        ("actors", "actor", "capability"),
        ("assumptions", "assumption", "failure_if_false"),
        ("assumptions", "assumption", "tracking_issue"),
        ("current_gaps", "current gap", "risk"),
        ("current_gaps", "current gap", "disposition"),
        ("review_examples", "review example", "request"),
        ("review_examples", "review example", "expected"),
    ],
    ids=[
        "asset-owner",
        "actor-capability",
        "assumption-failure",
        "assumption-owner",
        "gap-risk",
        "gap-disposition",
        "example-request",
        "example-outcome",
    ],
)
def test_rejects_a_reviewed_record_without_required_metadata(
    tmp_path: Path,
    section: str,
    record_name: str,
    field: str,
) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    identity = document[section][0]["id"]
    document[section][0].pop(field)
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": identity,
        "reason": f"{record_name} missing {field}",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_threat_that_references_an_unknown_asset(tmp_path: Path) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document["threats"][0]["assets"] = ["A-UNKNOWN"]
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "T01",
        "reason": "threat references unknown asset A-UNKNOWN",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_non_placeholder_authorization_example(tmp_path: Path) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document["review_examples"][1]["request"]["headers"]["Authorization"] = (
        "Bearer opaque-example-value"
    )
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "EX-02",
        "reason": "review example authorization must use the fake placeholder",
    } in json.loads(completed.stdout)["violations"]


@pytest.mark.parametrize(
    ("section", "identity_field", "record_name"),
    [
        ("secret_classes", "class", "secret class"),
        ("incident_scenarios", "scenario", "incident scenario"),
    ],
)
def test_rejects_a_security_record_without_an_identity(
    tmp_path: Path,
    section: str,
    identity_field: str,
    record_name: str,
) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document[section][0].pop(identity_field)
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "<missing>",
        "reason": f"{record_name} missing {identity_field}",
    } in json.loads(completed.stdout)["violations"]


@pytest.mark.parametrize(
    ("section", "field", "record_name"),
    [
        ("threats", "id", "threat"),
        ("threats", "category", "threat"),
        ("compromise_scenarios", "id", "compromise scenario"),
        ("compromise_scenarios", "component", "compromise scenario"),
    ],
)
def test_rejects_a_threat_record_without_its_identity(
    tmp_path: Path,
    section: str,
    field: str,
    record_name: str,
) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    existing_id = document[section][0].get("id", "<missing>")
    document[section][0].pop(field)
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    expected_id = "<missing>" if field == "id" else existing_id
    assert {
        "id": expected_id,
        "reason": f"{record_name} missing {field}",
    } in json.loads(completed.stdout)["violations"]


@pytest.mark.parametrize(
    "field",
    ["entry", "exit", "paths", "data_classification"],
)
def test_rejects_a_reviewed_scope_without_required_metadata(
    tmp_path: Path,
    field: str,
) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document["scope"].pop(field)
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "scope",
        "reason": f"reviewed scope missing {field}",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_scope_without_every_required_flow_path(tmp_path: Path) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    document["scope"]["paths"].remove("invoke")
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "scope",
        "reason": "reviewed scope missing required path invoke",
    } in json.loads(completed.stdout)["violations"]


def test_rejects_a_model_without_a_boundary_for_every_flow_path(
    tmp_path: Path,
) -> None:
    document = json.loads(MODEL.read_text(encoding="utf-8"))
    for boundary_record in document["trust_boundaries"]:
        if boundary_record["path"] == "invoke":
            boundary_record["path"] = "activate"
    model = tmp_path / "threat-model.json"
    model.write_text(json.dumps(document), encoding="utf-8")

    completed = run_checker(model)

    assert completed.returncode == 1
    assert {
        "id": "invoke",
        "reason": "required trust-boundary path missing",
    } in json.loads(completed.stdout)["violations"]
