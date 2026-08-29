from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

BOUNDARY_CONTROLS = (
    "validation",
    "authentication",
    "authorization",
    "limits",
    "audit",
)
BOUNDARY_METADATA = (
    "id",
    "name",
    "path",
    "from",
    "to",
    "data",
    "trusted_claims",
    "never_trust",
)
OWNER_FIELDS = ("repository", "tracking_issue")
THREAT_FIELDS = (
    "id",
    "category",
    "scenario",
    "assets",
    "boundaries",
    "controls",
    "negative_tests",
    "residual_risk",
)
COMPROMISE_FIELDS = (
    "id",
    "component",
    "scenario",
    "controls",
    "negative_tests",
    "residual_risk",
)
NEGATIVE_TEST_FIELDS = ("id", "name", "future_test", "expected")
REQUIRED_REVIEWED_SECTIONS = (
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
)
SCOPE_FIELDS = ("entry", "exit", "paths", "data_classification")
REQUIRED_FLOW_PATHS = {"activate", "discover", "invoke", "publish"}
REVIEWED_RECORD_FIELDS = (
    ("assets", "asset", ("id", "name", "owner")),
    ("actors", "actor", ("id", "name", "capability")),
    (
        "assumptions",
        "assumption",
        ("id", "statement", "failure_if_false", "tracking_issue"),
    ),
    ("current_gaps", "current gap", ("id", "risk", "disposition")),
    (
        "review_examples",
        "review example",
        ("id", "name", "request", "expected"),
    ),
)
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
REVIEWED_EFFECTS = {"external_effect", "write"}
REVIEW_BINDINGS = {
    "description_digest",
    "effect",
    "schema_digest",
    "tool_name",
    "version",
}
REQUIRED_SECRET_CLASSES = {
    "access_token",
    "downstream_credential",
    "gateway_client_secret",
    "publisher_client_secret",
    "signing_key",
}
SECRET_FIELDS = ("storage", "lifetime", "rotation", "redaction", "incident_action")
REQUIRED_INCIDENT_SCENARIOS = {
    "audit_integrity_loss",
    "credential_exposure",
    "cross_tenant_access",
    "gateway_compromise",
    "malicious_artifact",
}
INCIDENT_FIELDS = (
    "detection",
    "containment",
    "eradication",
    "recovery",
    "evidence",
    "notification",
)
TOKEN_SHAPE = re.compile(r"[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}")


def strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in strings(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in strings(nested)]
    return []


def values_named(value: Any, name: str) -> list[Any]:
    if isinstance(value, dict):
        matches: list[Any] = []
        for key, nested in value.items():
            if key.casefold() == name.casefold():
                matches.append(nested)
            else:
                matches.extend(values_named(nested, name))
        return matches
    if isinstance(value, list):
        return [item for nested in value for item in values_named(nested, name)]
    return []


def check(model_path: Path) -> dict[str, Any]:
    model = json.loads(model_path.read_text(encoding="utf-8"))
    boundaries = model.get("trust_boundaries", [])
    violations: list[dict[str, str]] = []
    if model.get("schema_version") != 1:
        violations.append(
            {
                "id": "model",
                "reason": (
                    f"unsupported schema_version {model.get('schema_version', '<missing>')}"
                ),
            }
        )
    if model.get("status") != "reviewed":
        violations.append(
            {
                "id": "model",
                "reason": "threat model status must be reviewed",
            }
        )
    if model.get("status") == "reviewed":
        for section in REQUIRED_REVIEWED_SECTIONS:
            if not model.get(section):
                violations.append(
                    {
                        "id": "model",
                        "reason": f"reviewed model missing {section}",
                    }
                )
        scope = model.get("scope", {})
        for field in SCOPE_FIELDS:
            if not scope.get(field):
                violations.append(
                    {
                        "id": "scope",
                        "reason": f"reviewed scope missing {field}",
                    }
                )
        for path in sorted(REQUIRED_FLOW_PATHS - set(scope.get("paths", []))):
            violations.append(
                {
                    "id": "scope",
                    "reason": f"reviewed scope missing required path {path}",
                }
            )
        for section, record_name, fields in REVIEWED_RECORD_FIELDS:
            for record in model.get(section, []):
                for field in fields:
                    if not record.get(field):
                        violations.append(
                            {
                                "id": record.get("id", "<missing>"),
                                "reason": f"{record_name} missing {field}",
                            }
                        )

    identity_bearing_items = [
        *model.get("assets", []),
        *model.get("actors", []),
        *model.get("assumptions", []),
        *boundaries,
        *model.get("threats", []),
        *model.get("compromise_scenarios", []),
        *model.get("negative_tests", []),
        *model.get("review_examples", []),
        *[control for threat in model.get("threats", []) for control in threat.get("controls", [])],
        *[
            control
            for scenario in model.get("compromise_scenarios", [])
            for control in scenario.get("controls", [])
        ],
    ]
    seen_identities: set[str] = set()
    duplicate_identities: set[str] = set()
    for item in identity_bearing_items:
        identity = item.get("id")
        if not identity:
            continue
        if identity in seen_identities:
            duplicate_identities.add(identity)
        seen_identities.add(identity)
    for identity in sorted(duplicate_identities):
        violations.append(
            {
                "id": identity,
                "reason": "duplicate identity in threat model",
            }
        )

    for boundary in boundaries:
        for field in BOUNDARY_METADATA:
            if not boundary.get(field):
                violations.append(
                    {
                        "id": boundary.get("id", "<missing>"),
                        "reason": f"trust boundary missing {field}",
                    }
                )
        for control in BOUNDARY_CONTROLS:
            if not boundary.get(control):
                violations.append(
                    {
                        "id": boundary.get("id", "<missing>"),
                        "reason": f"trust boundary missing {control}",
                    }
                )
        owner = boundary.get("owner", {})
        for field in OWNER_FIELDS:
            if not owner.get(field):
                violations.append(
                    {
                        "id": boundary.get("id", "<missing>"),
                        "reason": f"trust boundary missing owner.{field}",
                    }
                )
    if model.get("status") == "reviewed":
        boundary_paths = {boundary.get("path") for boundary in boundaries}
        for path in sorted(REQUIRED_FLOW_PATHS - boundary_paths):
            violations.append(
                {
                    "id": path,
                    "reason": "required trust-boundary path missing",
                }
            )
    categories = {threat.get("category") for threat in model.get("threats", [])}
    for category in sorted(REQUIRED_THREAT_CATEGORIES - categories):
        violations.append(
            {
                "id": category,
                "reason": "required threat category missing",
            }
        )
    components = {scenario.get("component") for scenario in model.get("compromise_scenarios", [])}
    for component in sorted(REQUIRED_COMPROMISE_SCENARIOS - components):
        violations.append(
            {
                "id": component,
                "reason": "required compromise scenario missing",
            }
        )
    negative_tests = model.get("negative_tests", [])
    negative_test_ids = {item.get("id") for item in negative_tests}
    for negative_test in negative_tests:
        for field in NEGATIVE_TEST_FIELDS:
            if not negative_test.get(field):
                violations.append(
                    {
                        "id": negative_test.get("id", "<missing>"),
                        "reason": f"negative test missing {field}",
                    }
                )
        owner = negative_test.get("owner", {})
        for field in OWNER_FIELDS:
            if not owner.get(field):
                violations.append(
                    {
                        "id": negative_test.get("id", "<missing>"),
                        "reason": f"negative test missing owner.{field}",
                    }
                )
        future_test = negative_test.get("future_test")
        if future_test and "::" not in future_test:
            violations.append(
                {
                    "id": negative_test.get("id", "<missing>"),
                    "reason": "negative test future_test must contain a pytest node",
                }
            )
    for scenario in model.get("compromise_scenarios", []):
        for field in COMPROMISE_FIELDS:
            if not scenario.get(field):
                violations.append(
                    {
                        "id": scenario.get("id", "<missing>"),
                        "reason": f"compromise scenario missing {field}",
                    }
                )
        for control in scenario.get("controls", []):
            if not control.get("id") or not control.get("description"):
                violations.append(
                    {
                        "id": scenario.get("id", "<missing>"),
                        "reason": "compromise control missing identity or description",
                    }
                )
            owner = control.get("owner", {})
            for field in OWNER_FIELDS:
                if not owner.get(field):
                    violations.append(
                        {
                            "id": control.get("id", "<missing>"),
                            "reason": f"compromise control missing owner.{field}",
                        }
                    )
        for negative_test_id in scenario.get("negative_tests", []):
            if negative_test_id not in negative_test_ids:
                violations.append(
                    {
                        "id": scenario.get("id", "<missing>"),
                        "reason": (
                            "compromise scenario references unknown negative test "
                            f"{negative_test_id}"
                        ),
                    }
                )
    boundary_ids = {boundary.get("id") for boundary in boundaries}
    asset_ids = {asset.get("id") for asset in model.get("assets", [])}
    for threat in model.get("threats", []):
        for field in THREAT_FIELDS:
            if not threat.get(field):
                violations.append(
                    {
                        "id": threat.get("id", "<missing>"),
                        "reason": f"threat missing {field}",
                    }
                )
        for boundary_id in threat.get("boundaries", []):
            if boundary_id not in boundary_ids:
                violations.append(
                    {
                        "id": threat.get("id", "<missing>"),
                        "reason": f"threat references unknown boundary {boundary_id}",
                    }
                )
        if "assets" in model:
            for asset_id in threat.get("assets", []):
                if asset_id not in asset_ids:
                    violations.append(
                        {
                            "id": threat.get("id", "<missing>"),
                            "reason": f"threat references unknown asset {asset_id}",
                        }
                    )
        for control in threat.get("controls", []):
            if not control.get("id") or not control.get("description"):
                violations.append(
                    {
                        "id": threat.get("id", "<missing>"),
                        "reason": "threat control missing identity or description",
                    }
                )
            owner = control.get("owner", {})
            for field in OWNER_FIELDS:
                if not owner.get(field):
                    violations.append(
                        {
                            "id": control.get("id", "<missing>"),
                            "reason": f"threat control missing owner.{field}",
                        }
                    )
        for negative_test_id in threat.get("negative_tests", []):
            if negative_test_id not in negative_test_ids:
                violations.append(
                    {
                        "id": threat.get("id", "<missing>"),
                        "reason": (f"threat references unknown negative test {negative_test_id}"),
                    }
                )

    referenced_negative_tests = {
        negative_test_id
        for threat in model.get("threats", [])
        for negative_test_id in threat.get("negative_tests", [])
    } | {
        negative_test_id
        for scenario in model.get("compromise_scenarios", [])
        for negative_test_id in scenario.get("negative_tests", [])
    }
    for negative_test_id in sorted(
        identity
        for identity in negative_test_ids - referenced_negative_tests
        if identity is not None
    ):
        violations.append(
            {
                "id": negative_test_id,
                "reason": ("negative test is not referenced by a threat or compromise scenario"),
            }
        )
    effects = {item.get("effect"): item for item in model.get("effect_classes", [])}
    for effect in sorted(REVIEWED_EFFECTS):
        effect_policy = effects.get(effect)
        if effect_policy is None:
            violations.append({"id": effect, "reason": "reviewed effect class missing"})
            continue
        review = effect_policy.get("security_review", {})
        if not review.get("required"):
            violations.append({"id": effect, "reason": "effect requires security review"})
        if not review.get("independent_reviewer"):
            violations.append(
                {
                    "id": effect,
                    "reason": "effect requires independent security review",
                }
            )
        missing_bindings = REVIEW_BINDINGS - set(review.get("binds", []))
        if missing_bindings:
            violations.append(
                {
                    "id": effect,
                    "reason": (
                        "security review missing bindings " + ", ".join(sorted(missing_bindings))
                    ),
                }
            )
        if not review.get("reapprove_on_change"):
            violations.append({"id": effect, "reason": "effect changes require reapproval"})
        if not review.get("per_call_approval_remains_enforced"):
            violations.append(
                {
                    "id": effect,
                    "reason": "static review cannot replace per-call approval",
                }
            )
    for example in model.get("review_examples", []):
        if example.get("fake") is not True:
            violations.append(
                {
                    "id": example.get("id", "<missing>"),
                    "reason": "review example must be explicitly fake",
                }
            )
        if any(TOKEN_SHAPE.search(value) for value in strings(example)):
            violations.append(
                {
                    "id": example.get("id", "<missing>"),
                    "reason": "review example contains token-shaped material",
                }
            )
        if any(
            value != "Bearer <fake-token>"
            for value in values_named(example.get("request", {}), "authorization")
        ):
            violations.append(
                {
                    "id": example.get("id", "<missing>"),
                    "reason": ("review example authorization must use the fake placeholder"),
                }
            )
    if "secret_classes" in model:
        secret_class_items = model.get("secret_classes", [])
        for item in secret_class_items:
            if not item.get("class"):
                violations.append(
                    {
                        "id": "<missing>",
                        "reason": "secret class missing class",
                    }
                )
        secret_classes = {item["class"]: item for item in secret_class_items if item.get("class")}
        for secret_class in sorted(REQUIRED_SECRET_CLASSES - set(secret_classes)):
            violations.append({"id": secret_class, "reason": "required secret class missing"})
        for secret_class, policy in sorted(secret_classes.items()):
            for field in SECRET_FIELDS:
                if not policy.get(field):
                    violations.append(
                        {
                            "id": secret_class,
                            "reason": f"secret class missing {field}",
                        }
                    )
            owner = policy.get("owner", {})
            for field in OWNER_FIELDS:
                if not owner.get(field):
                    violations.append(
                        {
                            "id": secret_class,
                            "reason": f"secret class missing owner.{field}",
                        }
                    )
    if "incident_scenarios" in model:
        incident_items = model.get("incident_scenarios", [])
        for item in incident_items:
            if not item.get("scenario"):
                violations.append(
                    {
                        "id": "<missing>",
                        "reason": "incident scenario missing scenario",
                    }
                )
        incidents = {item["scenario"]: item for item in incident_items if item.get("scenario")}
        for scenario in sorted(REQUIRED_INCIDENT_SCENARIOS - set(incidents)):
            violations.append({"id": scenario, "reason": "required incident scenario missing"})
        for scenario, response in sorted(incidents.items()):
            for field in INCIDENT_FIELDS:
                if not response.get(field):
                    violations.append(
                        {
                            "id": scenario,
                            "reason": f"incident scenario missing {field}",
                        }
                    )
            owner = response.get("owner", {})
            for field in OWNER_FIELDS:
                if not owner.get(field):
                    violations.append(
                        {
                            "id": scenario,
                            "reason": f"incident scenario missing owner.{field}",
                        }
                    )
    return {
        "passed": not violations,
        "summary": {
            "trust_boundaries": len(boundaries),
            "threats": len(model.get("threats", [])),
            "compromise_scenarios": len(model.get("compromise_scenarios", [])),
            "negative_tests": len(negative_tests),
            "review_examples": len(model.get("review_examples", [])),
        },
        "violations": violations,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    arguments = parser.parse_args()
    result = check(arguments.model)
    safe_report = {
        "passed": bool(result["passed"]),
        "violation_count": len(result["violations"]),
    }
    print(json.dumps(safe_report, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
