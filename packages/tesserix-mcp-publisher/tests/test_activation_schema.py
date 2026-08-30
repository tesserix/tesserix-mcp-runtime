from __future__ import annotations

import json
from pathlib import Path

from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from tesserix_mcp_publisher import (
    ActivationActor,
    ActivationConditionType,
    ActivationDesiredState,
    ActivationPhase,
    ActivationStatus,
)

ROOT = Path(__file__).parents[3]
SCHEMA = ROOT / "contracts" / "activation-status-v1alpha1.schema.json"
EXAMPLE = ROOT / "contracts" / "activation-status-v1alpha1.example.json"


def test_activation_schema_and_example_are_compatible_with_typed_contract() -> None:
    schema = json.loads(SCHEMA.read_bytes())
    example = json.loads(EXAMPLE.read_bytes())

    validator_type = validator_for(schema)
    validator_type.check_schema(schema)
    validator = validator_type(schema, format_checker=FormatChecker())
    assert list(validator.iter_errors(example)) == []
    status = ActivationStatus.from_document(example)

    assert status.phase is ActivationPhase.ACTIVE
    assert set(schema["properties"]["phase"]["enum"]) == {phase.value for phase in ActivationPhase}
    assert set(schema["properties"]["desiredState"]["enum"]) == {
        desired.value for desired in ActivationDesiredState
    }
    condition = schema["$defs"]["condition"]["properties"]
    assert set(condition["type"]["enum"]) == {
        condition_type.value for condition_type in ActivationConditionType
    }
    assert set(condition["actor"]["enum"]) == {actor.value for actor in ActivationActor}
