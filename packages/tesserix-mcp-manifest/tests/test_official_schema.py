from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from tesserix_mcp_manifest import (
    OFFICIAL_REGISTRY_COMMIT,
    OFFICIAL_REGISTRY_RELEASE,
    OFFICIAL_SCHEMA_SHA256,
)

SCHEMA_PATH = Path(__file__).parents[1] / "schemas" / "official-server-2025-12-11.schema.json"
GOLDENS = Path(__file__).with_name("goldens")


def test_vendored_schema_has_release_provenance() -> None:
    schema_bytes = SCHEMA_PATH.read_bytes()

    assert OFFICIAL_REGISTRY_RELEASE == "v1.8.1"
    assert OFFICIAL_REGISTRY_COMMIT == "f52dc8525a441a3abf5fedc9912152d95af5aab1"
    assert sha256(schema_bytes).hexdigest() == OFFICIAL_SCHEMA_SHA256


@pytest.mark.parametrize(
    "case",
    ["remote-public-native", "package-internal-adk", "oci-private-native"],
)
def test_goldens_are_valid_against_the_pinned_official_schema(case: str) -> None:
    schema = json.loads(SCHEMA_PATH.read_bytes())
    validator_type = validator_for(schema)
    validator_type.check_schema(schema)
    validator = validator_type(schema, format_checker=FormatChecker())
    server = json.loads((GOLDENS / case / "server.json").read_bytes())

    assert list(validator.iter_errors(server)) == []
