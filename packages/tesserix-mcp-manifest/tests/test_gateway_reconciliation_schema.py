from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from tesserix_mcp_manifest import (
    GatewayReconciliationPage,
    GatewayReconciliationSnapshot,
    assemble_gateway_reconciliation_pages,
)

ROOT = Path(__file__).parents[3]
SCHEMA = ROOT / "contracts" / "gateway-reconciliation-v1alpha1.schema.json"
EXAMPLE = ROOT / "contracts" / "gateway-reconciliation-v1alpha1.example.json"
PAGE_EXAMPLE = ROOT / "contracts" / "gateway-reconciliation-page-v1alpha1.example.json"


def test_gateway_reconciliation_schema_matches_the_complete_typed_contract() -> None:
    schema = json.loads(SCHEMA.read_text())
    example = json.loads(EXAMPLE.read_text())

    validator_type = validator_for(schema)
    validator_type.check_schema(schema)
    validator = validator_type(schema, format_checker=FormatChecker())
    assert list(validator.iter_errors(example)) == []
    snapshot = GatewayReconciliationSnapshot.from_document(example)

    assert snapshot.complete is True
    assert snapshot.route_count == 1
    assert snapshot.tenant_count == 2
    assert snapshot.tenants[0].tenant_id == "tenant-blue"
    assert snapshot.tenants[1].tenant_id == "tenant-retired"
    assert schema["properties"]["complete"] == {"const": True}
    assert schema["properties"]["routes"]["maxItems"] == 1000
    assert schema["properties"]["tenants"]["maxItems"] == 1000

    unsafe_name = deepcopy(example)
    unsafe_name["routes"][0]["ref"] = "mcpservers/tenant-blue/../orders@1.2.3"
    unsafe_name["routes"][0]["serverName"] = "../orders"
    assert list(validator.iter_errors(unsafe_name))


def test_gateway_reconciliation_page_schema_requires_a_complete_cursor_chain() -> None:
    schema = json.loads(SCHEMA.read_text())
    page_example = json.loads(PAGE_EXAMPLE.read_text())
    page_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"],
        **schema["$defs"]["page"],
    }

    validator_type = validator_for(page_schema)
    validator_type.check_schema(page_schema)
    validator = validator_type(page_schema, format_checker=FormatChecker())
    assert list(validator.iter_errors(page_example)) == []
    page = GatewayReconciliationPage.from_document(page_example)
    snapshot = assemble_gateway_reconciliation_pages((page,))

    assert page.complete is True
    assert page.next_cursor is None
    assert snapshot.snapshot_digest == page.snapshot_digest
