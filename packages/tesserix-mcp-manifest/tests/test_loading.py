from __future__ import annotations

import json

import pytest
from tesserix_mcp_manifest import (
    AUTHORING_MANIFEST_MAX_BYTES,
    AUTHORING_MANIFEST_MAX_DEPTH,
    AUTHORING_MANIFEST_MAX_NODES,
    ManifestValidationCode,
    ManifestValidationError,
    ServerAuthoringManifest,
    load_authoring_manifest,
)


def test_loads_a_valid_authoring_manifest(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    source = json.dumps(remote_manifest.model_dump(mode="json")).encode()

    assert load_authoring_manifest(source) == remote_manifest


def test_rejects_source_larger_than_the_fixed_limit() -> None:
    source = b"x" * (AUTHORING_MANIFEST_MAX_BYTES + 1)

    with pytest.raises(ManifestValidationError) as raised:
        load_authoring_manifest(source)

    assert raised.value.code is ManifestValidationCode.SOURCE_TOO_LARGE
    assert str(raised.value) == "authoring manifest validation failed (source_too_large)"


@pytest.mark.parametrize(
    "source",
    [b'{"name":"loader-canary"', b"\xffloader-canary"],
    ids=["malformed-json", "invalid-utf8"],
)
def test_invalid_json_is_reported_without_echoing_source(source: bytes) -> None:
    with pytest.raises(ManifestValidationError) as raised:
        load_authoring_manifest(source)

    assert raised.value.code is ManifestValidationCode.INVALID_JSON
    assert "loader-canary" not in str(raised.value)
    assert "loader-canary" not in repr(raised.value)


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
def test_rejects_nonstandard_json_numbers(constant: bytes) -> None:
    source = b'{"value":' + constant + b"}"

    with pytest.raises(ManifestValidationError) as raised:
        load_authoring_manifest(source)

    assert raised.value.code is ManifestValidationCode.INVALID_JSON


def test_rejects_an_integer_above_the_parser_digit_limit() -> None:
    source = b'{"safe":' + b"1" * 5_000 + b"}"

    with pytest.raises(ManifestValidationError) as raised:
        load_authoring_manifest(source)

    assert raised.value.code is ManifestValidationCode.INVALID_JSON


def test_rejects_duplicate_json_keys_without_echoing_values() -> None:
    source = b'{"name":"first","name":"duplicate-canary"}'

    with pytest.raises(ManifestValidationError) as raised:
        load_authoring_manifest(source)

    assert raised.value.code is ManifestValidationCode.DUPLICATE_KEY
    assert "duplicate-canary" not in str(raised.value)
    assert "duplicate-canary" not in repr(raised.value)


def test_rejects_documents_above_the_depth_limit() -> None:
    document: object = "leaf"
    for _ in range(AUTHORING_MANIFEST_MAX_DEPTH + 1):
        document = {"safe": document}

    with pytest.raises(ManifestValidationError) as raised:
        load_authoring_manifest(json.dumps(document).encode())

    assert raised.value.code is ManifestValidationCode.TOO_DEEP


def test_rejects_documents_above_the_node_limit() -> None:
    source = json.dumps({"safe": [0] * AUTHORING_MANIFEST_MAX_NODES}).encode()
    assert len(source) < AUTHORING_MANIFEST_MAX_BYTES

    with pytest.raises(ManifestValidationError) as raised:
        load_authoring_manifest(source)

    assert raised.value.code is ManifestValidationCode.TOO_COMPLEX


@pytest.mark.parametrize(
    "secret_key",
    [
        "password",
        "apiKey",
        "client-secret",
        "access_token",
        "authorization",
        "privateKey",
    ],
)
def test_rejects_secret_shaped_keys_recursively(secret_key: str) -> None:
    source = json.dumps({"outer": {"safe": {secret_key: "secret-field-canary"}}}).encode()

    with pytest.raises(ManifestValidationError) as raised:
        load_authoring_manifest(source)

    assert raised.value.code is ManifestValidationCode.SECRET_FIELD
    assert "secret-field-canary" not in str(raised.value)
    assert "secret-field-canary" not in repr(raised.value)


def test_model_validation_is_translated_without_echoing_input(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    document = remote_manifest.model_dump(mode="json")
    document["version"] = "invalid version model-canary"

    with pytest.raises(ManifestValidationError) as raised:
        load_authoring_manifest(json.dumps(document).encode())

    assert raised.value.code is ManifestValidationCode.INVALID_MANIFEST
    assert "model-canary" not in str(raised.value)
    assert "model-canary" not in repr(raised.value)
