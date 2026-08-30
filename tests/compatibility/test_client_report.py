from __future__ import annotations

from compatibility.client_report import ClientEvidence


def test_failed_client_evidence_names_the_operation_without_retaining_the_error() -> None:
    evidence = ClientEvidence(
        client="python-sdk",
        lane="devai-sdk",
        expected_sdk="1.28.1",
        supported_features=("pagination",),
        negotiated_out=("prompts", "resources"),
        feature_gaps=("pagination",),
    )
    evidence.begin("initialize")

    report = evidence.failed(
        actual_sdk="1.28.1",
        error=RuntimeError("Bearer should-never-enter-evidence payload=private"),
    )

    assert report == {
        "client": "python-sdk",
        "failure": {
            "code": "client_operation_failed",
            "error_type": "RuntimeError",
            "operation": "initialize",
            "protocol": "not-negotiated",
        },
        "feature_gaps": ["pagination"],
        "lane": "devai-sdk",
        "negotiated_out": ["prompts", "resources"],
        "operations": [],
        "passed": False,
        "protocols": [],
        "schema_version": 1,
        "sdk": "1.28.1",
        "supported_features": ["pagination"],
    }
    assert "should-never-enter-evidence" not in str(report)
