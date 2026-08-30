from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import cast

import pytest
from tesserix_mcp_publisher import (
    ActivationPhase,
    ActivationTarget,
    AgenticCLIPublisher,
    CommandLimits,
    CommandResult,
    CommandRunner,
    EvidenceReference,
    OfficialMCPPublisherCLI,
    PreparedPublication,
    PublicationError,
    PublicationErrorCode,
    PublicationEvidence,
    SubprocessCommandRunner,
    prepare_publication,
)

from tesserix_mcp_runtime import JsonValue, RedactionPolicy, SecretRedactor, SecretValue

ROOT = Path(__file__).parents[3]
AUTHORING = (
    ROOT
    / "packages"
    / "tesserix-mcp-manifest"
    / "tests"
    / "goldens"
    / "oci-private-native"
    / "authoring.json"
)


def prepared_publication() -> PreparedPublication:
    return prepare_publication(
        AUTHORING.read_bytes(),
        runtime_version="3.1.0",
        evidence=PublicationEvidence(
            artifact=EvidenceReference(
                uri=(f"oci://ghcr.io/tesserix/settlements-mcp:3.1.0@sha256:{'c' * 64}"),
                digest=f"sha256:{'c' * 64}",
                media_type="application/vnd.oci.image.manifest.v1+json",
            ),
            sbom=EvidenceReference(
                uri="https://artifacts.example.com/settlements/3.1.0/sbom.spdx.json",
                digest=f"sha256:{'d' * 64}",
                media_type="application/spdx+json",
            ),
            provenance=EvidenceReference(
                uri=("https://artifacts.example.com/settlements/3.1.0/provenance.intoto.jsonl"),
                digest=f"sha256:{'e' * 64}",
                media_type="application/vnd.in-toto+jsonl",
            ),
        ),
    )


class FakeRunner:
    def __init__(self, results: list[CommandResult]) -> None:
        self.results = results
        self.arguments: list[tuple[str, ...]] = []
        self.files: list[tuple[int, bytes]] = []

    async def run(self, arguments: tuple[str, ...], *, request_id: str) -> CommandResult:
        del request_id
        self.arguments.append(arguments)
        for argument in arguments:
            path = Path(argument)
            if path.suffix == ".json":
                snapshot = await asyncio.to_thread(file_snapshot, path)
                if snapshot is not None:
                    self.files.append(snapshot)
        if not self.results:
            raise AssertionError("unexpected delegated command")
        return self.results.pop(0)


def file_snapshot(path: Path) -> tuple[int, bytes] | None:
    if not path.is_file():
        return None
    return path.stat().st_mode & 0o777, path.read_bytes()


def result(stdout: bytes = b"", *, stderr: bytes = b"", exit_code: int = 0) -> CommandResult:
    return CommandResult(exit_code=exit_code, stdout=stdout, stderr=stderr)


def published_document(prepared: PreparedPublication) -> bytes:
    document = json.loads(prepared.registry_manifest)
    metadata = document["metadata"]
    metadata["labels"].update(
        {
            "registry.agentic.dev/org": metadata["orgId"],
            "registry.agentic.dev/tenant": metadata["tenantId"],
            "registry.agentic.dev/visibility": metadata["visibility"],
        }
    )
    metadata.update(
        {
            "digest": prepared.registry_digest,
            "ref": prepared.ref,
            "signature": "c2lnbmF0dXJl",
            "signedBy": "registry-key-2026-08",
        }
    )
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def activation_document(prepared: PreparedPublication) -> bytes:
    document = json.loads(published_document(prepared))
    document["status"] = {
        "activation": {
            "schemaVersion": "v1alpha1",
            "ref": prepared.ref,
            "registryDigest": prepared.registry_digest,
            "artifactDigest": prepared.evidence.artifact.digest,
            "generation": 7,
            "desiredState": "published",
            "phase": "published",
            "publishedAt": "2026-08-30T11:59:00Z",
            "activeAt": None,
            "observedAt": "2026-08-30T12:00:00Z",
            "conditions": [
                {
                    "type": "Published",
                    "status": "True",
                    "actor": "registry",
                    "reason": "PublicationCommitted",
                    "observedGeneration": 7,
                    "registryDigest": prepared.registry_digest,
                    "artifactDigest": prepared.evidence.artifact.digest,
                    "lastTransitionTime": "2026-08-30T12:00:00Z",
                    "requestId": "request-publication",
                }
            ],
        }
    }
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def test_agentic_dry_run_performs_status_read_and_remote_validation() -> None:
    prepared = prepared_publication()
    runner = FakeRunner(
        [
            result(b"registry https://registry.example.com\nsigning ed25519\n"),
            result(b'{"applied":[{"kind":"MCPServer"}],"count":1,"dry_run":true}'),
        ]
    )
    publisher = AgenticCLIPublisher(runner=runner, redactor=SecretRedactor())

    asyncio.run(
        publisher.remote_validate(
            prepared,
            idempotency_key="publish-run-42",
            request_id="request-dry-run",
        )
    )

    assert runner.arguments[0] == ("agentic", "status")
    assert runner.arguments[1][:3] == ("agentic", "apply", "-f")
    assert runner.arguments[1][4:] == (
        "--dry-run",
        "--idempotency-key",
        "publish-run-42",
    )
    assert runner.files == [(0o600, prepared.registry_manifest)]
    assert not Path(runner.arguments[1][3]).exists()


def test_agentic_publish_fetch_and_verify_use_exact_version() -> None:
    prepared = prepared_publication()
    applied: dict[str, JsonValue] = {
        "applied": [
            {
                "created": True,
                "kind": "MCPServer",
                "name": prepared.name,
                "namespace": prepared.namespace,
                "tag": prepared.version,
            }
        ],
        "count": 1,
    }
    runner = FakeRunner(
        [
            result(json.dumps(applied).encode()),
            result(published_document(prepared)),
            result(b"verified registry digest signature\n"),
        ]
    )
    publisher = AgenticCLIPublisher(runner=runner, redactor=SecretRedactor())

    receipt = asyncio.run(
        publisher.publish(
            prepared,
            idempotency_key="publish-run-42",
            request_id="request-publish",
        )
    )
    artifact = asyncio.run(publisher.fetch(prepared, request_id="request-publish"))
    asyncio.run(publisher.verify(artifact, request_id="request-publish"))

    assert receipt.created is True
    assert artifact.ref == prepared.ref
    assert artifact.digest == prepared.registry_digest
    assert artifact.signature == "c2lnbmF0dXJl"
    assert runner.arguments[1] == (
        "agentic",
        "pull",
        "mcpservers",
        prepared.name,
        "--tag",
        prepared.version,
    )
    assert runner.arguments[2] == (
        "agentic",
        "verify",
        "mcpservers",
        prepared.name,
        "--tag",
        prepared.version,
    )
    assert all("SECRET" not in argument.upper() for argv in runner.arguments for argument in argv)


def test_agentic_fetches_digest_bound_activation_for_a_slash_name() -> None:
    prepared = prepared_publication()
    runner = FakeRunner([result(activation_document(prepared))])
    publisher = AgenticCLIPublisher(runner=runner, redactor=SecretRedactor())
    target = ActivationTarget(
        ref=prepared.ref,
        registry_digest=prepared.registry_digest,
        artifact_digest=prepared.evidence.artifact.digest,
    )

    status = asyncio.run(publisher.fetch_activation(target, request_id="request-activation"))

    assert status.phase is ActivationPhase.PUBLISHED
    assert status.generation == 7
    assert runner.arguments == [
        (
            "agentic",
            "pull",
            "mcpservers",
            prepared.name,
            "--tag",
            prepared.version,
        )
    ]


def test_agentic_activation_rejects_moved_artifact_and_payload_status() -> None:
    prepared = prepared_publication()
    moved_target = ActivationTarget(
        ref=prepared.ref,
        registry_digest=prepared.registry_digest,
        artifact_digest=f"sha256:{'f' * 64}",
    )
    publisher = AgenticCLIPublisher(
        runner=FakeRunner([result(activation_document(prepared))]),
        redactor=SecretRedactor(),
    )

    with pytest.raises(PublicationError) as moved:
        asyncio.run(
            publisher.fetch_activation(
                moved_target,
                request_id="request-moved-activation",
            )
        )

    assert moved.value.code is PublicationErrorCode.ACTIVATION_SUPERSEDED
    assert moved.value.retryable is False

    malformed = json.loads(activation_document(prepared))
    malformed["status"]["activation"] = {
        "message": "Bearer CCCCCCCCCCCCCCCC",
    }
    publisher = AgenticCLIPublisher(
        runner=FakeRunner([result(json.dumps(malformed).encode())]),
        redactor=SecretRedactor(),
    )
    target = ActivationTarget(
        ref=prepared.ref,
        registry_digest=prepared.registry_digest,
        artifact_digest=prepared.evidence.artifact.digest,
    )

    with pytest.raises(PublicationError) as invalid:
        asyncio.run(
            publisher.fetch_activation(
                target,
                request_id="request-invalid-activation",
            )
        )

    assert invalid.value.code is PublicationErrorCode.ACTIVATION_CONTRACT_INVALID
    assert "CCCCCCCCCCCCCCCC" not in str(invalid.value)


def test_official_target_only_uses_validate_and_publish_with_server_json() -> None:
    prepared = prepared_publication()
    runner = FakeRunner([result(), result()])
    publisher = OfficialMCPPublisherCLI(runner=runner, redactor=SecretRedactor())

    asyncio.run(publisher.validate(prepared, request_id="request-official"))
    asyncio.run(publisher.publish(prepared, request_id="request-official"))

    assert [arguments[:2] for arguments in runner.arguments] == [
        ("mcp-publisher", "validate"),
        ("mcp-publisher", "publish"),
    ]
    assert runner.files == [
        (0o600, prepared.server_json),
        (0o600, prepared.server_json),
    ]
    assert all("--registry" not in arguments for arguments in runner.arguments)


@pytest.mark.parametrize(
    ("stderr", "expected_code", "retryable"),
    [
        (b'error: registry 409: {"code":"conflict"}', PublicationErrorCode.CONFLICT, False),
        (b'error: registry 403: {"code":"forbidden"}', PublicationErrorCode.COMMAND_FAILED, False),
        (b"registry unavailable", PublicationErrorCode.UNAVAILABLE, True),
    ],
)
def test_delegate_failures_are_typed_without_echoing_payloads(
    stderr: bytes,
    expected_code: PublicationErrorCode,
    retryable: bool,
) -> None:
    runner = FakeRunner([result(stderr=stderr, exit_code=1)])
    publisher = AgenticCLIPublisher(runner=runner, redactor=SecretRedactor())

    with pytest.raises(PublicationError) as caught:
        asyncio.run(
            publisher.publish(
                prepared_publication(),
                idempotency_key="publish-run-42",
                request_id="request-error",
            )
        )

    assert caught.value.code is expected_code
    assert caught.value.retryable is retryable
    assert stderr.decode() not in str(caught.value)


def test_delegate_output_with_secret_material_fails_closed() -> None:
    runner = FakeRunner([result(b"Bearer PPPPPPPPPPPPPPPP")])
    publisher = AgenticCLIPublisher(
        runner=runner,
        redactor=SecretRedactor(known_secrets=(SecretValue("PPPPPPPPPPPPPPPP"),)),
    )

    with pytest.raises(PublicationError) as caught:
        asyncio.run(
            publisher.publish(
                prepared_publication(),
                idempotency_key="publish-run-42",
                request_id="request-secret",
            )
        )

    assert caught.value.code is PublicationErrorCode.SECRET_MATERIAL
    assert "PPPPPPPPPPPPPPPP" not in str(caught.value)


def test_delegate_rejects_oversized_or_malformed_json_output() -> None:
    limits = CommandLimits(max_stdout_bytes=64)
    for output in (b"x" * 65, b'{"count":1,"count":2}'):
        runner = FakeRunner([result(output)])
        publisher = AgenticCLIPublisher(
            runner=runner,
            redactor=SecretRedactor(),
            limits=limits,
        )
        with pytest.raises(PublicationError) as caught:
            asyncio.run(
                publisher.publish(
                    prepared_publication(),
                    idempotency_key="publish-run-42",
                    request_id="request-invalid-output",
                )
            )
        assert caught.value.code is PublicationErrorCode.COMMAND_OUTPUT_INVALID


@pytest.mark.parametrize(
    "output",
    [b"\xff", b"NaN", b"[]"],
    ids=["non-utf8", "non-finite", "non-object"],
)
def test_delegate_rejects_noncanonical_command_documents(output: bytes) -> None:
    publisher = AgenticCLIPublisher(
        runner=FakeRunner([result(output)]),
        redactor=SecretRedactor(),
    )

    with pytest.raises(PublicationError) as caught:
        asyncio.run(
            publisher.publish(
                prepared_publication(),
                idempotency_key="publish-run-42",
                request_id="request-noncanonical",
            )
        )

    assert caught.value.code is PublicationErrorCode.COMMAND_OUTPUT_INVALID


def test_delegate_constructors_reject_unbounded_or_untyped_boundaries() -> None:
    runner = FakeRunner([])
    with pytest.raises(TypeError):
        AgenticCLIPublisher(
            runner=cast(CommandRunner, object()),
            redactor=SecretRedactor(),
        )
    with pytest.raises(TypeError):
        AgenticCLIPublisher(
            runner=runner,
            redactor=cast(RedactionPolicy, object()),
        )
    with pytest.raises(TypeError):
        AgenticCLIPublisher(
            runner=runner,
            redactor=SecretRedactor(),
            limits=cast(CommandLimits, object()),
        )
    with pytest.raises(ValueError):
        AgenticCLIPublisher(
            runner=runner,
            redactor=SecretRedactor(),
            executable="agentic\nunsafe",
        )
    with pytest.raises(ValueError):
        OfficialMCPPublisherCLI(
            runner=runner,
            redactor=SecretRedactor(),
            executable="",
        )


def test_agentic_rejects_inconsistent_dry_run_and_apply_results() -> None:
    prepared = prepared_publication()
    dry_runner = FakeRunner([result(), result(b'{"count":1,"dry_run":false}')])
    dry_publisher = AgenticCLIPublisher(runner=dry_runner, redactor=SecretRedactor())
    with pytest.raises(PublicationError) as caught:
        asyncio.run(
            dry_publisher.remote_validate(
                prepared,
                idempotency_key="publish-run-42",
                request_id="request-invalid-dry-run",
            )
        )
    assert caught.value.code is PublicationErrorCode.COMMAND_OUTPUT_INVALID

    apply_publisher = AgenticCLIPublisher(
        runner=FakeRunner([result(b'{"applied":[],"count":1}')]),
        redactor=SecretRedactor(),
    )
    with pytest.raises(PublicationError) as caught:
        asyncio.run(
            apply_publisher.publish(
                prepared,
                idempotency_key="publish-run-42",
                request_id="request-invalid-apply",
            )
        )
    assert caught.value.code is PublicationErrorCode.COMMAND_OUTPUT_INVALID


def test_agentic_rejects_a_readback_with_a_mismatched_digest() -> None:
    prepared = prepared_publication()
    document = json.loads(published_document(prepared))
    document["metadata"]["digest"] = f"sha256:{'f' * 64}"
    publisher = AgenticCLIPublisher(
        runner=FakeRunner([result(json.dumps(document).encode())]),
        redactor=SecretRedactor(),
    )

    with pytest.raises(PublicationError) as caught:
        asyncio.run(publisher.fetch(prepared, request_id="request-digest-mismatch"))

    assert caught.value.code is PublicationErrorCode.COMMAND_OUTPUT_INVALID


def test_subprocess_runner_uses_no_shell_and_enforces_timeout() -> None:
    runner = SubprocessCommandRunner(
        limits=CommandLimits(timeout_seconds=0.05),
        redactor=SecretRedactor(),
    )

    completed = asyncio.run(
        runner.run(
            (sys.executable, "-c", "print('bounded-output')"),
            request_id="request-process",
        )
    )
    assert completed.exit_code == 0
    assert completed.stdout == b"bounded-output\n"

    with pytest.raises(PublicationError) as caught:
        asyncio.run(
            runner.run(
                (sys.executable, "-c", "import time; time.sleep(30)"),
                request_id="request-timeout",
            )
        )
    assert caught.value.code is PublicationErrorCode.UNAVAILABLE
    assert caught.value.retryable is True
