from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest
from tesserix_mcp_publisher import (
    CommandResult,
    EvidenceReference,
    PreparedPublication,
    PublicationEvidence,
    prepare_publication,
)
from tesserix_mcp_publisher.cli import run

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


class FakeRunner:
    def __init__(self, results: list[CommandResult]) -> None:
        self.results = results
        self.arguments: list[tuple[str, ...]] = []

    async def run(self, arguments: tuple[str, ...], *, request_id: str) -> CommandResult:
        del request_id
        self.arguments.append(arguments)
        if not self.results:
            raise AssertionError("unexpected command")
        return self.results.pop(0)


def result(stdout: bytes = b"", *, stderr: bytes = b"", exit_code: int = 0) -> CommandResult:
    return CommandResult(exit_code=exit_code, stdout=stdout, stderr=stderr)


def prepared_publication(tmp_path: Path) -> PreparedPublication:
    arguments = evidence_arguments(tmp_path)
    sbom = Path(arguments[arguments.index("--sbom-file") + 1]).read_bytes()
    provenance = Path(arguments[arguments.index("--provenance-file") + 1]).read_bytes()
    return prepare_publication(
        AUTHORING.read_bytes(),
        runtime_version="3.1.0",
        evidence=PublicationEvidence(
            artifact=EvidenceReference(
                uri=arguments[arguments.index("--artifact-uri") + 1],
                digest=arguments[arguments.index("--artifact-digest") + 1],
                media_type=arguments[arguments.index("--artifact-media-type") + 1],
            ),
            sbom=EvidenceReference(
                uri=arguments[arguments.index("--sbom-uri") + 1],
                digest=f"sha256:{hashlib.sha256(sbom).hexdigest()}",
                media_type="application/spdx+json",
            ),
            provenance=EvidenceReference(
                uri=arguments[arguments.index("--provenance-uri") + 1],
                digest=f"sha256:{hashlib.sha256(provenance).hexdigest()}",
                media_type="application/vnd.in-toto+jsonl",
            ),
        ),
    )


def published_document(prepared: PreparedPublication) -> bytes:
    document = json.loads(prepared.registry_manifest)
    document["metadata"]["labels"].update(
        {
            "registry.agentic.dev/org": document["metadata"]["orgId"],
            "registry.agentic.dev/tenant": document["metadata"]["tenantId"],
            "registry.agentic.dev/visibility": document["metadata"]["visibility"],
        }
    )
    document["metadata"].update(
        {
            "digest": prepared.registry_digest,
            "ref": prepared.ref,
            "signature": "c2lnbmF0dXJl",
            "signedBy": "registry-key-2026-08",
        }
    )
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def applied_document(prepared: PreparedPublication, *, created: bool = True) -> bytes:
    return json.dumps(
        {
            "applied": [
                {
                    "created": created,
                    "kind": "MCPServer",
                    "name": prepared.name,
                    "namespace": prepared.namespace,
                    "tag": prepared.version,
                }
            ],
            "count": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def evidence_arguments(tmp_path: Path) -> list[str]:
    sbom = tmp_path / "sbom.spdx.json"
    sbom.write_text('{"spdxVersion":"SPDX-2.3"}', encoding="utf-8")
    provenance = tmp_path / "provenance.intoto.jsonl"
    provenance.write_text('{"_type":"https://in-toto.io/Statement/v1"}', encoding="utf-8")
    return [
        "--manifest",
        str(AUTHORING),
        "--runtime-version",
        "3.1.0",
        "--artifact-uri",
        f"oci://ghcr.io/tesserix/settlements-mcp:3.1.0@sha256:{'c' * 64}",
        "--artifact-digest",
        f"sha256:{'c' * 64}",
        "--artifact-media-type",
        "application/vnd.oci.image.manifest.v1+json",
        "--sbom-file",
        str(sbom),
        "--sbom-uri",
        "https://artifacts.example.com/settlements/3.1.0/sbom.spdx.json",
        "--provenance-file",
        str(provenance),
        "--provenance-uri",
        "https://artifacts.example.com/settlements/3.1.0/provenance.intoto.jsonl",
    ]


def test_validate_and_inspect_emit_only_bounded_safe_summaries(tmp_path: Path) -> None:
    for command in ("validate", "inspect"):
        stdout = io.StringIO()
        stderr = io.StringIO()
        exit_code = run(
            [command, *evidence_arguments(tmp_path)],
            stdout=stdout,
            stderr=stderr,
        )

        assert exit_code == 0
        assert stderr.getvalue() == ""
        document = json.loads(stdout.getvalue())
        assert document["name"] == "io.github.tesserix/settlements"
        assert document["ref"].endswith("@3.1.0")
        assert document["registry_digest"].startswith("sha256:")
        assert "spec" not in document
        assert "tools" not in document


def test_manifest_command_writes_exact_artifacts_and_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "out"
    output.mkdir()
    stdout = io.StringIO()
    stderr = io.StringIO()

    first = run(
        ["manifest", *evidence_arguments(tmp_path), "--output-dir", str(output)],
        stdout=stdout,
        stderr=stderr,
    )
    second = run(
        ["manifest", *evidence_arguments(tmp_path), "--output-dir", str(output)],
        stdout=io.StringIO(),
        stderr=stderr,
    )

    assert first == 0
    assert second == 2
    assert (output / "server.json").read_bytes().endswith(b"\n")
    registry = json.loads((output / "mcpserver.json").read_bytes())
    assert registry["spec"]["x-tesserix"]["publication"]["artifact"]["digest"] == (
        f"sha256:{'c' * 64}"
    )
    assert "manifest_invalid" in stderr.getvalue()


def test_publish_dry_run_delegates_external_reads_and_no_writes(tmp_path: Path) -> None:
    runner = FakeRunner(
        [
            result(b"registry ready and signing enabled\n"),
            result(b'{"applied":[{"kind":"MCPServer"}],"count":1,"dry_run":true}'),
        ]
    )
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = run(
        [
            "publish",
            *evidence_arguments(tmp_path),
            "--idempotency-key",
            "publish-run-42",
            "--request-id",
            "request-cli-dry-run",
            "--dry-run",
        ],
        runner=runner,
        environ={"AGENTIC_CLIENT_SECRET": "CCCCCCCCCCCCCCCC"},
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    assert json.loads(stdout.getvalue())["status"] == "dry_run"
    assert [arguments[1] for arguments in runner.arguments] == ["status", "apply"]
    assert "--dry-run" in runner.arguments[1]
    assert all(
        "CCCCCCCCCCCCCCCC" not in argument
        for arguments in runner.arguments
        for argument in arguments
    )


def test_official_dry_run_is_explicit_and_only_validates(tmp_path: Path) -> None:
    runner = FakeRunner(
        [
            result(b"registry ready and signing enabled\n"),
            result(b'{"applied":[{"kind":"MCPServer"}],"count":1,"dry_run":true}'),
            result(b"server.json is valid\n"),
        ]
    )
    stdout = io.StringIO()

    exit_code = run(
        [
            "publish",
            *evidence_arguments(tmp_path),
            "--idempotency-key",
            "publish-run-42",
            "--request-id",
            "request-cli-official",
            "--dry-run",
            "--official",
        ],
        runner=runner,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert exit_code == 0
    assert json.loads(stdout.getvalue())["official_status"] == "validated"
    assert [arguments[:2] for arguments in runner.arguments] == [
        ("agentic", "status"),
        ("agentic", "apply"),
        ("mcp-publisher", "validate"),
    ]


def test_publish_returns_the_exact_verified_registry_result(tmp_path: Path) -> None:
    prepared = prepared_publication(tmp_path)
    runner = FakeRunner(
        [
            result(applied_document(prepared)),
            result(published_document(prepared)),
            result(b"verified registry digest signature\n"),
        ]
    )
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = run(
        [
            "publish",
            *evidence_arguments(tmp_path),
            "--idempotency-key",
            "publish-run-42",
        ],
        runner=runner,
        environ={},
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    document = json.loads(stdout.getvalue())
    assert document["status"] == "verified"
    assert document["digest"] == prepared.registry_digest
    assert document["ref"] == prepared.ref
    assert document["signed_by"] == "registry-key-2026-08"
    assert document["request_id"].startswith("publish-")
    assert [arguments[1] for arguments in runner.arguments] == ["apply", "pull", "verify"]


@pytest.mark.parametrize(
    ("message", "expected_exit", "expected_code"),
    [
        (b"registry 409 conflict", 3, "immutable_version_conflict"),
        (b"registry 503 unavailable", 4, "publisher_unavailable"),
    ],
)
def test_publish_maps_terminal_and_retryable_apply_failures(
    tmp_path: Path,
    message: bytes,
    expected_exit: int,
    expected_code: str,
) -> None:
    stderr = io.StringIO()

    exit_code = run(
        [
            "publish",
            *evidence_arguments(tmp_path),
            "--idempotency-key",
            "publish-run-42",
            "--request-id",
            "request-cli-failure",
        ],
        runner=FakeRunner([result(stderr=message, exit_code=1)]),
        stdout=io.StringIO(),
        stderr=stderr,
    )

    assert exit_code == expected_exit
    assert json.loads(stderr.getvalue())["code"] == expected_code
    assert message.decode() not in stderr.getvalue()


def test_publish_reports_unknown_after_apply_when_readback_fails(tmp_path: Path) -> None:
    prepared = prepared_publication(tmp_path)
    stderr = io.StringIO()

    exit_code = run(
        [
            "publish",
            *evidence_arguments(tmp_path),
            "--idempotency-key",
            "publish-run-42",
            "--request-id",
            "request-cli-unknown",
        ],
        runner=FakeRunner(
            [
                result(applied_document(prepared)),
                result(stderr=b"registry unavailable", exit_code=1),
            ]
        ),
        stdout=io.StringIO(),
        stderr=stderr,
    )

    assert exit_code == 5
    error = json.loads(stderr.getvalue())
    assert error["code"] == "publication_outcome_unknown"
    assert error["request_id"] == "request-cli-unknown"
    assert error["retryable"] is False


def test_official_failure_returns_partial_after_tesserix_verification(tmp_path: Path) -> None:
    prepared = prepared_publication(tmp_path)
    runner = FakeRunner(
        [
            result(applied_document(prepared)),
            result(published_document(prepared)),
            result(b"verified registry digest signature\n"),
            result(b"server.json is valid\n"),
            result(stderr=b"official registry denied publication", exit_code=1),
        ]
    )
    stdout = io.StringIO()

    exit_code = run(
        [
            "publish",
            *evidence_arguments(tmp_path),
            "--idempotency-key",
            "publish-run-42",
            "--request-id",
            "request-cli-partial",
            "--official",
        ],
        runner=runner,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert exit_code == 6
    document = json.loads(stdout.getvalue())
    assert document["status"] == "partial"
    assert document["official_status"] == "failed"
    assert [arguments[:2] for arguments in runner.arguments[-2:]] == [
        ("mcp-publisher", "validate"),
        ("mcp-publisher", "publish"),
    ]


def test_validate_hashes_a_prebuilt_artifact_file(tmp_path: Path) -> None:
    artifact = tmp_path / "server.whl"
    artifact.write_bytes(b"prebuilt wheel")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    authoring = tmp_path / "authoring.json"
    authoring.write_text(
        AUTHORING.read_text(encoding="utf-8").replace("c" * 64, digest),
        encoding="utf-8",
    )
    arguments = evidence_arguments(tmp_path)
    arguments[arguments.index(str(AUTHORING))] = str(authoring)
    digest_flag = arguments.index("--artifact-digest")
    arguments[digest_flag : digest_flag + 2] = ["--artifact-file", str(artifact)]
    arguments[arguments.index("--artifact-uri") + 1] = (
        f"oci://ghcr.io/tesserix/settlements-mcp:3.1.0@sha256:{digest}"
    )
    stdout = io.StringIO()

    exit_code = run(["validate", *arguments], stdout=stdout, stderr=io.StringIO())

    assert exit_code == 0
    assert json.loads(stdout.getvalue())["artifact_digest"] == f"sha256:{digest}"


def test_cli_has_no_secret_bearing_arguments(tmp_path: Path) -> None:
    stderr = io.StringIO()

    exit_code = run(
        [
            "publish",
            *evidence_arguments(tmp_path),
            "--client-secret",
            "CCCCCCCCCCCCCCCC",
        ],
        stdout=io.StringIO(),
        stderr=stderr,
    )

    assert exit_code == 2
    error = json.loads(stderr.getvalue())
    assert error["code"] == "invalid_argument"
    assert "CCCCCCCCCCCCCCCC" not in stderr.getvalue()


def test_cli_environment_secret_is_redacted_from_delegate_failure(tmp_path: Path) -> None:
    runner = FakeRunner([result(b"CCCCCCCCCCCCCCCC")])
    stderr = io.StringIO()

    exit_code = run(
        [
            "publish",
            *evidence_arguments(tmp_path),
            "--idempotency-key",
            "publish-run-42",
            "--request-id",
            "request-cli-secret",
        ],
        runner=runner,
        environ={"AGENTIC_TOKEN": "CCCCCCCCCCCCCCCC"},
        stdout=io.StringIO(),
        stderr=stderr,
    )

    assert exit_code == 1
    error = json.loads(stderr.getvalue())
    assert error["code"] == "secret_material"
    assert "CCCCCCCCCCCCCCCC" not in stderr.getvalue()


def test_cli_rejects_malformed_environment_secrets_before_delegation(tmp_path: Path) -> None:
    runner = FakeRunner([])
    stderr = io.StringIO()

    exit_code = run(
        [
            "publish",
            *evidence_arguments(tmp_path),
            "--idempotency-key",
            "publish-run-42",
            "--request-id",
            "request-cli-malformed-secret",
        ],
        runner=runner,
        environ={"AGENTIC_CLIENT_SECRET": " bad"},
        stdout=io.StringIO(),
        stderr=stderr,
    )

    assert exit_code == 2
    assert json.loads(stderr.getvalue())["code"] == "manifest_invalid"
    assert " bad" not in stderr.getvalue()
    assert runner.arguments == []


def test_cli_error_shape_never_contains_manifest_or_tenant_payload(tmp_path: Path) -> None:
    manifest = tmp_path / "invalid.json"
    manifest.write_text('{"api_token":"CCCCCCCCCCCCCCCC"}', encoding="utf-8")
    arguments = evidence_arguments(tmp_path)
    arguments[arguments.index(str(AUTHORING))] = str(manifest)
    stderr = io.StringIO()

    exit_code = run(["validate", *arguments], stdout=io.StringIO(), stderr=stderr)

    assert exit_code == 2
    error = json.loads(stderr.getvalue())
    assert set(error) == {"code", "message", "request_id", "retryable"}
    assert error["code"] == "manifest_invalid"
    assert "CCCCCCCCCCCCCCCC" not in stderr.getvalue()
    assert "api_token" not in stderr.getvalue()
