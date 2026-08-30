"""Safe validate, inspect, manifest, and delegated publish commands."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import stat
import sys
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Never, TextIO, cast

from tesserix_mcp_runtime import SecretRedactor, SecretValue

from .activation import (
    ActivationClock,
    ActivationPhase,
    ActivationTarget,
    ActivationWaiter,
    SystemActivationClock,
)
from .commands import CommandRunner, SubprocessCommandRunner
from .delegates import AgenticCLIPublisher, OfficialMCPPublisherCLI
from .errors import PublicationError, PublicationErrorCode, PublicationValidationError
from .evidence import evidence_reference_from_file
from .models import EvidenceReference, PreparedPublication, PublicationEvidence, PublicationStatus
from .preparation import prepare_publication
from .workflow import PublisherWorkflow

_MANIFEST_MAX_BYTES = 1024 * 1024
_ARTIFACT_MAX_BYTES = 512 * 1024 * 1024
_EVIDENCE_MAX_BYTES = 8 * 1024 * 1024


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise _UsageError


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="tesserix-mcp-runtime")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "inspect", "manifest", "publish"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--runtime-version", required=True)
        command.add_argument("--artifact-uri", required=True)
        artifact = command.add_mutually_exclusive_group(required=True)
        artifact.add_argument("--artifact-file", type=Path)
        artifact.add_argument("--artifact-digest")
        command.add_argument(
            "--artifact-media-type",
            default="application/octet-stream",
        )
        command.add_argument("--sbom-file", type=Path, required=True)
        command.add_argument("--sbom-uri", required=True)
        command.add_argument("--sbom-media-type", default="application/spdx+json")
        command.add_argument("--provenance-file", type=Path, required=True)
        command.add_argument("--provenance-uri", required=True)
        command.add_argument(
            "--provenance-media-type",
            default="application/vnd.in-toto+jsonl",
        )
        if name == "manifest":
            command.add_argument("--output-dir", type=Path, required=True)
        if name == "publish":
            command.add_argument("--idempotency-key", required=True)
            command.add_argument("--request-id")
            command.add_argument("--dry-run", action="store_true")
            command.add_argument("--official", action="store_true")
    activation = commands.add_parser("activation")
    activation.add_argument("--ref", required=True)
    activation.add_argument("--registry-digest", required=True)
    activation.add_argument("--artifact-digest", required=True)
    activation.add_argument("--generation", type=int)
    activation.add_argument("--request-id")
    activation.add_argument("--wait-for", choices=tuple(ActivationPhase))
    activation.add_argument("--timeout-seconds", type=float, default=120.0)
    activation.add_argument("--poll-interval-seconds", type=float, default=2.0)
    return parser


def _read_regular_file(path: Path, *, maximum: int) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise OSError
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or not 1 <= opened.st_size <= maximum
        ):
            raise OSError
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            content = source.read(maximum + 1)
        if len(content) != opened.st_size or len(content) > maximum:
            raise OSError
        return content
    except OSError:
        raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID) from None
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _evidence(arguments: argparse.Namespace) -> PublicationEvidence:
    artifact_file = cast(Path | None, arguments.artifact_file)
    if artifact_file is None:
        artifact = EvidenceReference(
            uri=cast(str, arguments.artifact_uri),
            digest=cast(str, arguments.artifact_digest),
            media_type=cast(str, arguments.artifact_media_type),
        )
    else:
        artifact = evidence_reference_from_file(
            artifact_file,
            uri=cast(str, arguments.artifact_uri),
            media_type=cast(str, arguments.artifact_media_type),
            maximum_bytes=_ARTIFACT_MAX_BYTES,
        )
    sbom = evidence_reference_from_file(
        cast(Path, arguments.sbom_file),
        uri=cast(str, arguments.sbom_uri),
        media_type=cast(str, arguments.sbom_media_type),
        maximum_bytes=_EVIDENCE_MAX_BYTES,
    )
    provenance = evidence_reference_from_file(
        cast(Path, arguments.provenance_file),
        uri=cast(str, arguments.provenance_uri),
        media_type=cast(str, arguments.provenance_media_type),
        maximum_bytes=_EVIDENCE_MAX_BYTES,
    )
    return PublicationEvidence(artifact=artifact, sbom=sbom, provenance=provenance)


def _prepare(arguments: argparse.Namespace) -> PreparedPublication:
    source = _read_regular_file(
        cast(Path, arguments.manifest),
        maximum=_MANIFEST_MAX_BYTES,
    )
    return prepare_publication(
        source,
        runtime_version=cast(str, arguments.runtime_version),
        evidence=_evidence(arguments),
    )


def _summary(prepared: PreparedPublication, *, status: str) -> dict[str, Any]:
    return {
        "artifact_digest": prepared.evidence.artifact.digest,
        "name": prepared.name,
        "namespace": prepared.namespace,
        "provenance_digest": prepared.evidence.provenance.digest,
        "ref": prepared.ref,
        "registry_digest": prepared.registry_digest,
        "sbom_digest": prepared.evidence.sbom.digest,
        "status": status,
        "version": prepared.version,
    }


def _write_json(stream: TextIO, value: Mapping[str, object]) -> None:
    stream.write(json.dumps(value, separators=(",", ":"), sort_keys=True))
    stream.write("\n")


def _write_manifests(output_directory: Path, prepared: PreparedPublication) -> None:
    try:
        info = output_directory.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise OSError
        targets = (
            (output_directory / "server.json", prepared.server_json),
            (output_directory / "mcpserver.json", prepared.registry_manifest),
        )
        if any(target.exists() for target, _ in targets):
            raise OSError
        created: list[Path] = []
        try:
            for target, content in targets:
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb", closefd=True) as destination:
                    destination.write(content)
                    destination.flush()
                    os.fsync(destination.fileno())
                created.append(target)
        except OSError:
            for target in created:
                with contextlib.suppress(OSError):
                    target.unlink()
            raise
    except OSError:
        raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID) from None


def _redactor(environment: Mapping[str, str]) -> SecretRedactor:
    protected: list[SecretValue] = []
    for name in ("AGENTIC_TOKEN", "AGENTIC_CLIENT_SECRET"):
        value = environment.get(name, "")
        if value:
            protected.append(SecretValue(value))
    return SecretRedactor(known_secrets=tuple(protected))


def _exit_code(error: PublicationError) -> int:
    if error.code in {
        PublicationErrorCode.INVALID_ARGUMENT,
        PublicationErrorCode.MANIFEST_INVALID,
        PublicationErrorCode.EVIDENCE_REQUIRED,
        PublicationErrorCode.ARTIFACT_DIGEST_MISMATCH,
    }:
        return 2
    if error.code is PublicationErrorCode.CONFLICT:
        return 3
    if error.code is PublicationErrorCode.ACTIVATION_SUPERSEDED:
        return 3
    if error.code is PublicationErrorCode.UNAVAILABLE:
        return 4
    if error.code is PublicationErrorCode.UNKNOWN_OUTCOME:
        return 5
    if error.code is PublicationErrorCode.ACTIVATION_FAILED:
        return 7
    if error.code is PublicationErrorCode.ACTIVATION_TIMEOUT:
        return 8
    return 1


def run(
    argv: list[str],
    *,
    runner: CommandRunner | None = None,
    clock: ActivationClock | None = None,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the bounded publisher CLI with injectable process and I/O boundaries."""

    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    environment = os.environ if environ is None else environ
    try:
        arguments = _parser().parse_args(argv)
        command = cast(str, arguments.command)
        if command == "activation":
            redactor = _redactor(environment)
            resolved_runner = (
                SubprocessCommandRunner(redactor=redactor) if runner is None else runner
            )
            target = ActivationTarget(
                ref=cast(str, arguments.ref),
                registry_digest=cast(str, arguments.registry_digest),
                artifact_digest=cast(str, arguments.artifact_digest),
                generation=cast(int | None, arguments.generation),
            )
            request_id_value = cast(str | None, arguments.request_id)
            request_id = request_id_value or f"activation-{uuid.uuid4()}"
            client = AgenticCLIPublisher(runner=resolved_runner, redactor=redactor)
            waiter = ActivationWaiter(
                client=client,
                clock=SystemActivationClock() if clock is None else clock,
            )
            wait_for = cast(str | None, arguments.wait_for)
            if wait_for is None:
                status = asyncio.run(waiter.observe(target, request_id=request_id))
            else:
                status = asyncio.run(
                    waiter.wait(
                        target,
                        target_phase=ActivationPhase(wait_for),
                        timeout_seconds=cast(float, arguments.timeout_seconds),
                        poll_interval_seconds=cast(
                            float,
                            arguments.poll_interval_seconds,
                        ),
                        request_id=request_id,
                    )
                )
            _write_json(output, status.explain(request_id=request_id))
            return 0

        prepared = _prepare(arguments)
        if command in {"validate", "inspect"}:
            _write_json(
                output,
                _summary(prepared, status=("valid" if command == "validate" else "inspected")),
            )
            return 0
        if command == "manifest":
            _write_manifests(cast(Path, arguments.output_dir), prepared)
            _write_json(output, _summary(prepared, status="written"))
            return 0

        redactor = _redactor(environment)
        resolved_runner = SubprocessCommandRunner(redactor=redactor) if runner is None else runner
        publish_official = cast(bool, arguments.official)
        workflow = PublisherWorkflow(
            tesserix=AgenticCLIPublisher(runner=resolved_runner, redactor=redactor),
            official=(
                OfficialMCPPublisherCLI(runner=resolved_runner, redactor=redactor)
                if publish_official
                else None
            ),
        )
        request_id_value = cast(str | None, arguments.request_id)
        outcome = asyncio.run(
            workflow.execute(
                prepared,
                idempotency_key=cast(str, arguments.idempotency_key),
                request_id=request_id_value or f"publish-{uuid.uuid4()}",
                dry_run=cast(bool, arguments.dry_run),
                publish_official=publish_official,
            )
        )
        _write_json(output, outcome.to_dict())
        return 6 if outcome.status is PublicationStatus.PARTIAL else 0
    except _UsageError:
        error = PublicationError(
            PublicationErrorCode.INVALID_ARGUMENT,
            request_id="publication-cli",
        )
    except PublicationError as caught:
        error = caught
    except (OSError, TypeError, ValueError):
        error = PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID)
    _write_json(errors, error.to_dict())
    return _exit_code(error)


def main(argv: list[str] | None = None) -> int:
    return run(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    raise SystemExit(main())
