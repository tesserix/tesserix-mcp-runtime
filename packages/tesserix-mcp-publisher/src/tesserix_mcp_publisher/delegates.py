"""Adapters for shipped Agentic Registry and official MCP publisher CLIs."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from collections.abc import Generator, Mapping
from pathlib import Path
from typing import Any, NoReturn, TypeGuard, cast

from tesserix_mcp_runtime import JsonValue, RedactionPolicy, registry_artifact_digest

from .activation import (
    ActivationContractError,
    ActivationStatus,
    ActivationSupersededError,
    ActivationTarget,
)
from .commands import CommandLimits, CommandResult, CommandRunner
from .errors import PublicationError, PublicationErrorCode
from .models import PreparedPublication, PublishedArtifact, PublishReceipt

_DEFAULT_LIMITS = CommandLimits()


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


class _DuplicateKeyError(Exception):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_constant(_: str) -> NoReturn:
    raise ValueError


def _mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    if not isinstance(value, Mapping):
        return False
    mapping = cast(Mapping[object, object], value)
    return all(_is_runtime_instance(key, str) for key in mapping)


def _string(value: object) -> TypeGuard[str]:
    return _is_runtime_instance(value, str)


def _list(value: object) -> TypeGuard[list[object]]:
    return _is_runtime_instance(value, list)


def _text(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not _string(value):
        raise ValueError
    return value


def _string_mapping(value: object) -> dict[str, str]:
    if not _mapping(value) or not all(_is_runtime_instance(item, str) for item in value.values()):
        raise ValueError
    return cast(dict[str, str], dict(value))


@contextlib.contextmanager
def _private_document(name: str, content: bytes) -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory(prefix="tesserix-mcp-publish-") as directory:
        path = Path(directory) / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        except Exception:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            raise
        yield path


class _Delegate:
    def __init__(
        self,
        *,
        runner: CommandRunner,
        redactor: RedactionPolicy,
        limits: CommandLimits,
    ) -> None:
        if not _is_runtime_instance(runner, CommandRunner):
            raise TypeError("runner must implement CommandRunner")
        if not _is_runtime_instance(redactor, RedactionPolicy):
            raise TypeError("redactor must implement RedactionPolicy")
        if not _is_runtime_instance(limits, CommandLimits):
            raise TypeError("limits must be CommandLimits")
        self._runner = runner
        self._redactor = redactor
        self._limits = limits

    def _checked(self, result: CommandResult, *, request_id: str) -> bytes:
        if (
            not _is_runtime_instance(result, CommandResult)
            or len(result.stdout) > self._limits.max_stdout_bytes
            or len(result.stderr) > self._limits.max_stderr_bytes
        ):
            raise PublicationError(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            )
        try:
            stdout = result.stdout.decode("utf-8")
            stderr = result.stderr.decode("utf-8")
            if (
                self._redactor.redact_text(stdout) != stdout
                or self._redactor.redact_text(stderr) != stderr
            ):
                raise PublicationError(
                    PublicationErrorCode.SECRET_MATERIAL,
                    request_id=request_id,
                )
        except UnicodeDecodeError:
            raise PublicationError(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            ) from None
        except PublicationError:
            raise
        except Exception:
            raise PublicationError(
                PublicationErrorCode.SECRET_MATERIAL,
                request_id=request_id,
            ) from None
        if result.exit_code != 0:
            safe = f"{stdout}\n{stderr}".lower()
            if "409" in safe or "conflict" in safe:
                code = PublicationErrorCode.CONFLICT
                retryable = False
            elif any(
                marker in safe
                for marker in ("429", "502", "503", "connection", "timeout", "unavailable")
            ):
                code = PublicationErrorCode.UNAVAILABLE
                retryable = True
            else:
                code = PublicationErrorCode.COMMAND_FAILED
                retryable = False
            raise PublicationError(code, request_id=request_id, retryable=retryable)
        return result.stdout

    def _document(self, result: CommandResult, *, request_id: str) -> Mapping[str, object]:
        raw = self._checked(result, request_id=request_id)
        try:
            document = json.loads(
                raw,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError, _DuplicateKeyError):
            raise PublicationError(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            ) from None
        if not _mapping(document):
            raise PublicationError(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            )
        return document


class AgenticCLIPublisher(_Delegate):
    """Delegate auth, atomic apply, exact pull, and signature verification."""

    def __init__(
        self,
        *,
        runner: CommandRunner,
        redactor: RedactionPolicy,
        limits: CommandLimits = _DEFAULT_LIMITS,
        executable: str = "agentic",
    ) -> None:
        super().__init__(runner=runner, redactor=redactor, limits=limits)
        if (
            not _is_runtime_instance(executable, str)
            or not executable
            or len(executable) > 1_024
            or any(character in executable for character in ("\x00", "\r", "\n"))
        ):
            raise ValueError("agentic executable must be a bounded path")
        self._executable = executable

    async def remote_validate(
        self,
        prepared: PreparedPublication,
        *,
        idempotency_key: str,
        request_id: str,
    ) -> None:
        status = await self._runner.run(
            (self._executable, "status"),
            request_id=request_id,
        )
        self._checked(status, request_id=request_id)
        with _private_document("mcpserver.json", prepared.registry_manifest) as path:
            result = await self._runner.run(
                (
                    self._executable,
                    "apply",
                    "-f",
                    str(path),
                    "--dry-run",
                    "--idempotency-key",
                    idempotency_key,
                ),
                request_id=request_id,
            )
        document = self._document(result, request_id=request_id)
        if document.get("dry_run") is not True or document.get("count") != 1:
            raise PublicationError(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            )

    async def publish(
        self,
        prepared: PreparedPublication,
        *,
        idempotency_key: str,
        request_id: str,
    ) -> PublishReceipt:
        with _private_document("mcpserver.json", prepared.registry_manifest) as path:
            result = await self._runner.run(
                (
                    self._executable,
                    "apply",
                    "-f",
                    str(path),
                    "--idempotency-key",
                    idempotency_key,
                ),
                request_id=request_id,
            )
        document = self._document(result, request_id=request_id)
        applied = document.get("applied")
        if document.get("count") != 1 or not _list(applied) or len(applied) != 1:
            raise PublicationError(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            )
        item = applied[0]
        try:
            if (
                not _mapping(item)
                or _text(item, "kind") != "MCPServer"
                or _text(item, "name") != prepared.name
                or _text(item, "namespace") != prepared.namespace
                or _text(item, "tag") != prepared.version
                or not _is_runtime_instance(item.get("created"), bool)
            ):
                raise ValueError
            return PublishReceipt(created=cast(bool, item["created"]))
        except (KeyError, TypeError, ValueError):
            raise PublicationError(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            ) from None

    async def fetch(
        self,
        prepared: PreparedPublication,
        *,
        request_id: str,
    ) -> PublishedArtifact:
        document = await self._pull(
            name=prepared.name,
            version=prepared.version,
            request_id=request_id,
        )
        return self._artifact(document, request_id=request_id)

    async def _pull(
        self,
        *,
        name: str,
        version: str,
        request_id: str,
    ) -> Mapping[str, object]:
        result = await self._runner.run(
            (
                self._executable,
                "pull",
                "mcpservers",
                name,
                "--tag",
                version,
            ),
            request_id=request_id,
        )
        return self._document(result, request_id=request_id)

    @staticmethod
    def _artifact(
        document: Mapping[str, object],
        *,
        request_id: str,
    ) -> PublishedArtifact:
        try:
            metadata_value = document.get("metadata")
            spec_value = document.get("spec")
            if not _mapping(metadata_value) or not _mapping(spec_value):
                raise ValueError
            labels = _string_mapping(metadata_value.get("labels"))
            digest = _text(metadata_value, "digest")
            computed = registry_artifact_digest(
                kind=_text(document, "kind"),
                name=_text(metadata_value, "name"),
                namespace=_text(metadata_value, "namespace"),
                tag=_text(metadata_value, "tag"),
                labels=labels,
                spec=cast(Mapping[str, JsonValue], spec_value),
            )
            if digest != computed:
                raise ValueError
            return PublishedArtifact(
                name=_text(metadata_value, "name"),
                namespace=_text(metadata_value, "namespace"),
                version=_text(metadata_value, "tag"),
                ref=_text(metadata_value, "ref"),
                digest=digest,
                signature=_text(metadata_value, "signature"),
                signed_by=_text(metadata_value, "signedBy"),
            )
        except (TypeError, ValueError):
            raise PublicationError(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            ) from None

    async def fetch_activation(
        self,
        target: ActivationTarget,
        *,
        request_id: str,
    ) -> ActivationStatus:
        if not _is_runtime_instance(target, ActivationTarget):
            raise TypeError("target must be ActivationTarget")
        document = await self._pull(
            name=target.name,
            version=target.version,
            request_id=request_id,
        )
        artifact = self._artifact(document, request_id=request_id)
        if (
            artifact.name != target.name
            or artifact.namespace != target.namespace
            or artifact.version != target.version
            or artifact.ref != target.ref
            or artifact.digest != target.registry_digest
        ):
            raise ActivationSupersededError(request_id=request_id)
        try:
            spec = document.get("spec")
            status = document.get("status")
            if not _mapping(spec) or not _mapping(status):
                raise ValueError
            extension = spec.get("x-tesserix")
            if not _mapping(extension):
                raise ValueError
            publication = extension.get("publication")
            if not _mapping(publication):
                raise ValueError
            delivery_artifact = publication.get("artifact")
            if not _mapping(delivery_artifact):
                raise ValueError
            if _text(delivery_artifact, "digest") != target.artifact_digest:
                raise ActivationSupersededError(request_id=request_id)
            activation = ActivationStatus.from_document(
                status.get("activation"),
                request_id=request_id,
            )
        except ActivationSupersededError:
            raise
        except ActivationContractError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ActivationContractError(request_id=request_id) from None
        if (
            activation.ref != target.ref
            or activation.registry_digest != target.registry_digest
            or activation.artifact_digest != target.artifact_digest
            or (target.generation is not None and activation.generation != target.generation)
        ):
            raise ActivationSupersededError(request_id=request_id)
        return activation

    async def verify(
        self,
        artifact: PublishedArtifact,
        *,
        request_id: str,
    ) -> None:
        result = await self._runner.run(
            (
                self._executable,
                "verify",
                "mcpservers",
                artifact.name,
                "--tag",
                artifact.version,
            ),
            request_id=request_id,
        )
        self._checked(result, request_id=request_id)


class OfficialMCPPublisherCLI(_Delegate):
    """Explicit official MCP Registry target with no target override flags."""

    def __init__(
        self,
        *,
        runner: CommandRunner,
        redactor: RedactionPolicy,
        limits: CommandLimits = _DEFAULT_LIMITS,
        executable: str = "mcp-publisher",
    ) -> None:
        super().__init__(runner=runner, redactor=redactor, limits=limits)
        if not _is_runtime_instance(executable, str) or not executable:
            raise ValueError("official publisher executable must be a path")
        self._executable = executable

    async def validate(self, prepared: PreparedPublication, *, request_id: str) -> None:
        with _private_document("server.json", prepared.server_json) as path:
            result = await self._runner.run(
                (self._executable, "validate", str(path)),
                request_id=request_id,
            )
        self._checked(result, request_id=request_id)

    async def publish(self, prepared: PreparedPublication, *, request_id: str) -> None:
        with _private_document("server.json", prepared.server_json) as path:
            result = await self._runner.run(
                (self._executable, "publish", str(path)),
                request_id=request_id,
            )
        try:
            self._checked(result, request_id=request_id)
        except PublicationError:
            raise PublicationError(
                PublicationErrorCode.OFFICIAL_PUBLICATION_FAILED,
                request_id=request_id,
            ) from None


__all__ = ["AgenticCLIPublisher", "OfficialMCPPublisherCLI"]
