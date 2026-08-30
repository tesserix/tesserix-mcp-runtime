"""Race-resistant bounded hashing for prebuilt publication evidence."""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from .errors import PublicationErrorCode, PublicationValidationError
from .models import EvidenceReference

_MAX_EVIDENCE_BYTES = 512 * 1024 * 1024


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


def _invalid() -> PublicationValidationError:
    return PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID)


def evidence_reference_from_file(
    path: Path,
    *,
    uri: str,
    media_type: str,
    maximum_bytes: int,
) -> EvidenceReference:
    """Hash one existing regular non-symlink file without exposing its path."""

    if (
        not _is_runtime_instance(path, Path)
        or not _is_runtime_instance(uri, str)
        or not _is_runtime_instance(media_type, str)
        or _is_runtime_instance(maximum_bytes, bool)
        or not _is_runtime_instance(maximum_bytes, int)
        or not 1 <= maximum_bytes <= _MAX_EVIDENCE_BYTES
    ):
        raise _invalid()
    descriptor = -1
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise _invalid()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or not 1 <= opened.st_size <= maximum_bytes
        ):
            raise _invalid()
        digest = hashlib.sha256()
        consumed = 0
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            while True:
                chunk = source.read(min(64 * 1024, maximum_bytes + 1 - consumed))
                if not chunk:
                    break
                consumed += len(chunk)
                if consumed > maximum_bytes:
                    raise _invalid()
                digest.update(chunk)
        if consumed != opened.st_size:
            raise _invalid()
        return EvidenceReference(
            uri=uri,
            digest=f"sha256:{digest.hexdigest()}",
            media_type=media_type,
        )
    except PublicationValidationError:
        raise
    except (OSError, ValueError):
        raise _invalid() from None
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)


__all__ = ["evidence_reference_from_file"]
