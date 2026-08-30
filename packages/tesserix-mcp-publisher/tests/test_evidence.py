from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import cast

import pytest
from tesserix_mcp_publisher import (
    PublicationErrorCode,
    PublicationValidationError,
    evidence_reference_from_file,
)


def test_evidence_file_is_hashed_without_publishing_local_path(tmp_path: Path) -> None:
    content = b'{"spdxVersion":"SPDX-2.3"}'
    source = tmp_path / "sbom.spdx.json"
    source.write_bytes(content)

    reference = evidence_reference_from_file(
        source,
        uri="https://artifacts.example.com/orders/1.2.3/sbom.spdx.json",
        media_type="application/spdx+json",
        maximum_bytes=1024,
    )

    assert reference.digest == f"sha256:{hashlib.sha256(content).hexdigest()}"
    assert reference.uri == "https://artifacts.example.com/orders/1.2.3/sbom.spdx.json"
    assert str(tmp_path) not in str(reference.to_document())


@pytest.mark.parametrize("content", [b"", b"x" * 17], ids=["empty", "oversized"])
def test_evidence_file_must_be_nonempty_and_bounded(
    tmp_path: Path,
    content: bytes,
) -> None:
    source = tmp_path / "evidence.json"
    source.write_bytes(content)

    with pytest.raises(PublicationValidationError) as caught:
        evidence_reference_from_file(
            source,
            uri="https://artifacts.example.com/evidence.json",
            media_type="application/json",
            maximum_bytes=16,
        )

    assert caught.value.code is PublicationErrorCode.MANIFEST_INVALID
    assert str(source) not in str(caught.value)


def test_evidence_file_rejects_a_symlink_without_reading_its_target(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"secret":"EEEEEEEEEEEEEEEE"}', encoding="utf-8")
    link = tmp_path / "evidence.json"
    os.symlink(target, link)

    with pytest.raises(PublicationValidationError) as caught:
        evidence_reference_from_file(
            link,
            uri="https://artifacts.example.com/evidence.json",
            media_type="application/json",
            maximum_bytes=1024,
        )

    assert caught.value.code is PublicationErrorCode.MANIFEST_INVALID
    assert "EEEEEEEEEEEEEEEE" not in str(caught.value)


def test_evidence_file_rejects_replacement_between_identity_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "evidence.json"
    source.write_text('{"version":1}', encoding="utf-8")
    replacement = tmp_path / "replacement.json"
    replacement.write_text('{"secret":"RRRRRRRRRRRRRRRR"}', encoding="utf-8")
    real_open = os.open
    raced = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o600,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal raced
        if not raced:
            raced = True
            replacement.replace(source)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", racing_open)

    with pytest.raises(PublicationValidationError) as caught:
        evidence_reference_from_file(
            source,
            uri="https://artifacts.example.com/evidence.json",
            media_type="application/json",
            maximum_bytes=1024,
        )

    assert caught.value.code is PublicationErrorCode.MANIFEST_INVALID
    assert "RRRRRRRRRRRRRRRR" not in str(caught.value)


@pytest.mark.parametrize("maximum", [True, 0, 512 * 1024 * 1024 + 1])
def test_evidence_hash_limit_is_a_bounded_integer(tmp_path: Path, maximum: object) -> None:
    source = tmp_path / "evidence.json"
    source.write_text("{}", encoding="utf-8")

    with pytest.raises(PublicationValidationError):
        evidence_reference_from_file(
            source,
            uri="https://artifacts.example.com/evidence.json",
            media_type="application/json",
            maximum_bytes=cast(int, maximum),
        )
