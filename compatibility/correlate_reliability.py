from __future__ import annotations

import argparse
import contextlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

from tesserix_mcp_testkit import (
    ReliabilityLoadKind,
    correlate_agentgateway_reliability_window,
)

_MAX_SOURCE_BYTES = 8 * 1024 * 1024


def read_reliability_source(path: Path) -> str:
    descriptor = -1
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ValueError("reliability correlation source must be a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or not 1 <= opened.st_size <= _MAX_SOURCE_BYTES
        ):
            raise ValueError("reliability correlation source changed while opening")
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            encoded = source.read(_MAX_SOURCE_BYTES + 1)
        if len(encoded) != opened.st_size:
            raise ValueError("reliability correlation source changed while reading")
        return encoded.decode("utf-8")
    except ValueError:
        raise
    except (OSError, UnicodeError):
        raise ValueError("reliability correlation source could not be read") from None
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _write_evidence(path: Path, value: str) -> None:
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= _MAX_SOURCE_BYTES:
        raise ValueError("reliability correlation output target is invalid")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("reliability correlation output target is invalid")
    target = parent / path.name
    try:
        before = target.lstat()
    except FileNotFoundError:
        before = None
    if before is not None and (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode)):
        raise ValueError("reliability correlation output target is invalid")

    descriptor = -1
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=parent)
        with os.fdopen(descriptor, "wb", closefd=True) as temporary:
            descriptor = -1
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        try:
            current = target.lstat()
        except FileNotFoundError:
            current = None
        if (before is None) != (current is None) or (
            before is not None
            and current is not None
            and (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or current.st_dev != before.st_dev
                or current.st_ino != before.st_ino
            )
        ):
            raise ValueError("reliability correlation output target changed")
        os.replace(temporary_name, target)
        temporary_name = None
    except ValueError:
        raise
    except OSError:
        raise ValueError("reliability correlation output could not be written") from None
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if temporary_name is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary_name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--kind", required=True, choices=tuple(item.value for item in ReliabilityLoadKind)
    )
    parser.add_argument("--client-report", required=True, type=Path)
    parser.add_argument("--gateway-before", required=True, type=Path)
    parser.add_argument("--gateway-after", required=True, type=Path)
    parser.add_argument("--runtime-before", required=True, type=Path)
    parser.add_argument("--runtime-after", required=True, type=Path)
    parser.add_argument("--runtime-spans", required=True, type=Path)
    parser.add_argument("--pod-resources", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        evidence = correlate_agentgateway_reliability_window(
            kind=ReliabilityLoadKind(arguments.kind),
            client_report=read_reliability_source(arguments.client_report),
            gateway_metrics_before=read_reliability_source(arguments.gateway_before),
            gateway_metrics_after=read_reliability_source(arguments.gateway_after),
            runtime_metrics_before=read_reliability_source(arguments.runtime_before),
            runtime_metrics_after=read_reliability_source(arguments.runtime_after),
            runtime_spans=read_reliability_source(arguments.runtime_spans),
            pod_resource_samples=read_reliability_source(arguments.pod_resources),
        )
        _write_evidence(arguments.output, evidence.model_dump_json(indent=2) + "\n")
    except (OSError, TypeError, UnicodeError, ValueError):
        json.dump({"code": "reliability_correlation_failed"}, sys.stderr)
        sys.stderr.write("\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
