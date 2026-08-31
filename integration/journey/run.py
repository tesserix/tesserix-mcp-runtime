from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from tesserix_mcp_testkit import (
    JourneyEvidenceError,
    SecurityReportError,
    scan_journey_surfaces,
)

from integration.journey.real import RealJourneyConfig, run_real_journey
from integration.journey.runner import JourneyRunError
from integration.journey.stack import ComposeStack, JourneyStackError

_SERVICES = (
    "backing",
    "gateway-candidate",
    "gateway-good",
    "identity",
    "registry",
    "runtime-bad",
    "runtime-good",
)


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the disposable MCP release journey")
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--registry-image", required=True)
    parser.add_argument("--runtime-artifact-digest", required=True)
    parser.add_argument("--package-digest", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=Path(__file__).with_name("compose.yaml"),
    )
    parser.add_argument("--compose-standalone", type=Path)
    parser.add_argument("--run-id")
    return parser


def _project_name(run_id: str) -> str:
    normalized = run_id.lower().replace(":", "-").replace(".", "-")
    digest = hashlib.sha256(run_id.encode()).hexdigest()[:16]
    return f"mcp-{normalized[:42]}-{digest}"


def _invalid_run_id(run_id: str) -> str:
    return "invalid-" + hashlib.sha256(run_id.encode()).hexdigest()[:16]


def _write_failure(
    *,
    output_dir: Path,
    run_id: str,
    created_at: str,
    code: str,
    stack: ComposeStack | None,
) -> None:
    failure = _canonical_json(
        {
            "code": code,
            "created_at": created_at,
            "run_id": run_id,
            "status": "failed",
        }
    )
    scan_journey_surfaces((failure,))
    surfaces: dict[str, bytes] = {}
    if stack is not None:
        try:
            for service in _SERVICES:
                surfaces[f"failure-logs/{service}.log"] = stack.logs(service)
            scan_journey_surfaces(surfaces.values())
        except (JourneyEvidenceError, JourneyStackError, ValueError):
            surfaces = {}
    for relative, body in surfaces.items():
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    (output_dir / "journey-failure.json").write_bytes(failure)


def run(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    now = datetime.now(UTC).replace(microsecond=0)
    created_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    run_id = arguments.run_id or now.strftime("journey-%Y%m%dT%H%M%SZ")
    output_dir = arguments.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    executable = (
        (str(arguments.compose_standalone.resolve()),)
        if arguments.compose_standalone is not None
        else ("docker", "compose")
    )
    stack: ComposeStack | None = None
    failure_run_id = _invalid_run_id(run_id)
    try:
        config = RealJourneyConfig(
            output_dir=output_dir,
            runtime_artifact_digest=arguments.runtime_artifact_digest,
            package_digest=arguments.package_digest,
            source_revision=arguments.source_revision,
            run_id=run_id,
            created_at=created_at,
        )
        failure_run_id = run_id
        stack = ComposeStack(
            compose_file=arguments.compose_file.resolve(),
            project_name=_project_name(run_id),
            runtime_image=arguments.runtime_image,
            registry_image=arguments.registry_image,
            output_dir=output_dir,
            executable=executable,
        )
        asyncio.run(run_real_journey(config, stack=stack))
    except (
        JourneyEvidenceError,
        JourneyRunError,
        JourneyStackError,
        SecurityReportError,
        ValueError,
    ) as error:
        code = getattr(error, "code", "configuration_invalid")
        _write_failure(
            output_dir=output_dir,
            run_id=failure_run_id,
            created_at=created_at,
            code=str(code),
            stack=stack,
        )
        print(f"journey failed: {code}", file=sys.stderr)
        return 1
    except Exception:
        _write_failure(
            output_dir=output_dir,
            run_id=failure_run_id,
            created_at=created_at,
            code="unexpected_failure",
            stack=stack,
        )
        print("journey failed: unexpected_failure", file=sys.stderr)
        return 1
    finally:
        if stack is not None:
            with suppress(JourneyStackError):
                stack.down()
    print(str(output_dir / "journey-evidence.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
