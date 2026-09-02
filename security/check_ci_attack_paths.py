from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import yaml

_ACTION = re.compile(r"^\s*uses:\s+([^\s@]+)@([^\s#]+)(?:\s+#.*)?$")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ALLOWED_WRITES = {
    ("codeql.yml", "analyze", "security-events"),
    ("manifest-schema-update.yml", "update", "contents"),
    ("manifest-schema-update.yml", "update", "pull-requests"),
    ("release.yml", "publish", "artifact-metadata"),
    ("release.yml", "publish", "attestations"),
    ("release.yml", "publish", "id-token"),
    ("release.yml", "publish", "packages"),
    ("release.yml", "finalize", "contents"),
}


def _documents(root: Path) -> dict[str, str]:
    workflow_root = root / ".github" / "workflows"
    if not workflow_root.is_dir():
        return {}
    documents: dict[str, str] = {}
    for path in sorted(workflow_root.glob("*.yml")):
        try:
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return {}
        if not body or len(body.encode()) > 1024 * 1024:
            return {}
        documents[path.name] = body
    return documents


def _workflow(document: str) -> Mapping[str, object] | None:
    try:
        value: object = yaml.load(document, Loader=yaml.BaseLoader)
    except yaml.YAMLError:
        return None
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        return None
    return cast(Mapping[str, object], value)


def _read_only(permissions: object) -> bool:
    return isinstance(permissions, dict) and all(
        isinstance(name, str) and value in {"read", "none"} for name, value in permissions.items()
    )


def _triggers_pull_request(workflow: Mapping[str, object]) -> bool:
    triggers = workflow.get("on")
    return isinstance(triggers, dict) and "pull_request" in triggers


def _contains_secret_reference(value: object) -> bool:
    if isinstance(value, str):
        return "secrets." in value
    if isinstance(value, dict):
        return any(_contains_secret_reference(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_secret_reference(item) for item in value)
    return False


def _pull_request_secrets_are_guarded(workflow: Mapping[str, object]) -> bool:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return False
    for raw_job in jobs.values():
        if not isinstance(raw_job, dict):
            return False
        if not _contains_secret_reference(raw_job):
            continue
        if raw_job.get("if") != "github.event_name != 'pull_request'":
            return False
    return True


def _write_permissions(
    filename: str,
    workflow: Mapping[str, object],
) -> set[tuple[str, str, str]] | None:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return None
    writes: set[tuple[str, str, str]] = set()
    for job_name, raw_job in jobs.items():
        if not isinstance(job_name, str) or not isinstance(raw_job, dict):
            return None
        permissions = raw_job.get("permissions", {})
        if not isinstance(permissions, dict):
            return None
        for permission, access in permissions.items():
            if not isinstance(permission, str) or not isinstance(access, str):
                return None
            if access == "write":
                writes.add((filename, job_name, permission))
            elif access not in {"read", "none"}:
                return None
    return writes


def _immutable_actions(documents: Mapping[str, str]) -> bool:
    observed = 0
    for document in documents.values():
        for line in document.splitlines():
            if "uses:" not in line:
                continue
            stripped = line.strip()
            if stripped.startswith("uses: ./.github/workflows/"):
                continue
            match = _ACTION.fullmatch(line)
            if match is None or _SHA.fullmatch(match.group(2)) is None:
                return False
            observed += 1
    return observed > 0


def _least_privilege(
    parsed: Mapping[str, Mapping[str, object]],
) -> bool:
    writes: set[tuple[str, str, str]] = set()
    for filename, workflow in parsed.items():
        if not _read_only(workflow.get("permissions")):
            return False
        job_writes = _write_permissions(filename, workflow)
        if job_writes is None:
            return False
        writes.update(job_writes)
    return writes == _ALLOWED_WRITES


def _untrusted_pull_requests(
    documents: Mapping[str, str],
    parsed: Mapping[str, Mapping[str, object]],
) -> bool:
    for filename, workflow in parsed.items():
        document = documents[filename]
        if "pull_request_target" in document:
            return False
        if not _triggers_pull_request(workflow):
            continue
        if "secrets." in document and not _pull_request_secrets_are_guarded(workflow):
            return False
        if document.count("actions/checkout@") != document.count("persist-credentials: false"):
            return False
        writes = _write_permissions(filename, workflow)
        if writes is None or writes.difference({("codeql.yml", "analyze", "security-events")}):
            return False
    return True


def _dependency_policy(documents: Mapping[str, str]) -> bool:
    dependency = documents.get("dependency-review.yml", "")
    security = documents.get("security.yml", "")
    release = documents.get("release.yml", "")
    return all(
        (
            "pull_request:" in dependency,
            "actions/dependency-review-action@" in dependency,
            "fail-on-severity: high" in dependency,
            "deny-licenses:" in dependency,
            "pip-audit --requirement" in security,
            "--require-hashes" in security,
            "security/check_licenses.py" in security,
            "./.github/workflows/security.yml" in release,
        )
    )


def check_ci_attack_paths(root: Path) -> dict[str, bool]:
    if not isinstance(root, Path) or not root.is_absolute() or not root.is_dir():
        raise ValueError("CI attack-path root must be an absolute directory")
    documents = _documents(root)
    parsed: dict[str, Mapping[str, object]] = {}
    for filename, document in documents.items():
        workflow = _workflow(document)
        if workflow is None:
            parsed = {}
            break
        parsed[filename] = workflow
    return {
        "ci.immutable_actions": _immutable_actions(documents),
        "ci.least_privilege_permissions": bool(parsed) and _least_privilege(parsed),
        "ci.untrusted_pull_request": bool(parsed) and _untrusted_pull_requests(documents, parsed),
        "dependency.release_policy": _dependency_policy(documents),
    }


def main() -> int:
    report = check_ci_attack_paths(Path(__file__).parents[1])
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if all(report.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["check_ci_attack_paths"]
