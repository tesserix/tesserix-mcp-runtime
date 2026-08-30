from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).parents[1]
CONSTANTS = (
    ROOT / "packages" / "tesserix-mcp-manifest" / "src" / "tesserix_mcp_manifest" / "constants.py"
)
SCHEMA_DIRECTORY = ROOT / "packages" / "tesserix-mcp-manifest" / "schemas"
GITHUB_API = "https://api.github.com/repos/modelcontextprotocol/registry"
SCHEMA_SOURCE_DIRECTORY = "internal/validators/schemas"
MAX_API_BYTES = 1_048_576
MAX_SCHEMA_BYTES = 262_144
SCHEMA_NAME = re.compile(r"^(20\d{2}-\d{2}-\d{2})\.json$")


class SchemaUpdateError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SchemaRelease:
    version: str
    release: str
    commit: str
    content: bytes
    digest: str


def _request_json(url: str) -> object:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "tesserix-mcp-schema-updater",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=30) as response:
        payload = response.read(MAX_API_BYTES + 1)
    if len(payload) > MAX_API_BYTES:
        raise SchemaUpdateError("GitHub API response exceeds the fixed limit")
    return json.loads(payload)


def _mapping(value: object, *, field: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise SchemaUpdateError(f"{field} is not an object")
    return value


def _string(document: dict[str, object], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise SchemaUpdateError(f"{field} is missing")
    return value


def _release_commit(tag: str) -> str:
    reference = _mapping(
        _request_json(f"{GITHUB_API}/git/ref/tags/{quote(tag, safe='')}"),
        field="tag reference",
    )
    target = _mapping(reference.get("object"), field="tag target")
    target_type = _string(target, "type")
    target_sha = _string(target, "sha")
    if target_type == "tag":
        annotated = _mapping(
            _request_json(f"{GITHUB_API}/git/tags/{target_sha}"),
            field="annotated tag",
        )
        target = _mapping(annotated.get("object"), field="annotated tag target")
        target_type = _string(target, "type")
        target_sha = _string(target, "sha")
    if target_type != "commit" or re.fullmatch(r"[a-f0-9]{40}", target_sha) is None:
        raise SchemaUpdateError("release tag does not resolve to a commit")
    return target_sha


def _schema_content(blob_url: str) -> bytes:
    blob = _mapping(_request_json(blob_url), field="schema blob")
    if blob.get("encoding") != "base64":
        raise SchemaUpdateError("schema blob is not base64 encoded")
    encoded = _string(blob, "content")
    content = base64.b64decode("".join(encoded.split()), validate=True)
    if not content or len(content) > MAX_SCHEMA_BYTES:
        raise SchemaUpdateError("schema bytes exceed the fixed limit")
    return content


def _validate_schema(content: bytes, version: str) -> None:
    document = _mapping(json.loads(content), field="schema")
    expected_id = f"https://static.modelcontextprotocol.io/schemas/{version}/server.schema.json"
    if document.get("$id") != expected_id:
        raise SchemaUpdateError("schema identifier does not match its version")


def discover_latest_release() -> SchemaRelease:
    release_document = _mapping(
        _request_json(f"{GITHUB_API}/releases/latest"),
        field="latest release",
    )
    release = _string(release_document, "tag_name")
    commit = _release_commit(release)
    listing = _request_json(f"{GITHUB_API}/contents/{SCHEMA_SOURCE_DIRECTORY}?ref={commit}")
    if not isinstance(listing, list):
        raise SchemaUpdateError("schema directory response is not a list")
    candidates: list[tuple[str, str]] = []
    for raw_entry in listing:
        entry = _mapping(raw_entry, field="schema entry")
        name = entry.get("name")
        git_url = entry.get("git_url")
        if not isinstance(name, str) or not isinstance(git_url, str):
            continue
        match = SCHEMA_NAME.fullmatch(name)
        if match is not None:
            candidates.append((match.group(1), git_url))
    if not candidates:
        raise SchemaUpdateError("release contains no versioned server schema")
    version, blob_url = max(candidates)
    content = _schema_content(blob_url)
    _validate_schema(content, version)
    return SchemaRelease(
        version=version,
        release=release,
        commit=commit,
        content=content,
        digest=hashlib.sha256(content).hexdigest(),
    )


def _constant(document: str, name: str) -> str:
    pattern = re.compile(
        rf'^{re.escape(name)}: Final = (?:\(\n\s*)?"([^"]+)"(?:\n\))?',
        re.MULTILINE,
    )
    match = pattern.search(document)
    if match is None:
        raise SchemaUpdateError(f"{name} is missing from constants")
    return match.group(1)


def _replace_constant(document: str, name: str, value: str) -> str:
    pattern = re.compile(
        rf'^{re.escape(name)}: Final = (?:\(\n\s*)?"[^"]+"(?:\n\))?',
        re.MULTILINE,
    )
    updated, replacements = pattern.subn(f'{name}: Final = "{value}"', document)
    if replacements != 1:
        raise SchemaUpdateError(f"could not update {name}")
    return updated


def verify_checked_in_schema() -> SchemaRelease:
    constants = CONSTANTS.read_text(encoding="utf-8")
    version = _constant(constants, "OFFICIAL_SCHEMA_VERSION")
    digest = _constant(constants, "OFFICIAL_SCHEMA_SHA256")
    release = _constant(constants, "OFFICIAL_REGISTRY_RELEASE")
    commit = _constant(constants, "OFFICIAL_REGISTRY_COMMIT")
    schema_path = SCHEMA_DIRECTORY / f"official-server-{version}.schema.json"
    content = schema_path.read_bytes()
    if hashlib.sha256(content).hexdigest() != digest:
        raise SchemaUpdateError("checked-in schema digest does not match constants")
    _validate_schema(content, version)
    return SchemaRelease(version, release, commit, content, digest)


def update_from_latest_release() -> SchemaRelease:
    current = verify_checked_in_schema()
    latest = discover_latest_release()
    if current.version == latest.version and current.digest == latest.digest:
        return current
    schema_path = SCHEMA_DIRECTORY / f"official-server-{latest.version}.schema.json"
    schema_path.write_bytes(latest.content)
    constants = CONSTANTS.read_text(encoding="utf-8")
    for name, value in (
        ("OFFICIAL_SCHEMA_VERSION", latest.version),
        ("OFFICIAL_SCHEMA_SHA256", latest.digest),
        ("OFFICIAL_REGISTRY_RELEASE", latest.release),
        ("OFFICIAL_REGISTRY_COMMIT", latest.commit),
    ):
        constants = _replace_constant(constants, name, value)
    CONSTANTS.write_text(constants, encoding="utf-8")
    return verify_checked_in_schema()


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--verify", action="store_true")
    action.add_argument("--update", action="store_true")
    arguments = parser.parse_args()
    try:
        release = update_from_latest_release() if arguments.update else verify_checked_in_schema()
    except (
        SchemaUpdateError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        binascii.Error,
        HTTPError,
        URLError,
    ) as error:
        print(f"official MCP schema check failed: {error}", file=sys.stderr)
        return 1
    print(
        f"official MCP schema {release.version} verified "
        f"(registry {release.release} @ {release.commit})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
