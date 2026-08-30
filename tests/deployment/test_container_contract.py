from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[2]
CONTAINER_ROOT = ROOT / "deploy" / "container"

CORE_BASE = (
    "ghcr.io/tesserix/base-python-runtime-3.14:20260829@"
    "sha256:3854f5d9d00705b14077bf6715feb9c3bd6d1ad2e41d5594b3c09c0a74c22add"
)
ADK_BASE = (
    "ghcr.io/tesserix/base-python-adk-3.14:20260829@"
    "sha256:5a6fd1863ed7f37f3929cc596d0ec063c3077c11713cd334f14d1df2b30ef386"
)
UV_IMAGE = (
    "ghcr.io/astral-sh/uv:0.12.7@"
    "sha256:95f2aa1fe59274951cfe9b0cbc7972e879ff1004bc8945d130a32eb0dbd85945"
)
DOCKERFILE_FRONTEND = (
    "docker/dockerfile:1.20@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d"
)

DOCKER_CONTEXT_ALLOWLIST = {
    "!LICENSE",
    "!README.md",
    "!compatibility/",
    "!compatibility/server.py",
    "!packages/",
    "!packages/tesserix-mcp-manifest/",
    "!packages/tesserix-mcp-manifest/pyproject.toml",
    "!packages/tesserix-mcp-publisher/",
    "!packages/tesserix-mcp-publisher/pyproject.toml",
    "!packages/tesserix-mcp-testkit/",
    "!packages/tesserix-mcp-testkit/pyproject.toml",
    "!pyproject.toml",
    "!src/",
    "!src/**",
    "!uv.lock",
}


def test_reference_dockerfiles_are_pinned_minimal_and_explicit_about_adk() -> None:
    core = (CONTAINER_ROOT / "core.Dockerfile").read_text(encoding="utf-8")
    adk = (CONTAINER_ROOT / "adk.Dockerfile").read_text(encoding="utf-8")

    assert f"ARG BASE_IMAGE={CORE_BASE}" in core
    assert f"ARG BASE_IMAGE={ADK_BASE}" in adk
    assert f"ARG UV_IMAGE={UV_IMAGE}" in core
    assert f"ARG UV_IMAGE={UV_IMAGE}" in adk
    assert core.startswith(f"# syntax={DOCKERFILE_FRONTEND}\n")
    assert adk.startswith(f"# syntax={DOCKERFILE_FRONTEND}\n")
    assert core.count("FROM ") >= 3
    assert adk.count("FROM ") >= 3

    assert "base-python-adk" not in core.casefold()
    assert "--extra adk" not in core.casefold()
    assert "tesserix-adk" not in core.casefold()
    assert "TESSERIX_ADK_VERSION" in adk
    assert "COPY --from=build /wheels/ /tmp/wheels/" in adk
    assert "/tmp/wheels/tesserix_mcp_runtime-*.whl" in adk
    assert "/tmp/runtime.whl" not in adk
    for document in (core, adk):
        assert "SETUPTOOLS_SCM_PRETEND_VERSION=${PACKAGE_VERSION}" in document
        assert "USER 10001:10001" in document
        assert 'ENTRYPOINT ["/usr/bin/tini", "--"' in document
        assert 'CMD ["--host", "0.0.0.0", "--port", "8000"' in document
        assert '"--allowed-host", "127.0.0.1"' in document
        assert '"--allowed-origin", "https://gateway.invalid"' in document
        assert "rm -f /bin/sh /bin/dash /bin/bash /usr/bin/dash /usr/bin/bash" in document
        assert "COPY . ." not in document
        assert "ARG TOKEN" not in document
        assert "ARG SECRET" not in document
        assert "ARG KEY" not in document


def test_docker_build_context_is_an_explicit_source_allowlist() -> None:
    rules = tuple(
        line
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )

    assert rules[0] == "**"
    assert set(rules[1:]) == DOCKER_CONTEXT_ALLOWLIST
    assert not any("secret" in rule.casefold() for rule in rules[1:])


def test_adk_variant_preserves_the_verified_base_dependency_lane() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    adk = (CONTAINER_ROOT / "adk.Dockerfile").read_text(encoding="utf-8")

    assert "opentelemetry-api>=1.42.1,<2" in project["dependencies"]
    assert project["optional-dependencies"]["otel"] == ["opentelemetry-sdk>=1.42.1,<2"]
    assert "runtime-requirements.txt" not in adk


def test_container_server_requires_explicit_non_loopback_host_and_origin_policy() -> None:
    source = (ROOT / "compatibility" / "server.py").read_text(encoding="utf-8")

    assert 'parser.add_argument("--host", default="127.0.0.1")' in source
    assert 'parser.add_argument("--allowed-host", action="append", default=[])' in source
    assert 'parser.add_argument("--allowed-origin", action="append", default=[])' in source
    assert "host=host" in source
    assert "allowed_hosts=allowed_hosts" in source
    assert "allowed_origins=allowed_origins" in source
