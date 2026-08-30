from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml
from integration.journey.stack import (
    CommandExecutor,
    ComposeStack,
    JourneyStackError,
)

ROOT = Path(__file__).parents[2]
COMPOSE = ROOT / "integration" / "journey" / "compose.yaml"
DOCKERFILE = ROOT / "integration" / "journey" / "Dockerfile"
GATEWAY_IMAGE = (
    "cr.agentgateway.dev/agentgateway:v1.4.1@"
    "sha256:efd79355b89094a8225a9db465d9a01dc656b377f0bab458761b935a13231d29"
)


def _compose() -> dict[str, object]:
    return cast(dict[str, object], yaml.safe_load(COMPOSE.read_text(encoding="utf-8")))


def test_real_journey_stack_is_exact_isolated_and_least_privilege() -> None:
    document = _compose()
    services = cast(dict[str, dict[str, object]], document["services"])

    assert set(services) == {
        "backing",
        "gateway-candidate",
        "gateway-good",
        "identity",
        "registry",
        "runtime-bad",
        "runtime-good",
    }
    assert services["registry"]["image"] == "${JOURNEY_REGISTRY_IMAGE:?set JOURNEY_REGISTRY_IMAGE}"
    assert services["gateway-good"]["image"] == GATEWAY_IMAGE
    assert services["gateway-candidate"]["image"] == GATEWAY_IMAGE
    assert (
        services["runtime-good"]["image"] == "${JOURNEY_RUNTIME_IMAGE:?set JOURNEY_RUNTIME_IMAGE}"
    )
    assert services["runtime-bad"]["image"] == "${JOURNEY_RUNTIME_IMAGE:?set JOURNEY_RUNTIME_IMAGE}"

    expected_ports: dict[str, list[dict[str, object]]] = {
        "backing": [{"host_ip": "127.0.0.1", "protocol": "tcp", "target": 8082}],
        "gateway-candidate": [{"host_ip": "127.0.0.1", "protocol": "tcp", "target": 3000}],
        "gateway-good": [{"host_ip": "127.0.0.1", "protocol": "tcp", "target": 3000}],
        "identity": [{"host_ip": "127.0.0.1", "protocol": "tcp", "target": 8081}],
        "registry": [{"host_ip": "127.0.0.1", "protocol": "tcp", "target": 8080}],
        "runtime-bad": [{"host_ip": "127.0.0.1", "protocol": "tcp", "target": 8080}],
        "runtime-good": [{"host_ip": "127.0.0.1", "protocol": "tcp", "target": 8080}],
    }

    for name, service in services.items():
        assert service["read_only"] is True, name
        assert service["cap_drop"] == ["ALL"], name
        assert service["security_opt"] == ["no-new-privileges:true"], name
        assert service["restart"] == "no", name
        assert service.get("ports", []) == expected_ports[name]

    networks = cast(dict[str, dict[str, object]], document["networks"])
    journey = networks["journey"]
    assert journey["internal"] is False
    ipam = cast(dict[str, list[dict[str, str]]], journey["ipam"])
    assert ipam["config"] == [{"subnet": "172.30.0.0/24"}]


def test_registry_and_runtime_authority_are_explicit() -> None:
    services = cast(dict[str, dict[str, object]], _compose()["services"])
    registry_environment = cast(dict[str, str], services["registry"]["environment"])

    assert registry_environment == {
        "ADDR": ":8080",
        "AUTH_AUDIENCE": "https://registry.journey.invalid",
        "AUTH_GROUPS_CLAIM": "groups",
        "AUTH_ISSUER": "https://identity.journey.invalid",
        "AUTH_JWKS_URL": "http://identity:8081/jwks.json",
        "AUTH_MODE": "jwks",
        "AUTH_TENANT_CLAIM": "tenant_id",
        "AUTO_VERSION": "false",
        "IMMUTABLE_TAGS": "true",
        "PUBLIC_BASE_URL": "http://registry:8080",
        "SEED_EXAMPLES": "false",
        "SIGNING_DEV": "true",
        "STORE_BACKEND": "memory",
        "WEB_DIR": "",
    }
    assert "172.30.0.40/32" in cast(list[str], services["runtime-good"]["command"])
    assert "172.30.0.41/32" in cast(list[str], services["runtime-bad"]["command"])
    assert "runtime-good" in cast(list[str], services["runtime-good"]["command"])
    assert "runtime-bad" in cast(list[str], services["runtime-bad"]["command"])
    assert "http://gateway-good:3000" in cast(list[str], services["runtime-good"]["command"])
    assert "http://gateway-candidate:3000" in cast(list[str], services["runtime-bad"]["command"])
    assert "--reject-all" in cast(list[str], services["runtime-bad"]["command"])


def test_journey_image_reuses_the_core_runtime_without_a_shell() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "ARG CORE_IMAGE" in dockerfile
    assert "FROM ${CORE_IMAGE}" in dockerfile
    assert "COPY --chown=10001:10001 integration /app/integration" in dockerfile
    assert 'ENTRYPOINT ["/usr/bin/tini", "--", "/opt/app/bin/python", "-m"]' in dockerfile
    assert 'CMD ["integration.journey.reference_server"]' in dockerfile
    assert "apt-get" not in dockerfile
    assert "curl" not in dockerfile


class RecordingExecutor(CommandExecutor):
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str], float]] = []
        self.outputs: list[str] = []

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        environment: dict[str, str],
        timeout_seconds: float,
    ) -> str:
        self.calls.append((arguments, environment, timeout_seconds))
        return self.outputs.pop(0) if self.outputs else ""


def _stack(executor: RecordingExecutor) -> ComposeStack:
    return ComposeStack(
        compose_file=COMPOSE,
        project_name="journey-test-001",
        runtime_image="tesserix-mcp-runtime:journey",
        registry_image="tesserix-agentic-registry:6921474",
        output_dir=ROOT / "dist" / "journey-test",
        executor=executor,
        executable=("docker", "compose"),
        inherited_environment={"DOCKER_HOST": "unix:///safe/docker.sock"},
    )


def test_compose_stack_uses_bounded_argv_operations_and_exact_environment() -> None:
    executor = RecordingExecutor()
    stack = _stack(executor)

    stack.validate()
    stack.up("identity", "registry")
    stack.stop("registry")
    stack.start("registry")
    stack.down()

    operations = [call[0][6:] for call in executor.calls]
    assert operations == [
        ("config", "--quiet"),
        ("up", "--detach", "--no-build", "identity", "registry"),
        ("stop", "registry"),
        ("start", "registry"),
        ("down", "--volumes", "--remove-orphans", "--timeout", "10"),
    ]
    for _, environment, timeout in executor.calls:
        assert environment == {
            "COMPOSE_PROJECT_NAME": "journey-test-001",
            "DOCKER_HOST": "unix:///safe/docker.sock",
            "JOURNEY_OUTPUT_DIR": str(ROOT / "dist" / "journey-test"),
            "JOURNEY_REGISTRY_IMAGE": "tesserix-agentic-registry:6921474",
            "JOURNEY_RUNTIME_IMAGE": "tesserix-mcp-runtime:journey",
        }
        assert 1 <= timeout <= 120


def test_compose_stack_resolves_only_one_ipv4_loopback_port_and_bounds_logs() -> None:
    executor = RecordingExecutor()
    executor.outputs = ["127.0.0.1:49153\n", "safe-log\n"]
    stack = _stack(executor)

    assert stack.origin("registry", 8080) == "http://127.0.0.1:49153"
    assert stack.logs("registry", "runtime-good") == b"safe-log\n"

    assert executor.calls[0][0][-3:] == ("port", "registry", "8080")
    assert executor.calls[1][0][-5:] == (
        "logs",
        "--no-color",
        "--timestamps",
        "registry",
        "runtime-good",
    )


def test_compose_stack_re_resolves_ephemeral_port_after_start() -> None:
    executor = RecordingExecutor()
    executor.outputs = ["", "127.0.0.1:49154\n"]
    stack = _stack(executor)

    assert stack.start_and_resolve_origin("registry", 8080) == "http://127.0.0.1:49154"
    assert [call[0][6:] for call in executor.calls] == [
        ("start", "registry"),
        ("port", "registry", "8080"),
    ]


@pytest.mark.parametrize(
    "output",
    ["", "0.0.0.0:49153\n", "127.0.0.1:0\n", "127.0.0.1:1\n127.0.0.1:2\n"],
    ids=["missing", "public", "zero", "ambiguous"],
)
def test_compose_stack_rejects_unsafe_published_ports(output: str) -> None:
    executor = RecordingExecutor()
    executor.outputs = [output]

    with pytest.raises(JourneyStackError, match="journey_stack:port_invalid"):
        _stack(executor).origin("registry", 8080)
