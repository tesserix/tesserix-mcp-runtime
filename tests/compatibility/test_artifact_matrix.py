from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

ROOT = Path(__file__).parents[2]
COMPOSE = ROOT / "compatibility" / "compose.yaml"
GATEWAY_CONFIG = ROOT / "compatibility" / "agentgateway.yaml"
WORKFLOW = ROOT / ".github" / "workflows" / "compatibility.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
GATEWAY_IMAGE = (
    "cr.agentgateway.dev/agentgateway:v1.4.1@"
    "sha256:efd79355b89094a8225a9db465d9a01dc656b377f0bab458761b935a13231d29"
)


def _yaml(path: Path) -> dict[str, object]:
    return cast(dict[str, object], yaml.safe_load(path.read_text(encoding="utf-8")))


def test_compatibility_stack_uses_the_built_runtime_and_real_agentgateway() -> None:
    compose = _yaml(COMPOSE)
    services = cast(dict[str, dict[str, object]], compose["services"])

    assert set(services) == {"gateway", "runtime"}
    assert services["runtime"]["image"] == ("${COMPAT_RUNTIME_IMAGE:?set COMPAT_RUNTIME_IMAGE}")
    assert services["gateway"]["image"] == GATEWAY_IMAGE
    assert services["runtime"]["user"] == "10001:10001"
    assert services["gateway"]["user"] == "65532:65532"
    assert "--reliability-spans" in cast(list[str], services["runtime"]["command"])
    for name, service in services.items():
        assert service["read_only"] is True, name
        assert service["cap_drop"] == ["ALL"], name
        assert service["security_opt"] == ["no-new-privileges:true"], name
        assert service["restart"] == "no", name
        expected_ports = [
            {
                "host_ip": "127.0.0.1",
                "published": "38080" if name == "runtime" else "33000",
                "protocol": "tcp",
                "target": 8000 if name == "runtime" else 3000,
            }
        ]
        if name == "gateway":
            expected_ports.append(
                {
                    "host_ip": "127.0.0.1",
                    "published": "31520",
                    "protocol": "tcp",
                    "target": 15020,
                }
            )
        assert service["ports"] == expected_ports

    networks = cast(dict[str, dict[str, object]], compose["networks"])
    assert networks == {"compatibility": {"internal": False}}

    gateway = _yaml(GATEWAY_CONFIG)
    binds = cast(list[dict[str, object]], gateway["binds"])
    assert len(binds) == 1
    assert binds[0]["port"] == 3000
    listeners = cast(list[dict[str, object]], binds[0]["listeners"])
    routes = cast(list[dict[str, object]], listeners[0]["routes"])
    route = routes[0]
    assert route["matches"] == [{"path": {"pathPrefix": "/gateway/runtime/mcp"}}]
    backends = cast(list[dict[str, object]], route["backends"])
    mcp = cast(dict[str, object], backends[0]["mcp"])
    targets = cast(list[dict[str, object]], mcp["targets"])
    assert targets == [{"name": "runtime", "mcp": {"host": "http://runtime:8000/mcp"}}]


def test_compatibility_workflow_runs_pinned_artifact_and_devai_evidence() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    release_workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "  workflow_call:" in workflow
    assert '    tags: ["v*"]' in release_workflow
    assert "uses: ./.github/workflows/compatibility.yml" in release_workflow
    assert "  pull_request:" in workflow
    assert workflow.count("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1") == 3
    assert "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e" in workflow
    assert "version: v0.36.1" in workflow
    assert "850379a833bb5740c82eb2a16cac452ff93695f0" in workflow
    assert "2971b73f96ffc050df5437edad5e32c5c5b29e4dd86654f5f620ae0467793ad5" in workflow
    assert "uv sync --directory .compatibility/devai --frozen --no-dev" in workflow
    assert "uv build --wheel --out-dir dist/compatibility-wheel" in workflow
    assert "--file deploy/container/core.Dockerfile" in workflow
    assert workflow.count("--provenance=mode=max") == 1
    assert '--output "type=oci,dest=${provenance_oci},tar=false"' in workflow
    assert "vnd.docker.reference.type" in workflow
    assert "--load --provenance=false" in workflow
    assert "docker-compose-linux-x86_64" in workflow
    assert "c57ab918abd5b05ca7e7d0f275875dd1330a695074f309dc9eab1b49efafcd4b" in workflow
    assert "compatibility/run_matrix.py" in workflow
    assert "--wheel-python" in workflow
    assert "--image-endpoint" in workflow
    assert "--gateway-endpoint" in workflow
    assert "--devai-python" in workflow
    assert "--junit" in workflow
    assert workflow.count("compatibility/run_inspector.py") == 2
    assert workflow.count("compatibility/measure_reliability.py") == 2
    assert workflow.count("--compatibility-smoke") == 2
    assert "reliability-direct.json" in workflow
    assert "reliability-agentgateway.json" in workflow
    assert "scan_journey_surfaces" in workflow
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in workflow
    assert "retention-days: 7" in workflow
    assert "docker push" not in workflow
    assert "--push" not in workflow
    assert workflow.count("secrets.GO_PRIVATE_TOKEN") == 2
    assert "token: ${{ secrets.GO_PRIVATE_TOKEN }}" in workflow
    assert "GH_TOKEN: ${{ secrets.GO_PRIVATE_TOKEN }}" in workflow
    assert workflow.count("if: github.event_name != 'pull_request'") == 2
    assert "kubectl" not in workflow
