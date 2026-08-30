from __future__ import annotations

import hashlib
from typing import cast

import pytest
import yaml
from integration.journey.gateway import (
    parse_agentgateway_export,
    render_standalone_gateway_config,
)

from tesserix_mcp_runtime import JsonValue
from tesserix_mcp_runtime.adapters.outbound_http import OutboundHTTPResponse


def _export_response(
    *,
    resources: list[dict[str, JsonValue]] | None = None,
    count: int | None = None,
    digest: str | None = None,
) -> OutboundHTTPResponse:
    documents = resources or [
        {
            "apiVersion": "agentgateway.dev/v1alpha1",
            "kind": "AgentgatewayBackend",
            "metadata": {
                "labels": {
                    "app.kubernetes.io/managed-by": "agentic-registry",
                    "mcp.tesserix.app/tenant": "tenant-a",
                    "registry.agentic.dev/mcp": "io-github-tesserix-journey",
                },
                "name": "tenant-a-io-github-tesserix-journey",
                "namespace": "agentgateway-system",
            },
            "spec": {
                "mcp": {
                    "targets": [
                        {
                            "name": "io-github-tesserix-journey",
                            "static": {
                                "host": "runtime.journey.invalid",
                                "path": "/mcp",
                                "port": 443,
                                "protocol": "StreamableHTTP",
                            },
                        }
                    ]
                }
            },
        },
        {
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {
                "labels": {
                    "app.kubernetes.io/managed-by": "agentic-registry",
                    "mcp.tesserix.app/tenant": "tenant-a",
                    "registry.agentic.dev/mcp": "io-github-tesserix-journey",
                },
                "name": "tenant-a-io-github-tesserix-journey",
                "namespace": "agentgateway-system",
            },
            "spec": {
                "parentRefs": [{"name": "agentgateway", "namespace": "agentgateway-system"}],
                "rules": [
                    {
                        "backendRefs": [
                            {
                                "group": "agentgateway.dev",
                                "kind": "AgentgatewayBackend",
                                "name": "tenant-a-io-github-tesserix-journey",
                            }
                        ],
                        "matches": [
                            {
                                "path": {
                                    "type": "PathPrefix",
                                    "value": ("/mcp/tenant-a/io-github-tesserix-journey"),
                                }
                            }
                        ],
                    }
                ],
            },
        },
    ]
    body = yaml.safe_dump_all(documents, explicit_start=False, sort_keys=True).encode()
    computed = "sha256:" + hashlib.sha256(body).hexdigest()
    resource_digest = digest or computed
    return OutboundHTTPResponse(
        status_code=200,
        headers=(
            ("content-type", "application/yaml"),
            ("etag", f'"{resource_digest}"'),
            ("x-agentgateway-resource-count", str(count or len(documents))),
            ("x-agentgateway-resource-digest", resource_digest),
        ),
        body=body,
    )


def test_export_verification_drives_equivalent_standalone_gateway_config() -> None:
    exported = parse_agentgateway_export(_export_response())

    rendered = render_standalone_gateway_config(
        exported,
        upstream_url="http://runtime-good:8080/mcp",
        issuer="https://identity.journey.invalid",
        audience="https://registry.journey.invalid",
        jwks_url="http://identity:8081/jwks.json",
    )
    config = cast(dict[str, object], yaml.safe_load(rendered))
    binds = cast(list[dict[str, object]], config["binds"])
    listeners = cast(list[dict[str, object]], binds[0]["listeners"])
    routes = cast(list[dict[str, object]], listeners[0]["routes"])
    route = routes[0]
    policies = cast(dict[str, object], route["policies"])
    backends = cast(list[dict[str, object]], route["backends"])
    mcp = cast(dict[str, object], backends[0]["mcp"])
    targets = cast(list[dict[str, object]], mcp["targets"])

    assert exported.resource_count == 2
    assert binds[0]["port"] == 3000
    assert route["matches"] == [
        {"path": {"pathPrefix": "/mcp/tenant-a/io-github-tesserix-journey"}}
    ]
    assert targets == [
        {
            "mcp": {"host": "http://runtime-good:8080/mcp"},
            "name": "io-github-tesserix-journey",
        }
    ]
    assert policies["backendAuth"] == {"passthrough": {}}
    assert policies["mcpAuthorization"] == {"rules": ['jwt.tenant_id == "tenant-a"']}
    authentication = cast(dict[str, object], policies["mcpAuthentication"])
    assert authentication["mode"] == "strict"
    assert authentication["resourceMetadata"] == {
        "bearerMethodsSupported": ["header"],
        "resource": ("https://gateway.journey.invalid/mcp/tenant-a/io-github-tesserix-journey"),
        "scopesSupported": ["journey:approve", "journey:read", "journey:write"],
    }


@pytest.mark.parametrize(
    "response",
    [
        _export_response(count=3),
        _export_response(digest="sha256:" + "f" * 64),
        _export_response(
            resources=[
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": "forbidden",
                        "namespace": "agentgateway-system",
                    },
                }
            ]
        ),
    ],
    ids=["count", "digest", "kind"],
)
def test_export_parser_fails_closed_on_untrusted_control_plane_input(
    response: OutboundHTTPResponse,
) -> None:
    with pytest.raises(ValueError, match="AgentGateway export"):
        parse_agentgateway_export(response)
