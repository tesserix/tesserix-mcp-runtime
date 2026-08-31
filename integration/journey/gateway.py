from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import urlsplit

import yaml

from integration.journey.identity import ROUTE_SCOPE_CLAIM
from integration.journey.registry import REGISTRY_ORIGIN
from tesserix_mcp_runtime.adapters.outbound_http import OutboundHTTPResponse

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LABEL = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}\Z")
_MAX_EXPORT_BYTES = 1024 * 1024
_MAX_RESOURCES = 32
_MAX_NODES = 16_384
_ALLOWED_KINDS = {
    "AgentgatewayBackend": "agentgateway.dev/v1alpha1",
    "AgentgatewayPolicy": "agentgateway.dev/v1alpha1",
    "HTTPRoute": "gateway.networking.k8s.io/v1",
}


@dataclass(frozen=True, slots=True, kw_only=True)
class AgentGatewayExport:
    resource_count: int
    digest: str
    body: bytes
    resources: tuple[Mapping[str, object], ...]

    def __post_init__(self) -> None:
        if (
            isinstance(self.resource_count, bool)
            or not isinstance(self.resource_count, int)
            or not 1 <= self.resource_count <= _MAX_RESOURCES
            or _DIGEST.fullmatch(self.digest) is None
            or not isinstance(self.body, bytes)
            or not self.body
            or len(self.body) > _MAX_EXPORT_BYTES
            or not isinstance(self.resources, tuple)
            or len(self.resources) != self.resource_count
        ):
            raise ValueError("AgentGateway export is invalid")


def _header(response: OutboundHTTPResponse, name: str) -> str:
    values = [value for key, value in response.headers if key.lower() == name]
    if len(values) != 1:
        raise ValueError("AgentGateway export headers are invalid")
    return values[0]


def _freeze(
    value: object,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
    active: set[int] | None = None,
) -> object:
    resolved_budget = [0] if budget is None else budget
    resolved_active = set[int]() if active is None else active
    resolved_budget[0] += 1
    if depth > 32 or resolved_budget[0] > _MAX_NODES:
        raise ValueError("AgentGateway export exceeds structural bounds")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("AgentGateway export contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value) > 16_384 or any(ord(character) < 9 for character in value):
            raise ValueError("AgentGateway export text exceeds bounds")
        return value
    if isinstance(value, list):
        identity = id(value)
        if identity in resolved_active or len(value) > 1024:
            raise ValueError("AgentGateway export contains an invalid sequence")
        resolved_active.add(identity)
        frozen = tuple(
            _freeze(
                item,
                depth=depth + 1,
                budget=resolved_budget,
                active=resolved_active,
            )
            for item in value
        )
        resolved_active.remove(identity)
        return frozen
    if isinstance(value, dict):
        identity = id(value)
        if identity in resolved_active or len(value) > 512:
            raise ValueError("AgentGateway export contains an invalid mapping")
        resolved_active.add(identity)
        output: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 256:
                raise ValueError("AgentGateway export keys are invalid")
            output[key] = _freeze(
                item,
                depth=depth + 1,
                budget=resolved_budget,
                active=resolved_active,
            )
        resolved_active.remove(identity)
        return MappingProxyType(output)
    raise ValueError("AgentGateway export contains unsupported YAML values")


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError("AgentGateway export structure is invalid")
    return value


def _sequence(value: object) -> tuple[object, ...]:
    if not isinstance(value, tuple):
        raise ValueError("AgentGateway export sequence is invalid")
    return value


def _text(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError("AgentGateway export text field is invalid")
    return value


def parse_agentgateway_export(response: OutboundHTTPResponse) -> AgentGatewayExport:
    try:
        if not isinstance(response, OutboundHTTPResponse) or response.status_code != 200:
            raise ValueError
        if not response.body or len(response.body) > _MAX_EXPORT_BYTES:
            raise ValueError
        count_header = _header(response, "x-agentgateway-resource-count")
        if not count_header.isascii() or not count_header.isdecimal():
            raise ValueError
        count = int(count_header)
        if not 1 <= count <= _MAX_RESOURCES:
            raise ValueError
        digest = _header(response, "x-agentgateway-resource-digest")
        if _DIGEST.fullmatch(digest) is None:
            raise ValueError
        computed = "sha256:" + hashlib.sha256(response.body).hexdigest()
        if digest != computed or _header(response, "etag") != f'"{digest}"':
            raise ValueError
        decoded = response.body.decode()
        raw_resources = list(yaml.safe_load_all(decoded))
        if len(raw_resources) != count:
            raise ValueError
        frozen_resources: list[Mapping[str, object]] = []
        budget = [0]
        for raw in raw_resources:
            resource = _mapping(_freeze(raw, budget=budget))
            kind = _text(resource, "kind")
            if resource.get("apiVersion") != _ALLOWED_KINDS.get(kind):
                raise ValueError
            metadata = _mapping(resource.get("metadata"))
            if (
                _NAME.fullmatch(_text(metadata, "name")) is None
                or _text(metadata, "namespace") != "agentgateway-system"
            ):
                raise ValueError
            _mapping(resource.get("spec"))
            frozen_resources.append(resource)
        return AgentGatewayExport(
            resource_count=count,
            digest=digest,
            body=response.body,
            resources=tuple(frozen_resources),
        )
    except (UnicodeDecodeError, yaml.YAMLError, TypeError, ValueError):
        raise ValueError("AgentGateway export is invalid") from None


def _single_resource(exported: AgentGatewayExport, kind: str) -> Mapping[str, object]:
    matches = [resource for resource in exported.resources if resource.get("kind") == kind]
    if len(matches) != 1:
        raise ValueError("AgentGateway export must contain one journey resource per kind")
    return matches[0]


def _validated_upstream(url: str, *, expected_path: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"runtime-good", "runtime-bad"}
        or parsed.port != 8080
        or parsed.path != expected_path
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("standalone upstream must be an isolated journey runtime")
    return url


def _validate_identity_urls(*, issuer: str, audience: str, jwks_url: str) -> None:
    issuer_parts = urlsplit(issuer)
    jwks_parts = urlsplit(jwks_url)
    if (
        issuer_parts.scheme != "https"
        or issuer_parts.hostname != "identity.journey.invalid"
        or issuer_parts.path not in {"", "/"}
        or issuer_parts.query
        or issuer_parts.fragment
        or audience != REGISTRY_ORIGIN
        or jwks_parts.scheme != "http"
        or jwks_parts.hostname not in {"identity", "identity.test"}
        or jwks_parts.port not in {None, 8081}
        or jwks_parts.path != "/jwks.json"
        or jwks_parts.query
        or jwks_parts.fragment
    ):
        raise ValueError("standalone identity configuration is invalid")


def render_standalone_gateway_config(
    exported: AgentGatewayExport,
    *,
    upstream_url: str,
    issuer: str,
    audience: str,
    jwks_url: str,
) -> bytes:
    try:
        if not isinstance(exported, AgentGatewayExport):
            raise TypeError
        backend = _single_resource(exported, "AgentgatewayBackend")
        route = _single_resource(exported, "HTTPRoute")
        scope_policy = _single_resource(exported, "AgentgatewayPolicy")
        backend_metadata = _mapping(backend.get("metadata"))
        route_metadata = _mapping(route.get("metadata"))
        policy_metadata = _mapping(scope_policy.get("metadata"))
        backend_name = _text(backend_metadata, "name")
        if (
            _text(route_metadata, "name") != backend_name
            or _text(route_metadata, "namespace")
            != _text(
                backend_metadata,
                "namespace",
            )
            or _text(policy_metadata, "name") != backend_name
            or _text(
                policy_metadata,
                "namespace",
            )
            != _text(backend_metadata, "namespace")
        ):
            raise ValueError
        labels = _mapping(backend_metadata.get("labels"))
        tenant = _text(labels, "mcp.tesserix.app/tenant")
        server = _text(labels, "registry.agentic.dev/mcp")
        if _LABEL.fullmatch(tenant) is None or _NAME.fullmatch(server) is None:
            raise ValueError
        backend_spec = _mapping(backend.get("spec"))
        mcp_spec = _mapping(backend_spec.get("mcp"))
        targets = _sequence(mcp_spec.get("targets"))
        if len(targets) != 1:
            raise ValueError
        target = _mapping(targets[0])
        if _text(target, "name") != server:
            raise ValueError
        static = _mapping(target.get("static"))
        expected_path = _text(static, "path")
        if (
            _text(static, "host") != "runtime.journey.invalid"
            or static.get("port") != 443
            or expected_path != "/mcp"
            or static.get("protocol") != "StreamableHTTP"
        ):
            raise ValueError
        route_spec = _mapping(route.get("spec"))
        rules = _sequence(route_spec.get("rules"))
        if len(rules) != 1:
            raise ValueError
        rule = _mapping(rules[0])
        backend_refs = _sequence(rule.get("backendRefs"))
        matches = _sequence(rule.get("matches"))
        if len(backend_refs) != 1 or len(matches) != 1:
            raise ValueError
        backend_ref = _mapping(backend_refs[0])
        if (
            backend_ref.get("group") != "agentgateway.dev"
            or backend_ref.get("kind") != "AgentgatewayBackend"
            or backend_ref.get("name") != backend_name
        ):
            raise ValueError
        path_match = _mapping(_mapping(matches[0]).get("path"))
        route_path = _text(path_match, "value")
        if path_match.get("type") != "PathPrefix" or route_path != f"/mcp/{tenant}/{server}":
            raise ValueError
        policy_spec = _mapping(scope_policy.get("spec"))
        target_refs = _sequence(policy_spec.get("targetRefs"))
        if len(target_refs) != 1:
            raise ValueError
        target_ref = _mapping(target_refs[0])
        if (
            target_ref.get("group") != "gateway.networking.k8s.io"
            or target_ref.get("kind") != "HTTPRoute"
            or target_ref.get("name") != backend_name
        ):
            raise ValueError
        authorization = _mapping(_mapping(policy_spec.get("traffic")).get("authorization"))
        policy = _mapping(authorization.get("policy"))
        expressions = _sequence(policy.get("matchExpressions"))
        scope_rule = f'"mcp:{tenant}:{server}" in jwt["{ROUTE_SCOPE_CLAIM}"]'
        if authorization.get("action") != "Allow" or expressions != (scope_rule,):
            raise ValueError
        resolved_upstream = _validated_upstream(upstream_url, expected_path=expected_path)
        _validate_identity_urls(issuer=issuer, audience=audience, jwks_url=jwks_url)
    except (TypeError, ValueError):
        raise ValueError("AgentGateway export cannot produce an equivalent route") from None
    config = {
        "binds": [
            {
                "listeners": [
                    {
                        "routes": [
                            {
                                "backends": [
                                    {
                                        "mcp": {
                                            "failureMode": "failClosed",
                                            "targets": [
                                                {
                                                    "mcp": {"host": resolved_upstream},
                                                    "name": server,
                                                }
                                            ],
                                        }
                                    }
                                ],
                                "matches": [{"path": {"pathPrefix": route_path}}],
                                "name": backend_name,
                                "policies": {
                                    "authorization": {"rules": [scope_rule]},
                                    "backendAuth": {"passthrough": {}},
                                    "mcpAuthentication": {
                                        "audiences": [audience],
                                        "issuer": issuer,
                                        "jwks": {"url": jwks_url},
                                        "mode": "strict",
                                        "resourceMetadata": {
                                            "bearerMethodsSupported": ["header"],
                                            "resource": (
                                                "https://gateway.journey.invalid" + route_path
                                            ),
                                            "scopesSupported": [
                                                f"mcp:{tenant}:{server}",
                                                "journey:approve",
                                                "journey:read",
                                                "journey:write",
                                            ],
                                        },
                                    },
                                    "mcpAuthorization": {"rules": [f'jwt.tenant_id == "{tenant}"']},
                                },
                            }
                        ]
                    }
                ],
                "port": 3000,
            }
        ]
    }
    rendered = yaml.safe_dump(config, allow_unicode=False, sort_keys=True)
    if not isinstance(rendered, str):
        raise RuntimeError("standalone AgentGateway rendering failed")
    return rendered.encode()


__all__ = [
    "AgentGatewayExport",
    "parse_agentgateway_export",
    "render_standalone_gateway_config",
]
