from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

ROOT = Path(__file__).parents[2]
REFERENCE = ROOT / "deploy" / "kubernetes" / "reference"
INVALID_IMAGE = "registry.invalid/tesserix/mcp-server@sha256:" + ("0" * 64)
JSON_OBJECT = TypeAdapter(dict[str, Any])


def load_resource(name: str) -> dict[str, Any]:
    return JSON_OBJECT.validate_json((REFERENCE / name).read_bytes())


def test_reference_deployment_is_a_non_deployable_ha_runtime() -> None:
    deployment = load_resource("deployment.json")
    spec = deployment["spec"]
    pod_spec = spec["template"]["spec"]
    container = pod_spec["containers"][0]

    assert deployment["apiVersion"] == "apps/v1"
    assert deployment["kind"] == "Deployment"
    assert spec["replicas"] == 2
    assert pod_spec["serviceAccountName"] == "mcp-server-reference"
    assert container["image"] == INVALID_IMAGE
    assert container["ports"] == [{"name": "http", "containerPort": 8000, "protocol": "TCP"}]


def test_reference_deployment_is_hardened_and_memory_bounded() -> None:
    pod_spec = load_resource("deployment.json")["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]

    assert pod_spec["automountServiceAccountToken"] is False
    assert pod_spec["enableServiceLinks"] is False
    assert pod_spec["securityContext"] == {
        "runAsNonRoot": True,
        "runAsUser": 10001,
        "runAsGroup": 10001,
        "fsGroup": 10001,
        "fsGroupChangePolicy": "OnRootMismatch",
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    assert container["resources"] == {
        "requests": {"memory": "128Mi"},
        "limits": {"memory": "256Mi"},
    }
    assert container["volumeMounts"] == [{"name": "tmp", "mountPath": "/tmp"}]
    assert pod_spec["volumes"] == [{"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}]


def test_reference_deployment_has_distinct_probes_and_graceful_termination() -> None:
    pod_spec = load_resource("deployment.json")["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]

    assert pod_spec["terminationGracePeriodSeconds"] == 45
    assert container["args"] == [
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
        "--allowed-host",
        "mcp-server-reference",
        "--allowed-host",
        "mcp-server-reference:8000",
        "--allowed-host",
        "mcp-server-reference.replace-in-tesserix-k8s.svc.cluster.local",
        "--allowed-host",
        "replace-before-adoption.invalid",
        "--allowed-origin",
        "https://replace-before-adoption.invalid",
    ]
    assert container["startupProbe"] == {
        "httpGet": {
            "path": "/startupz",
            "port": "http",
            "scheme": "HTTP",
            "httpHeaders": [{"name": "Host", "value": "mcp-server-reference"}],
        },
        "periodSeconds": 2,
        "timeoutSeconds": 1,
        "failureThreshold": 30,
        "successThreshold": 1,
    }
    assert container["readinessProbe"] == {
        "httpGet": {
            "path": "/readyz",
            "port": "http",
            "scheme": "HTTP",
            "httpHeaders": [{"name": "Host", "value": "mcp-server-reference"}],
        },
        "periodSeconds": 5,
        "timeoutSeconds": 2,
        "failureThreshold": 2,
        "successThreshold": 1,
    }
    assert container["livenessProbe"] == {
        "httpGet": {
            "path": "/livez",
            "port": "http",
            "scheme": "HTTP",
            "httpHeaders": [{"name": "Host", "value": "mcp-server-reference"}],
        },
        "periodSeconds": 10,
        "timeoutSeconds": 2,
        "failureThreshold": 3,
        "successThreshold": 1,
    }
    assert container["lifecycle"]["preStop"]["exec"]["command"] == [
        "/usr/local/bin/python3",
        "-c",
        "import time; time.sleep(5)",
    ]


def test_reference_deployment_rolls_without_dropping_capacity_and_spreads_replicas() -> None:
    spec = load_resource("deployment.json")["spec"]
    pod_spec = spec["template"]["spec"]
    selector = {"matchLabels": {"app.kubernetes.io/name": "mcp-server-reference"}}

    assert spec["strategy"] == {
        "type": "RollingUpdate",
        "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
    }
    assert spec["minReadySeconds"] == 10
    assert spec["progressDeadlineSeconds"] == 300
    assert spec["revisionHistoryLimit"] == 2
    assert pod_spec["topologySpreadConstraints"] == [
        {
            "maxSkew": 1,
            "topologyKey": "topology.kubernetes.io/zone",
            "whenUnsatisfiable": "DoNotSchedule",
            "labelSelector": selector,
        },
        {
            "maxSkew": 1,
            "topologyKey": "kubernetes.io/hostname",
            "whenUnsatisfiable": "ScheduleAnyway",
            "labelSelector": selector,
        },
    ]


def test_reference_package_exposes_only_a_cluster_service_with_pdb_and_identity() -> None:
    service = load_resource("service.json")
    service_account = load_resource("service-account.json")
    pdb = load_resource("pod-disruption-budget.json")
    kustomization = load_resource("kustomization.yaml")
    selector = {"app.kubernetes.io/name": "mcp-server-reference"}

    assert service["spec"] == {
        "type": "ClusterIP",
        "selector": selector,
        "ports": [{"name": "http", "port": 8000, "targetPort": "http", "protocol": "TCP"}],
    }
    assert service_account["automountServiceAccountToken"] is False
    assert service_account["metadata"]["annotations"] == {
        "iam.gke.io/gcp-service-account": "replace-before-adoption@registry.invalid"
    }
    assert pdb["spec"] == {"minAvailable": 1, "selector": {"matchLabels": selector}}
    assert kustomization["namespace"] == "replace-in-tesserix-k8s"
    assert {
        "deployment.json",
        "service.json",
        "service-account.json",
        "pod-disruption-budget.json",
    }.issubset(kustomization["resources"])


def test_reference_network_is_default_deny_with_only_declared_paths() -> None:
    network = load_resource("network-policy.json")
    deployment = load_resource("deployment.json")
    spec = network["spec"]
    gateway_peer = {
        "namespaceSelector": {
            "matchLabels": {"kubernetes.io/metadata.name": "agentgateway-system"}
        },
        "podSelector": {
            "matchLabels": {"gateway.networking.k8s.io/gateway-name": "agentgateway-mcp"}
        },
    }

    assert spec["podSelector"] == {
        "matchLabels": {"app.kubernetes.io/name": "mcp-server-reference"}
    }
    assert spec["policyTypes"] == ["Ingress", "Egress"]
    assert spec["ingress"] == [
        {"from": [gateway_peer], "ports": [{"port": 8000, "protocol": "TCP"}]}
    ]
    assert spec["egress"] == [
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                    },
                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                }
            ],
            "ports": [
                {"port": 53, "protocol": "UDP"},
                {"port": 53, "protocol": "TCP"},
            ],
        },
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "observability"}
                    },
                    "podSelector": {"matchLabels": {"app.kubernetes.io/name": "otel-gateway"}},
                }
            ],
            "ports": [{"port": 4318, "protocol": "TCP"}],
        },
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "replace-identity-namespace"}
                    },
                    "podSelector": {
                        "matchLabels": {"app.kubernetes.io/name": "replace-identity-proxy"}
                    },
                }
            ],
            "ports": [{"port": 8443, "protocol": "TCP"}],
        },
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": "replace-backing-api-namespace"
                        }
                    },
                    "podSelector": {
                        "matchLabels": {"app.kubernetes.io/name": "replace-backing-api"}
                    },
                }
            ],
            "ports": [{"port": 443, "protocol": "TCP"}],
        },
        {
            "to": [{"ipBlock": {"cidr": "169.254.169.254/32"}}],
            "ports": [{"port": 80, "protocol": "TCP"}],
        },
    ]
    assert deployment["spec"]["template"]["metadata"]["annotations"] == {
        "traffic.sidecar.istio.io/excludeOutboundIPRanges": "169.254.169.254/32"
    }
    assert "0.0.0.0/0" not in json.dumps(network)
