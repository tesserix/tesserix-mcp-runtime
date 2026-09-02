# Kubernetes reference contract

> **Warning:** this package is not deployable as checked in. It is a reusable
> contract, not product desired state. Adopt it through a reviewed change in
> `tesserix-k8s`; never apply these placeholder resources to a shared cluster.

The package contains six Kubernetes 1.31 resources plus one machine-readable
capacity plan:

- a two-replica, zero-unavailable `Deployment` with startup, readiness, and
  liveness probes plus graceful drain;
- a private `ClusterIP` `Service` for AgentGateway with session affinity
  explicitly disabled;
- a keyless workload identity `ServiceAccount`;
- a `PodDisruptionBudget` retaining one replica;
- a default-deny `NetworkPolicy` with bounded ingress and egress; and
- a two-to-ten-replica `HorizontalPodAutoscaler` driven by per-pod saturation.

The optional sibling overlay at `../overlays/istio-ambient` adds per-workload
ambient enrollment, STRICT mesh mTLS, and exact AgentGateway SPIFFE-principal
authorization. It applies to either the core or ADK image variant. Because the
ADK runs in process, it shares the runtime pod's ServiceAccount identity; use a
separate workload if a separately enforceable ADK identity is required. See
[ADR-0032](../../../docs/adr/0032-istio-ambient-workload-identity.md).

`capacity-plan.json` binds the 128/256 MiB resources, two-replica floor,
ten-replica ceiling, 45-second termination grace, and 0.5 saturation target to
the checked-in reliability observations. It is evidence input, not a
Kubernetes resource.

## Why adoption fails closed

The image points at `registry.invalid` with an all-zero digest. The namespace is
`replace-in-tesserix-k8s`. The GCP identity annotation, identity-proxy peer,
and backing API peer are placeholders. `replace-before-adoption.invalid`
appears in both Host and Origin allowlists. These values make accidental use
fail visibly instead of selecting an unintended image, tenant, identity,
Gateway, or destination.

The reference allows ingress only from the labeled AgentGateway pod in its
declared namespace. Egress is limited to DNS, the OTLP collector, an identity
proxy, one declared backing API, and the GKE metadata endpoint required by
workload identity. It contains no broad internet CIDR and no secret or static
service-account key.

## Adoption checklist

Implement the actual resource templates or values in `tesserix-k8s` and retain
the security and availability invariants. Before merging:

1. Replace the invalid image with a published immutable digest.
2. Replace the namespace and workload identity annotation with reviewed
   environment values.
3. Replace every Host and Origin placeholder with exact Service and
   AgentGateway-facing values. Wildcards are not acceptable.
4. Replace or remove the identity-proxy and backing API peers and ports. Do not
   add `0.0.0.0/0` as a convenience fallback.
5. Confirm the AgentGateway namespace and pod labels against the owning chart.
6. Classify backing and identity dependencies as critical, degradable, or
   optional; include only bounded critical checks in readiness and none in
   liveness.
7. Pin a memory request and limit, keep the non-root and read-only security
   context, bounded `/tmp`, PDB, topology spread, and drain timings.
8. Exercise a failed canary and one-revision GitOps rollback in non-production
   while the previous Registry route remains active.
9. For ambient adoption, replace the placeholder AgentGateway SPIFFE principal
   with its exact trust domain, namespace, and ServiceAccount; retain STRICT
   mTLS and prove wrong-principal and plaintext requests are denied.

See the [container and GitOps guide](../../../docs/container-gitops.md) for
image evidence, dependency behavior, capacity arithmetic, rollout, rollback,
and the expand-contract procedure.

## Render and validate

Rendering is read-only and does not contact a cluster:

    kustomize build deploy/kubernetes/reference

Render the optional ambient variant with:

    kustomize build deploy/kubernetes/overlays/istio-ambient

The CI workflow validates all six Kubernetes JSON resources against strict Kubernetes
1.31 schemas. Product adoption must validate the fully rendered
`tesserix-k8s` revision as well; validation of these placeholders does not prove
the adopted identities, routes, or NetworkPolicy peers are correct.
