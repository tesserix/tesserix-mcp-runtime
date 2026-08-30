# Container and GitOps deployment

This guide covers the reusable image and Kubernetes contract. It does not
publish an image or establish product desired state. A product deployment is a
reviewed change in `tesserix-k8s`; never run the reference manifests against a
shared or production cluster.

The architectural boundary, SLO, threat model, capacity arithmetic, and
alternatives are recorded in
[ADR-0022](adr/0022-container-and-gitops-deployment.md).

## Choose the smallest valid image

Core is the default. Select ADK only when the server imports the optional ADK
bridge and has evidence that the all-extras closure is required.

| Variant | Immutable Python 3.14 base | Merged image size | Compressed `docker save` archive |
| --- | --- | ---: | ---: |
| Core | `ghcr.io/tesserix/base-python-runtime-3.14:20260829@sha256:3854f5d9d00705b14077bf6715feb9c3bd6d1ad2e41d5594b3c09c0a74c22add` | 66,975,933 bytes | 66,342,726 bytes |
| ADK | `ghcr.io/tesserix/base-python-adk-3.14:20260829@sha256:5a6fd1863ed7f37f3929cc596d0ec063c3077c11713cd334f14d1df2b30ef386` | 146,156,861 bytes | 145,231,613 bytes |

Those arm64 measurements came from the issue verification build with package
version `0.0.1.dev0`; registry compression and another architecture may differ.
Both images initialized MCP SDK 2.1.1, returned a two-page tool catalog, called
a successful and a failed tool, served all probes, became unready during drain,
and exited zero after SIGTERM.

Google ADK 2.8.0 caps its telemetry closure at OpenTelemetry 1.42.1. The shared
runtime metadata therefore accepts `>=1.42.1,<2`. The immutable ADK base uses
OpenTelemetry 1.42.1 while the current core lock resolves OpenTelemetry 1.44.0.
Do not raise the common minimum beyond the maintained ADK lane without first
updating and rebuilding that base.

## Build and exercise locally

The Dockerfiles use a digest-pinned uv 0.12.7 builder and an isolated wheel
stage. A removed base digest fails the build; neither Dockerfile has a floating
fallback.

    docker build \
      --build-arg PACKAGE_VERSION=0.0.1.dev0 \
      --file deploy/container/core.Dockerfile \
      --tag tesserix-mcp-runtime:core .

    uv run --frozen python deploy/container/verify.py \
      --image tesserix-mcp-runtime:core \
      --variant core \
      --base-image ghcr.io/tesserix/base-python-runtime-3.14:20260829@sha256:3854f5d9d00705b14077bf6715feb9c3bd6d1ad2e41d5594b3c09c0a74c22add \
      --expected-sdk 2.1.1 \
      --output /tmp/tesserix-mcp-core-runtime.json

Use `deploy/container/adk.Dockerfile`, the ADK base digest from the table, and
`--variant adk` for the optional variant. The verifier starts the image as
`10001:10001` with a read-only root, a 64 MiB `noexec,nosuid,nodev` `/tmp`, all
capabilities dropped, and no privilege escalation. It also proves there is no
runtime shell or pip installer. The Kubernetes contract adds `RuntimeDefault`
seccomp.

Because there is no runtime shell, diagnose with structured logs, RED metrics,
traces, health endpoints, and the verifier first. If process-namespace or file
inspection is essential, an operator may attach an approved ephemeral debug
container under cluster RBAC. Do not rebuild the application with a shell or
copy credentials into a debug image.

## Understand the scan evidence

The container workflow emits one runtime report, fresh Syft SPDX and CycloneDX
inventories, and separate Trivy OS and language vulnerability reports for each
variant. Tool images and Actions are pinned, the workflow has read-only
permissions, and it neither pushes an image nor requests an OIDC token.

An inherited layer SBOM in a third-party base can describe pip-vendored
`msgpack 1.1.2` and `setuptools 70.3.0`. Both final variants remove pip after
the last local install, so neither package nor the installer remains reachable.
The fresh Syft inventories and runtime verifier prove that removal. CI scans the
actual merged-image OS and language packages without a CVE-specific waiver. It
retains every HIGH/CRITICAL finding in JSON, reports inherited findings with no
upstream fix, and fails closed when any finding has an available fixed version.
That matches the owning base-image policy without hiding its residual risk.

## Adopt the Kubernetes contract

The files in `deploy/kubernetes/reference` are not deployable as checked in.
Create the product values or templates in `tesserix-k8s`, retaining the five
resource contracts, and replace every placeholder there.

Before review, prove all of the following:

1. Replace `registry.invalid/...@sha256:000...` with the published application
   digest. Keep the digest; do not replace it with a tag.
2. Replace namespace `replace-in-tesserix-k8s` and the GCP service-account
   annotation with the reviewed workload identity mapping.
3. Replace `replace-before-adoption.invalid` in both Host and Origin allowlists
   with exact AgentGateway-facing values. Retain exact in-cluster Service Host
   values required by probes. Never use `*` or remove the allowlists to make a
   probe pass.
4. Replace the identity-proxy and backing API namespace, label, and port peers.
   Delete an unused egress rule instead of leaving a fictitious peer. Do not add
   `0.0.0.0/0`.
5. Confirm the AgentGateway namespace, Gateway label, Service name, and port
   match the owning cluster. The Service remains `ClusterIP`; this package does
   not create public ingress.
6. Classify every dependency using the table below and compose only bounded
   critical checks into readiness. Liveness remains dependency-independent.
7. Recalculate replicas from measured peak rate and p99 product latency. Keep
   two or more for a user-facing GA workload, the PDB, zone/hostname topology
   spread, memory request and limit, and the 45-second drain window.
8. Render and validate the exact adopted revision, then let Argo CD reconcile
   it. Do not use `kubectl apply` as product delivery.

Render the reference contract without contacting a cluster:

    kustomize build deploy/kubernetes/reference

Validate its Kubernetes 1.31 schemas with the same pinned image as CI:

    docker run --rm --volume "$PWD:/work:ro" \
      ghcr.io/yannh/kubeconform:v0.8.0@sha256:faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e \
      -strict -summary -kubernetes-version 1.31.0 \
      /work/deploy/kubernetes/reference/deployment.json \
      /work/deploy/kubernetes/reference/service.json \
      /work/deploy/kubernetes/reference/service-account.json \
      /work/deploy/kubernetes/reference/pod-disruption-budget.json \
      /work/deploy/kubernetes/reference/network-policy.json

## Classify dependency failures

| Tier | Examples | Readiness | Liveness and calls |
| --- | --- | --- | --- |
| Critical | usable identity/JWKS, mandatory policy/audit, an API required by every tool | 503 after a bounded check fails | Liveness stays 200; calls fail closed with a safe stable error |
| Degradable | API used by only some tools, Registry or GitOps control plane after activation | 200 while independent tools and the last-known-good route work | Liveness stays 200; affected calls alone return a safe dependency error |
| Optional | OTLP collector | Never included | Liveness stays 200; bounded telemetry is dropped and counted |

Do not retry authentication, authorization, validation, conflict, or unsafe
write failures. A safe or idempotent call may retry a transient timeout, 429,
or 5xx only inside its original deadline and bounded attempt budget. Readiness
checks execute concurrently with finite timeouts, so one dependency cannot
serialize or hang probe handling.

## Canary, promote, and roll back

All rollout mutations belong in `tesserix-k8s`.

1. Publish the candidate once and record its immutable digest and evidence.
2. Add the candidate to non-production at zero active Gateway traffic or under
   an isolated smoke route. Keep the previous Registry route and image digest.
3. Wait for startup and readiness, then exercise MCP initialization,
   paginated discovery, a representative read, a safe failure, and SIGTERM
   drain. Observe error ratio, p99 duration, saturation, and dropped telemetry.
4. Promote by changing the reviewed route target only after the health policy
   passes. Keep the old route through at least one complete observation window.
5. Remove the previous route and digest in a later reviewed revision, never in
   the promotion revision.

If the candidate never becomes ready, `maxUnavailable: 0` keeps the old
ReplicaSet serving and the route does not move. Revert the failed desired state
with one Git revision:

    git revert --no-edit <failed-tesserix-k8s-commit>

Review and merge that revert; Argo CD restores the earlier digest and route.
Do not use `kubectl rollout undo`, because Git would reconcile the failed state
again. Before cutover, RTO is zero because traffic never left the old route.
After cutover, the target is five minutes from approved revert to restored
readiness. Runtime configuration RPO is zero because Git and immutable digests
retain the entire state.

Configuration changes use expand-contract across separate revisions:

1. deploy code that accepts old and new optional configuration;
2. add the new value while retaining the old value;
3. cut traffic after both forms have been exercised;
4. remove old configuration only after no old pod or rollback needs it.

## Local non-production rollback evidence

Issue #24 was exercised on 2026-08-31 with Kind 0.33.0 and Kubernetes 1.31.14
in an ephemeral local cluster, not a shared Tesserix cluster. The node image was
`kindest/node:v1.31.14@sha256:6f86cf509dbb42767b6e79debc3f2c32e4ee01386f0489b3b2be24b0a55aac2b`.
The scenario loaded the verified core image, applied a two-replica stable
revision, and confirmed two ready Service endpoints. A second declarative
revision changed the candidate startup probe to `/never-ready`.

The failed state had three pods: two stable ready and available, and one
candidate unready. The EndpointSlice retained exactly the two stable pods, and
the Kubernetes Service proxy continued returning 200. No Registry/Gateway
cutover was made. Reapplying the prior declarative revision scaled the failed
ReplicaSet to zero and completed with two ready stable replicas and two ready
Service endpoints.

This local Kind exercise proves the Kubernetes rollout invariant and
previous-version traffic preservation. It does not claim that Argo CD or the
real AgentGateway integration has been exercised.
[tesserix-k8s#756](https://github.com/tesserix/tesserix-k8s/issues/756) owns a
non-production Argo rehearsal before product promotion.

## Cost and retention checklist

The reference schedules 256 MiB and caps 512 MiB across its two replicas. At 30
single-architecture revisions, the measured compressed archives total about
2.0 GB for core or 4.4 GB for ADK before registry deduplication. During
adoption, also estimate cross-zone Gateway traffic, backing-API egress, trace
and log retention, and any minimum replicas above two. Prefer core, bounded
telemetry, and measured concurrency-based scaling; do not choose ADK or an HPA
signal by convention.
