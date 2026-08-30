# Gateway activation status

The optional publisher package can observe and wait for one exact MCP server's
Gateway activation. It is a read-only client. It does not deploy a server,
write status, run a probe, mutate Kubernetes, or make Registry publication mean
“active”.

The producer-side Registry and Gateway work is still tracked by the six issues
listed in [ADR-0020](adr/0020-digest-bound-gateway-activation.md). Until those
land, current Registry objects do not contain `status.activation`; the command
fails closed with `activation_contract_invalid`.

## Identity to retain after publication

An activation target has three immutable values:

- `ref`: exact versioned Registry reference;
- `registry_digest`: canonical signed Registry object digest;
- `artifact_digest`: wheel/image/delivery artifact digest actually deployed.

`publish`, `validate`, and `inspect` output the artifact digest. A verified
`publish` result now contains both `digest` (the Registry digest) and
`artifact_digest`. Do not wait on a mutable name or `latest` without pinning
both digests. Optionally pin the first expected status generation too.

Observe once:

```console
tesserix-mcp-runtime activation \
  --ref mcpservers/tenant-orders/io.github.tesserix/orders@1.2.3 \
  --registry-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --artifact-digest sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --request-id orders-1.2.3-status
```

Wait through the polling baseline:

```console
tesserix-mcp-runtime activation \
  --ref mcpservers/tenant-orders/io.github.tesserix/orders@1.2.3 \
  --registry-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --artifact-digest sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --wait-for active \
  --timeout-seconds 120 \
  --poll-interval-seconds 2 \
  --request-id orders-1.2.3-activation
```

The standalone `tesserix-mcp-publish` entry point exposes the same command.
Authentication and tenant selection remain the installed `agentic` CLI's
responsibility. Supply credentials only through its supported environment or
credential store; no activation flag accepts a token or secret.

## Safe result

Output contains only exact identity, generation, desired state, phase,
timestamps, safe condition type/status/reason/request IDs, blocking conditions,
summary, retryability, and terminal classification. It never emits the MCP
manifest, tool schemas, tool payloads, credentials, claims, or upstream error
text.

The nine phases are:

| Phase | Operator meaning |
| --- | --- |
| `draft` | No committed Registry version |
| `published` | Immutable version exists; stage deployment pending |
| `deployed` | Backend/policy/probe route accepted; protocol probe pending |
| `probed` | Authenticated initialize and `tools/list` passed; public route pending |
| `active` | Exact deployment, probe, health, policy, and public route accepted |
| `degraded` | A previously active version lost readiness; inspect last-known-good handling |
| `deprecated` | Observable retirement window; not a current active-wait success |
| `retired` | Removed from discovery/routing; callers receive non-disclosing 404 |
| `failed` | Activation ended before first public route |

Runtime process startup/readiness/drain/stopped state is a separate contract and
never changes these phases.

## Wait behavior and exit codes

The default wait is 120 seconds and polls every two seconds. Timeout must be
between 0.1 and 900 seconds; poll interval must be between 0.1 and 30 seconds
and no greater than timeout. The waiter sleeps only to the monotonic deadline.

Linear progress may be observed after the requested phase: `active` satisfies a
wait for `published`, `deployed`, or `probed`. Degraded, deprecated, retired,
and failed do not satisfy an active wait. The first observed generation is
pinned unless `--generation` is supplied. A generation/digest move is
non-retryable; a new wait requires explicit review.

| Exit | Meaning | Operator action |
| ---: | --- | --- |
| 0 | One-shot status observed, or requested phase reached | Record identity, generation, request IDs |
| 1 | Delegated output or activation contract invalid | Repair/upgrade the owning Registry contract; do not infer activation |
| 2 | Unsafe or invalid arguments | Repair exact ref/digests/bounds |
| 3 | Target superseded by generation/digest movement | Review and explicitly pin the new immutable target |
| 4 | Registry read unavailable before success | Retry with the same exact target under release policy |
| 7 | Wait reached failed, deprecated, or retired | Follow condition reason/request IDs; do not route |
| 8 | Bounded wait expired | Inspect the safe final activation projection and stage alerts |

A one-shot observation of `failed` still exits 0 because the requested read
succeeded. `--wait-for active` on that same object exits 7 and includes only the
safe final projection.

## Reusable Python API

Use `ActivationStatus.from_document` for strict contract validation,
`ActivationTarget` for immutable identity, and `ActivationWaiter` with an
`ActivationClient`. The waiter accepts an `ActivationClock` so tests use a fake
clock without sleeps. `AgenticCLIPublisher` implements both publication and
activation reads through argv-only delegated commands.

The schema is
[`contracts/activation-status-v1alpha1.schema.json`](../contracts/activation-status-v1alpha1.schema.json)
with a checked-in
[`active` example](../contracts/activation-status-v1alpha1.example.json).
State derivation, condition ownership, SLO, security model, producer issues,
failure behavior, rollout, and rollback are normative in
[ADR-0020](adr/0020-digest-bound-gateway-activation.md).

Identity-scoped tenant discovery, collision-safe route identity, complete
pagination, quota admission, and tenant-scoped prune are a separate contract in
the [tenant Gateway reconciliation guide](tenant-gateway-reconciliation.md).
