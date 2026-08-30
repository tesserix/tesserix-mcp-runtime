# Registry publication

The opt-in publisher validates and compiles one authoring manifest, binds
immutable artifact/SBOM/provenance evidence, delegates Agentic Registry
publication, and verifies the exact signed result. It does not build artifacts,
store credentials, publish during server startup, or activate a Gateway route.

## Install and authenticate

Install the release tooling separately from serving runtime dependencies:

```console
pip install 'tesserix-mcp-runtime[publisher]'
```

Humans authenticate through the browser or device flow supported by
`agentic`. CI supplies Agentic's supported short-lived client credentials
through its environment or credential store. The publisher has no
`--client-secret` argument. In particular, never place `AGENTIC_TOKEN` or
`AGENTIC_CLIENT_SECRET` in a command line, manifest, log, or artifact.

The commands require artifacts to be built and uploaded first. The example
uses an immutable OCI digest plus local SBOM and provenance files whose public
URIs already exist:

```console
tesserix-mcp-runtime validate \
  --manifest authoring.json \
  --runtime-version 3.1.0 \
  --artifact-uri oci://ghcr.io/tesserix/orders-mcp:3.1.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --artifact-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --artifact-media-type application/vnd.oci.image.manifest.v1+json \
  --sbom-file dist/orders.spdx.json \
  --sbom-uri https://artifacts.example.com/orders/3.1.0/orders.spdx.json \
  --provenance-file dist/orders.intoto.jsonl \
  --provenance-uri https://artifacts.example.com/orders/3.1.0/orders.intoto.jsonl
```

Use `--artifact-file` instead of `--artifact-digest` when the authoring
manifest declares a file package and the local prebuilt file must be hashed.
SBOM and provenance files are always hashed locally. Inputs must be nonempty
regular files and are protected against symlinks and replacement races.

## Validate, inspect, and write manifests

`validate` returns a bounded JSON summary after all local checks. `inspect`
returns the same safe identity and digest fields with a distinct status; it
never emits tool schemas or tenant payloads. `manifest` writes `server.json`
and `mcpserver.json` into an existing empty directory and refuses to overwrite
either file:

```console
tesserix-mcp-runtime manifest <evidence arguments> --output-dir dist/manifests
```

The Agentic document contains the evidence at
`spec.x-tesserix.publication`. Both documents are byte-stable for the same
input. Generate them for review; do not edit the generated output.

## Dry run and publish

Choose one stable idempotency key for the logical release. CI build or release
IDs are appropriate when they remain unchanged across retries.

```console
tesserix-mcp-runtime publish <evidence arguments> \
  --idempotency-key orders-3.1.0-release-42 \
  --request-id orders-3.1.0-dry-run \
  --dry-run

tesserix-mcp-runtime publish <evidence arguments> \
  --idempotency-key orders-3.1.0-release-42 \
  --request-id orders-3.1.0-publish
```

Dry run performs local validation, `agentic status`, and Agentic remote apply
validation without a write. The real flow applies atomically, pulls the exact
name and version, recomputes its canonical digest, and runs Registry signature
verification. The success JSON contains `ref`, `version`, `digest`, `created`,
`signed_by`, `request_id`, and the reused `idempotency_key`.

Official MCP Registry publication is preview functionality and must be
explicit:

```console
tesserix-mcp-runtime publish <evidence arguments> \
  --idempotency-key orders-3.1.0-release-42 \
  --request-id orders-3.1.0-both-registries \
  --official
```

Tesserix always publishes and verifies first. `--official` then runs official
validation and publication; it cannot change the Agentic target or replace a
Tesserix result.

## Exit codes and recovery

| Exit | Meaning | Operator action |
| ---: | --- | --- |
| 0 | Valid, dry-run, or exact verified publication | Record the returned ref, digest, and request ID |
| 1 | Delegated command, output, or protected-material failure | Fix the delegated tool or safe-output contract |
| 2 | Invalid arguments, manifest, evidence, or digest | Repair local inputs; no write occurred |
| 3 | Immutable version conflict | Inspect the existing exact version; use a new version for different content |
| 4 | Publisher unavailable before confirmed success | Retry with the same inputs and idempotency key |
| 5 | Agentic apply may have succeeded but verification did not finish | Do not blindly retry; reconcile exact pull and signature using the request ID |
| 6 | Tesserix verified; explicit official target failed | Preserve the Tesserix result and reconcile only the official target |

For exit 5, run the owning `agentic pull mcpservers NAME --tag VERSION` and
`agentic verify mcpservers NAME --tag VERSION` commands under the same tenant
identity. Compare the pulled canonical digest to the CLI's prepared digest. If
another attempt is required, reuse the original idempotency key.

Publication does not prove Gateway activation. Route pickup and activation
have a separate default-deny status contract and must be observed independently.

The ownership, failure state machine, security model, cost, rollout, and
rollback are recorded in
[ADR-0019](adr/0019-delegated-immutable-registry-publication.md).
