# ADR-0019: Delegated immutable Registry publication

## Status

Accepted.

## Context

MCP authors need one reusable path from a reviewed authoring manifest and
prebuilt delivery artifacts to an immutable, signed Agentic Registry version.
Agentic Registry already owns authentication, tenant authorization, atomic
apply, idempotency, immutable version storage, canonical digests, and signing.
Its command contract at commit `6921474591b6c59e89025370c310c7f85859246f`
is `agentic status`, `agentic apply -f FILE [--dry-run] --idempotency-key KEY`,
`agentic pull mcpservers NAME --tag VERSION`, and `agentic verify mcpservers
NAME --tag VERSION`. The official MCP Registry separately provides the preview
`mcp-publisher validate [file]` and `mcp-publisher publish [path]` commands.

The initial design envelope assumes fewer than one publication per minute per
server and an organization-wide burst of five attempts/second. A publication
contains at most 1 MiB of authoring or Agentic manifest JSON, one prebuilt
artifact reference or a locally hashed artifact of at most 512 MiB, and SBOM
and provenance files of at most 8 MiB each. Publication is write-heavy, but
all durable version data remains in Registry; this package stores zero bytes
at 12 and 36 months. Local validation targets p99 below two seconds excluding
artifact hashing. Each delegated process has a 30-second default deadline,
bounded arguments, 512 KiB stdout, and 64 KiB stderr. These are pre-GA
assumptions to measure, not production throughput claims.

The consuming CI job owns its availability objective. The workflow targets a
successful or explicitly reconcilable result for every accepted invocation;
it does not hide dependency failure to claim an availability percentage.
Agentic Registry and the official publisher are critical and optional
dependencies respectively. Their latency is outside the local p99 target.

Assets worth protecting are Registry write authority, tenant catalog
existence, immutable artifact identity, signatures, SBOM and provenance
identity, and unpublished manifest content. Attackers include another
authenticated tenant, a malicious manifest author, a compromised delegated
binary, a dependency returning secret-bearing output, and a local user racing
evidence files. Trust boundaries are local files, process arguments and
environment, delegated command output, Agentic Registry, and the optional
official Registry. Every crossing is bounded and validated; authorization
remains in Registry and is never inferred from local metadata.

## Decision

### Keep publication outside serving runtime

Publication ships as the opt-in `tesserix-mcp-publisher` workspace
distribution. The core runtime has no new mandatory dependency and lazily
delegates the `validate`, `inspect`, `manifest`, and `publish` commands only
when the `publisher` extra is installed. The standalone
`tesserix-mcp-publish` entry point exposes the same command contract. Runtime
startup never publishes.

The package consumes prebuilt artifact, SBOM, and provenance references. It
does not run arbitrary build commands, push images, mint credentials, write
Registry databases, or mutate Kubernetes. It compiles the existing manifest
package's official `server.json` and Agentic manifest, then deterministically
adds immutable evidence under `spec.x-tesserix.publication` before computing
the canonical Agentic digest.

### Delegate authority to existing publishers

The workflow uses argv-only child processes with no shell. Human browser or
device authorization and CI client credentials remain owned by `agentic`.
The runtime accepts no client-secret flag and never writes tokens to a file.
`AGENTIC_TOKEN` and `AGENTIC_CLIENT_SECRET` values are protected by the final
output redactor; `AGENTIC_CLIENT_ID` and `AGENTIC_TOKEN_URL` remain ordinary
non-secret configuration passed through the environment to `agentic`.

All temporary manifests are regular files created with mode `0600` in a new
private temporary directory and removed after the delegated command returns.
Manifest, artifact, SBOM, and provenance inputs reject symlinks, non-regular
files, inode replacement, truncation, growth, empty content, and configured
size overruns. JSON command output rejects duplicate keys, non-finite values,
non-objects, invalid UTF-8, excess bytes, and protected material. Errors expose
only a stable code, safe message, request ID, and retryable flag.

### Publish Tesserix first and verify exactly

One non-dry execution is an ordered state machine:

1. validate and compile locally, hash evidence, and bind the canonical digest;
2. call atomic Agentic `apply` with the caller's idempotency key;
3. pull the exact name and version, recompute and compare its canonical digest;
4. verify the Registry signature for that exact version; and
5. only when explicitly requested, validate and publish `server.json` through
   the official publisher.

The idempotency key is required, contains 8–200 bounded safe characters, and
must be stable for the logical release. A replay returns Registry's original
receipt, including its original `created` value; it does not create a duplicate.
A `409` is an
immutable-version conflict and is never retried. Timeouts, connection errors,
`429`, `502`, and `503` before a confirmed write are typed unavailable results
and may be retried with the same key.

Once Agentic apply succeeds, a failed exact pull, digest comparison, or
signature check becomes `publication_outcome_unknown`. It is deliberately
non-retryable until the exact version is reconciled using the request ID,
`agentic pull`, and `agentic verify`. This prevents a process crash between
write and verification from becoming an untracked second publication.

Official publication is additive. Failure after a verified Tesserix publish
returns a partial result and exit code 6 with the verified Tesserix reference;
it never rewrites success as failure or silently substitutes the official
Registry for Tesserix. A later retry uses the same Agentic idempotency key and
reconciles the official target independently.

### Dry run reaches external validation without writing

Dry run performs the same local preparation, calls `agentic status`, and uses
`agentic apply --dry-run` with the real idempotency key. When the official
target is requested it also runs `mcp-publisher validate`. It never runs
Agentic apply without `--dry-run` or official publish. This proves credentials,
remote policy, and both generated manifests without creating Registry state.

## Failure and dependency analysis

- Artifact build or upload fails before invocation: no Registry call occurs;
  repair or reuse the prebuilt immutable artifact.
- Registry is unavailable before apply confirms success: return unavailable;
  retry the same inputs and idempotency key with bounded backoff owned by CI.
- The process dies while Registry applies: outcome is not knowable locally;
  reconcile the exact version and signature before another attempt.
- The same key is delivered twice: Agentic's atomic idempotency record returns
  the original result; local code performs exact verification again.
- An existing version has different content: return immutable conflict; fix
  the input or choose a new semantic version rather than overwriting it.
- Credentials are expired or revoked: `agentic` may refresh once under its
  supported auth flow; authorization denial is terminal and is not retried.
- Read-back identity, digest, or signature differs: return unknown outcome and
  page the release owner; never proceed to the official target.
- Official validation or publication fails: preserve the verified Tesserix
  result and report partial status for explicit reconciliation.
- A delegated process exceeds time or output bounds: terminate its POSIX
  process group (or the direct child on Windows), discard payload output, and
  return a typed safe failure. Cancellation performs the same cleanup before
  propagating.

There is no database transaction spanning the two registries. The pivot is a
verified Agentic publication. Before it, the workflow can safely retry with
the same idempotency key; after it, Agentic is durable and official publication
can only move forward. This is a small explicit saga whose terminal states are
dry-run, verified, partial, conflict, unavailable, and unknown outcome.

## Alternatives considered

- Add publication to runtime startup: rejected because serving identity and
  release write authority have different failure domains and least-privilege
  requirements.
- Call Registry HTTP or Postgres directly: rejected because it duplicates
  authentication, tenancy, idempotency, canonicalization, and signing owners.
- Build wheels or containers inside the publisher: rejected because arbitrary
  build execution expands supply-chain authority and makes retries mutable.
- Publish official Registry first or choose one target with a flag: rejected
  because official publication cannot replace the platform catalog and route
  source of truth.
- Automatically retry an unknown outcome: rejected because the write may have
  committed and safe recovery begins with exact reconciliation.
- Put the publisher in core: rejected because serving installations do not
  need release tooling and must retain the existing dependency envelope.

## Verification

- package tests exercise local preparation, evidence identity and replacement
  races, no-shell command limits, temporary-file permissions, duplicate JSON
  rejection, secret canaries, every workflow terminal state, and exact command
  ordering;
- root CLI tests prove lazy delegation, actionable missing-extra behavior, and
  unchanged installed `--version` output;
- CI runs branch coverage above 90%, Ruff, strict mypy, strict Pyright, public
  API drift checks, dependency policy, wheel/sdist inspection, and an isolated
  offline install of the publisher extra; and
- sandbox Agentic Registry evidence covers first publish, same-key replay,
  immutable conflict, exact read-back, signature verification, and
  unauthorized-tenant non-disclosure in memory and Postgres modes.

## Rollout and rollback

Roll out first in CI with `validate`, then `publish --dry-run`, then one
non-production tenant and one reviewed immutable version. Observe stable exit
codes and Agentic request IDs without logging command payloads. Enable the
official target only after Tesserix publication is routinely reconciled.

Rollback is one Git revert or removal of the optional `publisher` extra from
the release job. No serving pod, schema, queue, Gateway route, or cloud
resource changes. Already published versions are immutable and are not deleted
by rollback; supersede or deactivate them through their owning Registry and
Gateway workflows. The package adds build and test minutes plus transient
local hashing and process memory, but no always-on infrastructure, storage,
network egress service, or baseline cloud cost. Publication alerts belong to
the release pipeline and Registry SLO owner.

## Consequences

Authors gain a reusable fail-closed release path while Registry and existing
publisher tools retain their authority. The deliberate cost is explicit
reconciliation: an ambiguous post-write failure or a partial official target
cannot be converted into a convenient generic retry.
