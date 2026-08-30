# ADR-0024: Immutable release supply chain

- Status: Accepted
- Date: 2026-08-31
- Tracking: [tesserix-mcp-runtime#27](https://github.com/tesserix/tesserix-mcp-runtime/issues/27)
- Supersedes: none

## Context and quantitative envelope

The repository builds four Python distributions and two runtime image variants,
but before this decision it had no tag-triggered publisher, protected release
environment, package channel, signature, or public-channel smoke test. PyPI
returned 404 for all four distribution names on 2026-08-31. GHCR had no
repository package that this account could inspect without a `read:packages`
scope. No repository secret or variable existed.

The release envelope is at most 24 releases per year. One run handles eight
Python archives, two images currently about 67 MiB and 146 MiB compressed, and
less than 20 MiB of release metadata. The target is completion within 30
minutes on GitHub-hosted runners. Release failure must not affect invocation;
RPO for published bytes is zero and the release-control RTO is four hours to
resume safe finalization or create a superseding candidate.

Assets worth protecting are source-to-artifact identity, package/image bytes,
workflow OIDC authority, SBOMs, signatures, release metadata, and consumer
trust. Threats include a malicious tag, compromised action or dependency,
untrusted pull request, stolen long-lived credential, tag/image substitution,
partial multi-channel publication, and accidental secret retention. Trust
boundaries are the tag guard, reusable unprivileged gates, protected release
environment, GitHub artifact service, GHCR, future PyPI publisher, and public
consumer verification.

## Decision

One immutable `vX.Y.Z` or `vX.Y.Z-rc.N` tag on an already integrated `main`
commit is the release identity. A typed parser derives both the PEP 440 version
and OCI tag. Leading-zero, build-suffix, mutable, newline, overlong, off-main,
reused, or otherwise ambiguous tags fail before publication.

The release workflow reuses the complete quality, security, compatibility, and
container workflows through `workflow_call`. Those jobs remain read-only. Only
the protected `release` job receives job-scoped `contents`, `packages`,
`attestations`, `artifact-metadata`, and OIDC write permissions. It receives no
static secret.

The protected job publishes:

1. all four wheels and source archives built by the quality gate;
2. exact core and ADK image tags, always consumed by digest;
3. wheel-content SPDX/CycloneDX inventory, a CycloneDX dependency closure
   derived from `uv.lock`, and final/base-image CycloneDX inventories;
4. GitHub SLSA provenance and SBOM attestations;
5. Cosign keyless image signatures and SBOM attestations;
6. a bounded manifest, SHA256SUMS, compatibility matrix, release notes,
   vulnerability reports, runtime reports, and verification runbook.

The workflow binds all workspace versions into the dependency SBOM and rejects
any component/version absent from the lock. Final images remove pip after the
last local install; the base comparison permits and reports only pip-owned
components missing from the final SBOM, while every other base component must
remain. Runtime verification proves no pip or shell is executable. The workflow
also checks source/version OCI labels. Trivy retains every HIGH/CRITICAL finding
and a typed gate rejects any finding with an available fixed version. Unfixed
findings remain visible release evidence and follow the owning base-image
remediation policy; no CVE ID is silently waived downstream.
It creates a draft GitHub release. A separate read-only job verifies checksums,
GitHub provenance and CycloneDX predicates, Cosign repository/ref/SHA identity,
SBOM attestations, clean Python 3.14 installs, and real MCP calls before a second
protected job finalizes the draft. A final job downloads release assets without
authentication and pulls the public images after logging out of GHCR.

GitHub Releases are the documented Python fallback until PyPI pending trusted
publishers exist for every distribution. Enabling PyPI requires a separate
reviewed job in the `pypi` environment, no token secret, cross-channel digest
comparison, and a release-candidate smoke from PyPI.

## Options considered

### Publish directly to PyPI now

Rejected. The project names do not exist and no pending publisher is evidenced.
Pretending the channel exists would make the first release irrecoverable or
encourage a static token.

### Use personal API tokens or signing keys

Rejected. Long-lived credentials broaden theft and rotation impact. GitHub OIDC
and Sigstore certificates bind short-lived authority to the exact workflow,
repository, ref, and protected environment.

### Rebuild independently for GitHub, PyPI, and GHCR

Rejected. Independently built bytes can diverge while sharing a version. One
tag and one gate-built distribution set feed every channel; images record the
same source SHA and normalized version.

### Copy reduced checks into the release workflow

Rejected. A lighter release-only suite would drift from branch protection.
Reusable workflows make the full gates the one implementation.

### Publish mutable `latest`, `stable`, or replacement tags

Rejected. Consumers and GitOps use exact versions plus digests. Mutable aliases
hide substitution and make rollback evidence ambiguous.

## Failure behavior and rollback

Any gate failure publishes nothing. Release and registry absence checks fail
closed on ambiguous API errors. Once an image or artifact becomes visible, that
version is burned; immutable-tag preflight prevents a rerun from overwriting it.
A failed staged smoke leaves a draft. A failed public smoke creates an incident
and a superseding version. The exact recovery matrix, CVE process, yank policy,
and OIDC containment steps live in `docs/releasing.md`.

Consumer rollback is one GitOps change to the previous verified image digest
and pinned Python version. There is no release datastore, migration, or runtime
dependency to restore. Git history, immutable assets, registry digests,
attestations, and transparency entries are the recovery evidence.

## Consequences

The first release requires repository environment and tag-protection settings,
a human approval, and explicit authorization for the named public RC tag. CI
cost increases by a full gate set and two image builds per release, bounded by
low release frequency. GitHub Releases remain less convenient than PyPI, but
they are public, attestable, smoke-testable, and honest about current external
state.

The workflow publishes only the host platform image today. Multi-architecture
images, PyPI, mutable aliases, automatic tag creation, and automatic yanking
are deliberately not implemented. Each requires separate evidence rather than
being hidden behind a release flag.
