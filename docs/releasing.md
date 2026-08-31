# Releasing and verifying Tesserix MCP runtime

This is the operator runbook for the tag-only release workflow. A release
publishes four Python wheels and source distributions through the GitHub
Release fallback plus two public GHCR variants. Every byte is bound to one
source tag, one workflow identity, checksums, SBOMs, and keyless attestations.

## Current channel decision

As of 2026-08-31, tesserix-mcp-runtime does not yet exist on PyPI. The three
companion project names are also unclaimed. PyPI trusted publishing therefore
cannot be treated as an available channel until a Tesserix PyPI owner creates
pending publishers for all four names and a release candidate proves them.

The verified GitHub Release fallback is the current Python channel. Consumers
download exact wheel versions from an immutable GitHub tag. They do not install
from `main`, a floating `latest` URL, or an unauthenticated private index.

No production token, PyPI API token, signing key, or registry password is
stored in this repository. GitHub supplies a job-scoped token and short-lived
OIDC identity only after the protected environment admits a tag run.

## Repository controls required before the first tag

Create these GitHub environments in repository settings:

```text
environment: release
required reviewer: a Tesserix repository administrator other than the tag actor
deployment branches/tags: refs/tags/v*
prevent self-review: enabled where the organization plan supports it

environment: pypi
required reviewer: a Tesserix package owner
deployment branches/tags: refs/tags/v*
prevent self-review: enabled where the organization plan supports it
```

The `release` environment protects GHCR publication, artifact attestations,
and draft/final GitHub Release mutation. The `pypi` environment is reserved for
future PyPI trusted publishing and is not referenced by the current workflow.
Creating it does not grant authority or enable publishing.

Protect `v*` tags from update and deletion. Never delete or move a published tag.
Require the release workflow's public-smoke job before an operator declares the
release complete. Repository-wide Actions defaults remain read-only; only
the protected publish job receives `packages: write`, `contents: write`,
`attestations: write`, `artifact-metadata: write`, and `id-token: write`.

## Release-candidate procedure

1. Start from a clean, up-to-date `main`. Confirm every required pull-request
   check is green and the intended version has never been used.
2. Review the committed MCP support matrix, migration impact, dependency audit,
   container vulnerability reports, base-image digests, and release notes.
3. Obtain explicit approval for the named public tag. Creating a public tag or
   release is not implied by ordinary code-review approval.
4. Create one annotated or signed tag such as `v0.1.0-rc.1` at the reviewed
   `main` commit and push that exact tag once.
5. Approve the `release` environment only after the guard, quality, security,
   compatibility, and container jobs pass for the tag SHA.
6. Wait for staged verification, finalization, and anonymous public smoke. Do
   not announce the release while any job is incomplete or failing.

The guard accepts only `vX.Y.Z` and `vX.Y.Z-rc.N`. It rejects leading zeros,
build suffixes, mutable names, a tag outside `main`, and an existing release.
The normalized Python version (`0.1.0rc1`) and OCI tag (`0.1.0-rc.1`) come from
one typed identity contract.

## What the workflow proves

The release orchestrator calls the existing quality, security, compatibility,
and container workflows rather than copying lighter release-only checks. After
they pass, the protected job:

- downloads the exact four wheels and four source distributions built by the
  quality gate and checks their shared version and clean-environment installs;
- extracts the built wheels for an artifact SPDX/CycloneDX inventory, exports
  the complete production-and-extra dependency closure from `uv.lock`, binds
  all four release versions, and fails the SBOM-to-lock comparison on drift;
- builds the core and ADK images from the same source/version, pushes only
  exact variant tags, and records immutable registry digests;
- regenerates each image and pinned base-image SBOM, requires every base
  component except explicitly reported pip-owned build tooling, proves pip is
  absent, retains every high/critical vulnerability, rejects every finding
  with an available fixed version, reports inherited unfixed risk, and
  exercises a real MCP initialize/list/call/error flow from both images;
- creates GitHub provenance and SBOM attestations, Cosign keyless signatures,
  and Cosign SBOM attestations;
- scans archives and retained evidence for secret shapes;
- creates a draft release, verifies the draft, publishes it, then downloads
  assets anonymously and pulls both images without registry credentials.

The release manifest records the tag, PEP 440 version, source SHA, workflow
ref, artifact SHA-256 values, sizes, and image digest references. `SHA256SUMS`
covers every downloadable asset and the manifest itself.

## Adversarial evidence and GA review

The `adversarial` release prerequisite runs the pinned Registry, AgentGateway,
identity, backing, and built-runtime journey before the protected publish job.
It must emit `security-evidence.json` with all 51 required cases passed, all 12
named sinks digest-bound, no open finding, and exact source/package/image/
manifest/SBOM/component identities. Missing or failed evidence prevents the
reusable workflow from succeeding and therefore prevents publication.

Nightly and release-candidate evidence may have `review: null`. A GA operator
must obtain a review from someone other than the evidence preparer and require
`SecurityReport.to_json(require_independent_review=True)` against the exact
reviewed scope. Changing any digest, result, sink, component, or finding after
review invalidates the scope digest. A green candidate run is not itself an
independent approval.

Follow the [security verification guide](security-verification.md) for the case
matrix, retained-evidence rules, finding ownership/remediation/retest policy,
verifier-outage behavior, and compatible contract upgrades.

## Consumer verification

Install the GitHub CLI and Cosign from their authenticated distribution
channels. Download a named release and verify bytes before installation:

```bash
tag=v0.1.0-rc.1
repo=tesserix/tesserix-mcp-runtime
workflow=tesserix/tesserix-mcp-runtime/.github/workflows/release.yml

gh release download "$tag" --repo "$repo" --dir "release-$tag"
cd "release-$tag"
sha256sum --check SHA256SUMS

for artifact in ./*.whl ./*.tar.gz; do
  gh attestation verify "$artifact" \
    --repo "$repo" \
    --signer-workflow "$workflow" \
    --source-ref "refs/tags/$tag" \
    --source-digest "$(jq -r .source_sha release-manifest.json)"
  gh attestation verify "$artifact" \
    --repo "$repo" \
    --signer-workflow "$workflow" \
    --source-ref "refs/tags/$tag" \
    --source-digest "$(jq -r .source_sha release-manifest.json)" \
    --predicate-type https://cyclonedx.org/bom
done
```

Inspect `release-manifest.json`, then verify each exact image reference:

```bash
identity="https://github.com/$workflow@refs/tags/$tag"
image="$(jq -r '.images[] | select(.variant == "core") | .reference' release-manifest.json)"
source_sha="$(jq -r .source_sha release-manifest.json)"

cosign verify \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-ref "refs/tags/$tag" \
  --certificate-github-workflow-repository "$repo" \
  --certificate-github-workflow-sha "$source_sha" \
  "$image"
cosign verify-attestation \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-ref "refs/tags/$tag" \
  --certificate-github-workflow-repository "$repo" \
  --certificate-github-workflow-sha "$source_sha" \
  --type cyclonedx \
  "$image"
```

Install all workspace wheels from the verified directory so internal
dependencies resolve to the same release:

```bash
python3.14 -m venv .release-venv
.release-venv/bin/python -m pip install \
  --find-links . \
  "tesserix-mcp-runtime==0.1.0rc1" \
  "tesserix-mcp-manifest==0.1.0rc1" \
  "tesserix-mcp-publisher==0.1.0rc1" \
  "tesserix-mcp-testkit==0.1.0rc1"
```

Use the digest from the manifest in GitOps. Never deploy an exact-looking tag
without its digest and verified workflow identity.

## PyPI trusted publishing

When Tesserix is ready to enable PyPI, a PyPI owner must create one pending
trusted publisher for each distribution with these exact claims:

- GitHub owner: `tesserix`
- repository: `tesserix-mcp-runtime`
- workflow: `release.yml`
- environment: `pypi`

Then add a reviewed, protected PyPI job using
`pypa/gh-action-pypi-publish` pinned to a full commit SHA with only
`id-token: write`. Do not add a token secret or reuse the GHCR job. A release
candidate must publish all four distributions, smoke-install from PyPI, and
compare hashes with the GitHub assets before PyPI becomes the documented
primary channel. Until then, the GitHub Release fallback remains authoritative.

## Failure and recovery

| Failure point | State | Required response |
|---|---|---|
| Any reusable gate | Nothing published | Fix through a PR; keep or delete the unpublished local tag according to tag policy |
| Image push or attestation | A versioned GHCR object may exist; no public release | Treat the version as burned, preserve evidence, and use a superseding version |
| Draft creation or staged smoke | Draft may exist; it is not a completed release | Do not replace assets; inspect the draft and publish a superseding version |
| Finalization | Verified draft remains recoverable | Re-run only the failed finalization job after confirming the draft asset hashes |
| Anonymous public smoke | Public release is incomplete | Open an incident, mark it affected, retain evidence, and publish a superseding version |
| Future PyPI/GitHub divergence | One channel may contain immutable bytes | Stop finalization, compare digests, follow the index incident procedure, and never rebuild the same version |

The publish job checks both exact image tags before either build. An existing
tag aborts publication; an ambiguous registry error also fails closed. A rerun
after any image push therefore cannot replace bytes and must use a superseding
version. Reruns after the protected publish job reuse its immutable outputs and
resume only staged smoke, finalization, or public smoke.

Rollback for a consuming service is one GitOps change to the previous verified
image digest and Python version. Release rollback never moves a tag backward
and never replaces package bytes.

## Yank, revoke, and CVE response

- PyPI: yank the affected version when that channel is enabled; do not delete
  it unless PyPI security directs otherwise. State why and name the successor.
- GitHub Release: keep forensic assets and attestations, mark the release and
  notes as affected, and link the advisory and superseding version.
- GHCR: stop new deployment through policy, retain the exact digest for audit,
  and revoke access only when containment requires it. A transparency-log
  signature cannot be erased; policy denies the affected digest.
- Critical CVE: publish a GitHub Security Advisory, identify supported
  versions, rebuild only under a new version from reviewed dependency/base
  pins, repeat all gates, and exercise rollback in non-production.
- Suspected OIDC or workflow compromise: disable the release environment,
  block the workflow identity at admission, preserve audit and transparency
  evidence, and require a clean superseding release.

## Recovery objectives and cost

Release metadata and artifact bytes have RPO 0: immutable published bytes are
never reconstructed under the same version. The release-control RTO is four
hours to diagnose a failed candidate and either safely resume finalization or
prepare a superseding version. Runtime invocation has no dependency on the
release workflow, PyPI, or GitHub after deployment.

At the current envelope of at most 24 releases per year, each release runs four
reusable gates plus one protected two-image build and two smoke jobs. The
expected GitHub-hosted duration is 15–30 minutes. Current compressed images are
about 67 MiB (core) and 146 MiB (ADK); wheels, source archives, SBOMs, and
attestation bundles are expected to stay below 20 MiB per release. This is
roughly 5.5 GiB/year before registry deduplication. Review actual duration,
storage, and egress cost after every six releases.

The release system stores no database state and has no backup. Git history,
GitHub Release assets, GHCR digests, attestations, and the transparency log are
the recovery evidence; their restore exercise is the clean-environment public
smoke performed for every release.
