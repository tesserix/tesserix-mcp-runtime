# ADR-0016: Portable and Agentic Registry MCP manifests

- Status: Accepted
- Date: 2026-08-30
- Tracking: [tesserix-mcp-runtime#18](https://github.com/tesserix/tesserix-mcp-runtime/issues/18)

## Context

MCP publication needs an official `server.json`, while Tesserix discovery and
Gateway activation need ownership, tenant, lifecycle, routing, semantic, and
credential-reference metadata in an Agentic Registry `MCPServer`. Maintaining
those documents independently would let identity, version, transport, or
repository fields drift before publication.

This is a build-time compiler, not a serving hop. It receives zero production
requests per second, stores zero bytes at 12 or 36 months, adds no request
latency, and has no production availability SLO. A normal checked-in authoring
document is 1,521 to 1,673 bytes; its official output is 474 to 693 bytes and its
Agentic output is 2,061 to 2,169 bytes. On Python 3.14t arm64 macOS, 10,000
representative compiles took 0.268 seconds, or 26.79 microseconds each. These
figures are evidence for normal manifests, not a claim for adversarial maximum
input.

The trust boundary is an untrusted authoring JSON document becoming public and
tenant-scoped registry metadata. Assets are package identity, route ownership,
semantic discovery integrity, and credential references. Attackers include a
malicious author, a compromised build dependency, another tenant, and an insider
attempting to place literal credentials in metadata. Every input is therefore
bounded and validated before compilation; neither compilation nor default tests
fetch a supplied URL.

## Decision

### Separate build-time distribution

Publish `tesserix-mcp-manifest` as a typed workspace distribution and expose it
through the runtime's `manifest` extra. It depends on the runtime contract and
Pydantic but is not a core runtime dependency. `ToolSummary.from_runtime`
consumes `ToolManifest` names, descriptions, scopes, and fingerprints directly,
so runtime schemas remain the authority established by ADR-0007.

The measured manifest wheel is 14,604 bytes. The explicit manifest profile
resolves 35 distributions; the core remains 34. Adding the optional-extra
metadata moves the runtime wheel to 98,142 bytes, still below its fixed 98,304
byte ceiling. There is no container, service, database, queue, cache, network
policy, alert, backup, or production infrastructure cost.

### One strict authoring boundary

`ServerAuthoringManifest` is frozen and rejects unknown fields. JSON loading is
limited to 65,536 bytes, depth 16, and 4,096 nodes. It rejects duplicate keys,
non-standard JSON numbers, malformed UTF-8, secret-shaped keys at any depth, and
model failures through stable payload-free `ManifestValidationError` codes.
Only root `credential_ref.secret_name` and its key name are accepted as a secret
reference shape; literal password, token, API-key, client-secret, private-key,
authorization, or credential fields are rejected.
The compiler repeats that check for dynamic ownership labels and annotations
immediately before serialization because frozen Pydantic models do not
deep-freeze their dictionaries.

Deployed remotes and repositories require absolute HTTPS without userinfo,
query or fragment delimiters, malformed escapes, authority percent-encoding,
backslashes, traversal after repeated decoding, whitespace, control characters,
or more than 2,048 UTF-8 bytes. Package-local Streamable HTTP may use HTTP for a
loopback process. Validation performs no DNS lookup, connection, HTTP request,
or package fetch.

Runtime version must equal manifest version. A versioned package must also equal
that version. Package ranges and `latest` are rejected. OCI packages require a
separate `sha256:` image digest and compile to the official digest-qualified
identifier `image[:tag]@sha256:...` without inventing a nonportable package
field.

### Portable core and Tesserix envelope

Compilation first creates one official portable document. The Agentic envelope
copies that exact object into `spec`, then adds only Agentic or Tesserix fields.

| Authoring concept | Official `server.json` | Agentic `MCPServer` |
|---|---|---|
| schema, name, version, title, description | root fields | identical fields in `spec` |
| repository | `repository` | identical `spec.repository` |
| deployed Streamable HTTP endpoint | `remotes[0]` | identical `spec.remotes[0]` |
| package or digest-qualified OCI image | `packages[0]` | identical `spec.packages[0]` |
| namespace, tenant, org, team, visibility | not portable | `metadata` |
| artifact version | root `version` | root `spec.version` and `metadata.tag` |
| labels and narrative annotations | not portable | `metadata.labels` and `metadata.annotations` |
| credential reference | not portable | `spec.credentialRef` |
| adapter, lifecycle, protocols, route policy | not portable | `spec.x-tesserix` |
| semantic capabilities, domains, keywords | not portable | `spec.x-tesserix.semantic` |
| egress hosts, scopes, tool summaries | not portable | `spec.x-tesserix` |

`credentialRef` carries a Kubernetes Secret name and data key only. It never
carries the Secret value. Issue #21 owns authenticated, idempotent publication;
issues #19, #20, and #22 own registry resolution, semantic filtering, and
Gateway activation. This compiler performs none of those external mutations.

### Canonical bytes and round-trip limits

Both artifacts use UTF-8 JSON with sorted keys, two-space indentation, Unicode
preservation, finite numbers, and one terminal newline. Tuple-like semantic and
scope data and tool summaries are sorted before encoding. There are no clocks,
random values, generated identifiers, or timestamps. SHA-256 digests are over
the exact returned bytes, so duplicate builds are idempotent and byte-identical.

Envelope to official is lossless: `extract_server_json` removes
`credentialRef` and `x-tesserix` and returns the same canonical portable bytes.
Official to authoring is deliberately lossy. `server.json` cannot reconstruct
ownership, tenant, visibility, labels, lifecycle, route policy, credential
reference, semantic metadata, egress policy, tool fingerprints, or adapter.
Compiled bytes also cannot recover original ordering because list-like metadata
is canonicalized. The authoring document remains the source of truth; neither
output is edited and reverse-compiled.

### Pinned compatibility evidence

The official schema is `2025-12-11`, embedded by MCP Registry release `v1.8.1`
at commit `f52dc8525a441a3abf5fedc9912152d95af5aab1`. The exact vendored bytes have
SHA-256 `578b5bb01866d060ff6a67734cf6b2f17a5da283a0877775c7913e4761a626e5`.
The live static URL later removed one `Package.version.maxLength` constraint;
the release-pinned schema is stricter, and outputs valid against it remain valid
against the relaxed live document.

Three checked-in golden scenarios cover remote/public/native,
PyPI/internal/ADK, and OCI/private/native. All validate offline against the
pinned schema. The Sigstore-verified `mcp-publisher` 1.8.1 binary and the same
publisher source commit each returned `server.json is valid` for every official
golden. Agentic Registry release `v0.2.1` defines the accepted envelope. Its
released CLI lacks a no-write validation command, so commit
`8f0b5615fdfd1adbe48ade99e717f6cff22535e7` is pinned for local
`agentic validate -f`; all three envelopes returned `valid: 1 resource(s)` with
no registry configuration or HTTP call.

A path-scoped compatibility workflow reruns both upstream validators without
`publish`, `push`, or `apply`. A weekly workflow discovers schemas only from the
latest released Registry commit, verifies bounded bytes and `$id`, retains old
schema files, and opens a reviewed pull request. It never silently updates a
release or golden.

## Failure behavior

| Failure | Behavior |
|---|---|
| source exceeds byte, depth, or node limit | reject before model compilation with a stable safe code |
| duplicate key, invalid UTF-8/JSON, or non-finite number | reject without echoing source bytes |
| literal secret-shaped field appears | reject recursively; accept only the typed Secret reference shape |
| remote URL is unsafe or unsupported | reject without DNS or HTTP access |
| runtime, package, and manifest versions disagree | fail the build before any publication step |
| OCI digest is absent, malformed, or mixed into the identifier | reject the package identity |
| official schema changes | automation opens a review; existing pins and releases remain reproducible |
| official or Agentic validator is unavailable | compatibility lane fails; no artifact is published or activated |
| compilation is repeated | return identical bytes and digests; no external idempotency key is needed |
| build process crashes | returned/in-memory bytes are lost; no registry, route, or datastore state changes |

There is no distributed transaction, outbox, retry loop, saga, compensation,
cache consistency, backup, RTO, or RPO requirement in this slice. Future
publication must supply its own durable idempotency and rollback semantics.

## Alternatives considered

- Maintain `server.json` and Agentic YAML independently: rejected because shared
  identity and transport fields would drift.
- Put Tesserix fields inside official package definitions: rejected because
  unknown portable fields reduce interoperability and the envelope owns them.
- Compile inside every serving pod: rejected because compiler dependencies and
  schema files do not belong in the latency or failure path.
- Fetch remote URLs during validation: rejected because it creates SSRF,
  availability, and nondeterminism risks without proving MCP behavior.
- Store literal credentials for publisher convenience: rejected because build
  artifacts, diffs, caches, and registries are not secret stores.
- Track the mutable static schema URL without a release commit: rejected because
  the supposedly versioned content has already changed in place.
- Use Agentic `apply --dry-run` as the only validator: rejected for the release
  baseline because `v0.2.1` has no dry-run flag and `/v0/apply` writes state.

## Rollout and rollback

Rollout publishes the optional manifest distribution with the same VCS version
as runtime and testkit, then issue #21 consumes its canonical bytes in a
separately reviewed publication workflow. No live Registry record, Gateway
route, Kubernetes object, credential, database schema, or production pod changes
in this decision.

Rollback removes the `manifest` extra or pins the previous package release and
reuses its checked-in schema/goldens. A bad schema update is reverted as one Git
change; released artifacts are never overwritten. Later publication rollback
must reactivate the prior immutable registry version rather than mutating an old
manifest in place.

## Consequences

Authors review one bounded source and two deterministic, diffable outputs.
Official consumers see no Tesserix package extensions, while the Agentic
Registry receives enough tenant, discovery, route, and Secret-reference metadata
for later filtering and activation. The costs are a 14.6 KiB optional wheel,
one additional 35-distribution build profile, pinned upstream compatibility
lanes, and explicit review whenever either registry contract changes.
