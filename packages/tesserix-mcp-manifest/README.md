# Tesserix MCP manifest compiler

`tesserix-mcp-manifest` turns one validated authoring document into two
byte-stable artifacts:

- official MCP `server.json`;
- `registry.agentic.dev/v1alpha1` Agentic Registry `MCPServer` JSON.

It is a build-time package exposed by the runtime's `manifest` extra. It is not
installed by the core serving runtime and never publishes, resolves, activates,
or fetches an MCP server.

The package also exposes the read-only reference contract for
[identity-scoped tenant Gateway reconciliation](../../docs/tenant-gateway-reconciliation.md):
default-deny eligibility, deterministic collision-safe route identity, quota
admission, digest-bound complete snapshots, and fail-closed cursor-page
assembly. It does not discover tenants, provision roles, render or apply
Kubernetes resources, or mutate Registry/Gateway state.

## Install

```bash
pip install 'tesserix-mcp-runtime[manifest]'
```

Python 3.12, 3.13, and 3.14 are supported. The Registry schema version, MCP
protocol revision, Python version, and MCP SDK package version are independent
compatibility dimensions.

## Compile

```python
from pathlib import Path

from tesserix_mcp_manifest import compile_manifests, load_authoring_manifest

source = Path("mcp-authoring.json").read_bytes()
manifest = load_authoring_manifest(source)
compiled = compile_manifests(manifest, runtime_version="1.2.3")

Path("server.json").write_bytes(compiled.server_json)
Path("mcpserver.json").write_bytes(compiled.registry_manifest)
print(compiled.server_digest, compiled.registry_digest)
```

The caller should write returned bytes atomically. The compiler itself performs
no filesystem or network mutation.

For runtime-generated tools, reuse their canonical metadata rather than copying
schemas or hashes. `ToolSummary.from_runtime` also reuses compatible
`ToolDiscoveryMetadata` summary, trigger, capabilities, examples, and deprecated
lifecycle when it is already present. Pass typed authoring metadata only to add
fields the core runtime contract does not carry or to override that projection:

```python
from tesserix_mcp_manifest import (
    DiscoveryRisk,
    ManifestLifecycle,
    SemanticMetadata,
    ToolSummary,
)

summary = ToolSummary.from_runtime(
    runtime_tool_manifest,
    semantic=SemanticMetadata(
        summary="Return one order by its stable identifier.",
        when_to_use=("look up one known customer order",),
        not_for=("changing fulfillment state",),
        capabilities=("cap/orders-read",),
        requires=("arn:agentic:registry:tenant-orders:tools/tenant-orders/customer_lookup",),
        risk=DiscoveryRisk.LOW,
    ),
    lifecycle=ManifestLifecycle.ACTIVE,
)
```

See `tests/goldens/` for complete remote, PyPI, OCI, public, internal, private,
ADK, and native authoring examples.

## Output mapping

Name, version, title, description, repository, remotes, packages, and transport
are compiled once into the official portable document. The Agentic envelope
copies those fields unchanged into `spec` and adds:

- ownership, namespace, tenant, visibility, tag, labels, and annotations in
  `metadata`;
- a Secret name/data-key reference in `spec.credentialRef`;
- lifecycle, adapter, protocol compatibility, route policy, semantic metadata,
  egress hosts, scopes, and tool fingerprints in `spec.x-tesserix`.

Literal credentials never belong in either artifact. Loading rejects
secret-shaped keys recursively and accepts only the typed credential-reference
shape.
Compilation also rechecks dynamic ownership labels and annotations so a
programmatically mutated model cannot bypass that boundary.

## Semantic discovery authoring

`SemanticMetadata` is the single source for server and tool intent. Summaries,
trigger phrases, negative cues, examples, domains, keywords, capabilities,
requirements, and risk are bounded and secret-safe. Capabilities use
`cap/<lower-kebab-name>`. Requirements use canonical Registry ARNs:

```text
arn:agentic:registry:<tenant>:<plural>/<namespace>/<name>
```

The compiler emits only the four publisher annotations accepted by Agentic
Registry issue 68:

| Typed field | Registry annotation |
|---|---|
| `summary` | `discovery.agentic.dev/summary` |
| `when_to_use` | `discovery.agentic.dev/when-to-use` |
| `capabilities` | `discovery.agentic.dev/capabilities` |
| `requires` | `discovery.agentic.dev/requires` |

Negative cues, examples, risk, domains, and keywords remain structured under
`spec.x-tesserix.semantic`; the compiler does not invent unaccepted annotation
keys. `registry.agentic.dev/body-tokens` is Registry-managed and publishers
cannot claim either reserved namespace.

Each Tool projection contains its safe description, input property
name/type/description/requiredness, capabilities, requirements, risk, and
lifecycle. Credential-shaped properties are omitted. Defaults, example values,
headers, environment values, and executable bodies are never copied. Unsafe
descriptions or property names fail without echoing their content.

### Author lint

Compilation remains additive for older manifests. CI and publishing should run
the stricter author linter:

```python
from tesserix_mcp_manifest import lint_semantic_manifest

findings = lint_semantic_manifest(manifest)
for finding in findings:
    print(finding.code.value, finding.path)
```

Findings contain only a stable typed code and field path. They flag missing or
vague intent, duplicated description/intent, marketing or model-control text,
the 1,500-token aggregate discovery budget, and tool capabilities,
requirements, risk, or lifecycle outside the server envelope.

### Progressive disclosure and authority

Discovery follows one fixed sequence:

```text
intent -> authorized Registry search -> bounded stubs -> exact authorized fetch
       -> compatibility check -> policy authorization -> runtime invocation
```

Relevance selects candidates only. Compatibility determines whether schemas and
protocols can interoperate. Policy authorization determines tenant, scope,
approval, and egress access. Runtime invocation executes only after all three.
Search failure may use the Registry's authorized lexical fallback; it never
falls back to an unfiltered catalog or a runtime-owned vector index.

### Retrieval evaluation

`evaluate_discovery` accepts recorded ranked Registry results and reports
precision at K, no-good-match accuracy, incompatible/deprecated recommendation
counts, and every forbidden-tenant exposure. It embeds nothing and owns no
catalog. The checked-in `evaluation/semantic-discovery.json` dataset covers
ambiguous intent, near duplicates, wrong tenant, deprecated and incompatible
candidates, and no good match. `architecture/check_semantic_discovery.py`
lints all generated examples and enforces the recorded metric thresholds in CI.

`extract_server_json(registry_manifest)` is a lossless envelope-to-official
round trip. The reverse direction is intentionally lossy because official
`server.json` has no Tesserix ownership, policy, semantic, or credential-reference
fields. Keep the authoring JSON as the source of truth.

## Determinism and limits

Outputs use sorted UTF-8 JSON, two-space indentation, sorted list-like metadata,
and one trailing newline. They contain no generated timestamp or identifier.
SHA-256 properties cover the exact returned bytes.

The safe loader rejects input over 65,536 bytes, depth 16, or 4,096 nodes, plus
duplicate keys, malformed UTF-8/JSON, non-standard numbers, unknown fields, and
unsafe URLs. Remote and repository URLs are validated syntactically without DNS
or HTTP access. Runtime version must equal manifest version; versioned packages
must match too. OCI identity requires a separate `sha256:` digest.

## Pinned validation

The vendored official schema is `2025-12-11` from MCP Registry `v1.8.1`, commit
`f52dc8525a441a3abf5fedc9912152d95af5aab1`, SHA-256
`578b5bb01866d060ff6a67734cf6b2f17a5da283a0877775c7913e4761a626e5`.

Offline verification:

```bash
python architecture/update_manifest_schema.py --verify
pytest packages/tesserix-mcp-manifest/tests
```

The compatibility workflow additionally runs official `mcp-publisher validate`
and pinned local `agentic validate -f` against every golden. Neither command in
that workflow publishes or writes registry state.

As of 2026-08-30, Agentic Registry issue 68 is still open and has no merged
implementation PR. The pinned Agentic validator therefore proves the generated
envelope remains accepted; local contract tests pin the reserved annotation and
safe Tool projection proposed by issue 68. This is explicit pre-merge
compatibility evidence, not a claim that Registry indexing support has shipped.

The full rationale, field table, failure behavior, and rollback policy are in
[ADR-0016](https://github.com/tesserix/tesserix-mcp-runtime/blob/main/docs/adr/0016-portable-and-agentic-registry-manifests.md)
and
[ADR-0017](https://github.com/tesserix/tesserix-mcp-runtime/blob/main/docs/adr/0017-bounded-semantic-discovery-authoring.md).
