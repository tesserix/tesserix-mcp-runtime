# Tesserix MCP manifest compiler

`tesserix-mcp-manifest` turns one validated authoring document into two
byte-stable artifacts:

- official MCP `server.json`;
- `registry.agentic.dev/v1alpha1` Agentic Registry `MCPServer` JSON.

It is a build-time package exposed by the runtime's `manifest` extra. It is not
installed by the core serving runtime and never publishes, resolves, activates,
or fetches an MCP server.

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
schemas or hashes:

```python
from tesserix_mcp_manifest import ToolSummary

summary = ToolSummary.from_runtime(runtime_tool_manifest)
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

The full rationale, field table, failure behavior, and rollback policy are in
[ADR-0016](https://github.com/tesserix/tesserix-mcp-runtime/blob/main/docs/adr/0016-portable-and-agentic-registry-manifests.md).
