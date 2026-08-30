# Tesserix MCP publisher

`tesserix-mcp-publisher` validates, inspects, compiles, and delegates immutable
MCP publication without adding publisher behavior to serving runtime pods.

The package is pre-release. Install it through the runtime extra:

```bash
pip install 'tesserix-mcp-runtime[publisher]'
```

Publication always targets Agentic Registry first. Official MCP Registry
publication is a separate explicit option and never replaces the Tesserix
result. Authentication, tenant policy, immutable storage, and signatures remain
owned by the corresponding publisher tools and registries.

The full command contract, exit-code recovery matrix, and credential guidance
are in the [Registry publication guide](../../docs/registry-publication.md).
The architecture and failure-state decision is
[ADR-0019](../../docs/adr/0019-delegated-immutable-registry-publication.md).
