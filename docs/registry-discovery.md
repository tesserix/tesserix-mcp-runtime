# Registry discovery

The Registry discovery client turns an authenticated intent into at most one
exact, digest-verified MCP server declaration. Agentic Registry remains the
ranking and object-authorization authority; this runtime adds bounded local
policy checks, identity-scoped caching, and an optional handoff to the existing
ADK MCP surface.

## Shipped contract

The implementation is pinned to the Agentic Registry behavior present at
commit `59a98273f693b5f9b87df41cb17f1c8af3139757`:

- `GET /v0/search` with `q`, repeated `kinds`, optional `namespace`, `limit`,
  and `view=stub`;
- a bare array of Registry-authorized safe stubs, bounded here to 20; and
- one exact same-origin fetch through the selected stub's relative
  `fetchPath`.

The client does not implement roadmap-only ETags, `POST` hybrid search,
minimum-score budgets, runtime hashes, bundle tools, or Registry MCP discovery
tools. Those require additive contract evidence after the corresponding
Registry work ships. Search order is Registry order; the runtime does not add
embeddings, a vector store, a catalog cache, or model reranking.

## Composition

`RegistryHTTPDiscovery` accepts any transport satisfying
`RegistryHTTPTransport`. In production, use the runtime's hardened
`OutboundHTTPClient` with an egress policy that authorizes only the Registry
origin. A `CredentialProvider[SecretValue]` is optional and is invoked for each
HTTP request; issued credentials are sent only in the authorization header and
are never cached.

```python
from tesserix_mcp_runtime import (
    InMemoryRegistryCache,
    RegistryCachePolicy,
    RegistryResolutionPolicy,
    RegistryResolver,
    RegistrySearchQuery,
    RegistryToolRequirement,
)
from tesserix_mcp_runtime.adapters.registry_adk import (
    to_adk_mcp_server_config,
)
from tesserix_mcp_runtime.adapters.registry_http import RegistryHTTPDiscovery

discovery = RegistryHTTPDiscovery(
    origin="https://registry.example.com",
    transport=outbound_http_client,
    credential_provider=registry_credentials,
)
resolver = RegistryResolver(
    discovery=discovery,
    cache=InMemoryRegistryCache(),
    cache_policy=RegistryCachePolicy(),
)

query = RegistrySearchQuery(
    intent="find a known order",
    kinds=("MCPServer",),
    namespace="tenant-orders",
)
policy = RegistryResolutionPolicy(
    server_name="orders",
    gateway_origin="https://gateway.example.com",
    supported_protocol_versions=("2025-11-25",),
    required_capabilities=("cap/orders-read",),
    tool_allow=("orders_get",),
    tool_requirements=(
        RegistryToolRequirement(
            name="orders_get",
            expected_input_fingerprint=reviewed_input_fingerprint,
            expected_output_fingerprint=reviewed_output_fingerprint,
        ),
    ),
)

resolution = await resolver.resolve(query, policy=policy, context=call_context)
if resolution.server is None:
    # Treat this as an explicit no-match. Do not choose a rejected candidate.
    raise LookupError("no authorized compatible MCP server")

adk_config = to_adk_mcp_server_config(resolution.server)
```

The example names application-provided objects rather than constructing
credentials or egress policy from environment variables. Identity comes from
the verified `CallContext`; it must never be copied from the search request.

## Resolution gates

The resolver preserves Registry ranking, selects the first stub that passes
cheap checks, and performs only one exact fetch. Before producing a server it
checks:

- artifact kind, namespace, advertised capabilities, and exact identity;
- canonical Registry digest, lifecycle, and MCP protocol overlap;
- server and per-tool scopes against the authenticated caller;
- default-deny tool allow/deny policy and finite tool/schema budgets;
- reviewed input/output fingerprints and optional input-schema compatibility;
  and
- a safe relative Gateway path joined to the operator-controlled HTTPS origin.

Rejected tools never enter the ADK configuration or model context. Candidate
explanations contain only an already-authorized Registry ref and stable reason
codes.

## Cache and outage behavior

| Value | Default | Hard maximum | Meaning |
| --- | ---: | ---: | --- |
| Search lease | 30 seconds | 30 seconds | Short authorization lease for bounded stubs |
| Exact lease | 60 seconds | 60 seconds | Fresh authorization lease for one immutable artifact |
| Offline stale window | Disabled | 1 hour | Explicit exact-fetch fallback only |
| Search entries | 128 | 1,024 | Process-local LRU bound |
| Exact entries | 64 | 256 | Process-local LRU bound |

Keys contain the canonical Registry origin, query-contract version, and a hash
over issuer, tenant, subject, and sorted scopes. Artifact keys also contain the
exact Registry digest. Raw identities, credentials, headers, and error bodies
never enter cache keys or values.

Cache failures fall through to Registry. Registry search failure cannot use a
stale catalog. When explicit offline policy is enabled, an exact-fetch outage
may use only a same-identity stale artifact selected by a fresh search stub;
identity and canonical digest are reverified after every cache read. Cache
hits never renew authorization leases.

External cache implementations must satisfy `RegistryDiscoveryCache`, retain
the supplied expiries, preserve key isolation, return only the typed immutable
contracts, and raise `RegistryCacheUnavailableError` when they cannot answer
safely. A cache is never an authorization source.

## ADK ownership

Install the exact optional profile before converting a projection:

```console
uv sync --extra adk
```

The adapter constructs ADK 0.53.1's existing `McpServerConfig` with the trusted
Gateway endpoint, exact reviewed allowlist, denylist, prefix, and budgets. ADK
continues to own live tool discovery, deterministic namespacing, collision
rejection, schema budgets, and caller-supplied `SurfacePin` checks.

`RegistryToolPin` values describe Registry-reviewed artifact metadata. They are
not ADK live `SurfacePin` fingerprints and must not be converted into them. Pin
the surface discovered from the live Gateway session through ADK's own API.

## Version evidence

The checked-in compatibility contract is:

- Python `>=3.12,<3.15`, including maintained Python 3.14 runtimes;
- `mcp>=2.1.1,<3` and `mcp-types>=2.1.1,<3`; and
- optional `tesserix-adk==0.53.1` from the hash-pinned release wheel.

This repository has no dependency, lock entry, or authoritative catalog
evidence for an MCP SDK release called `1.34`; do not publish an image or
compatibility claim under that invented version. If “1.34” meant Python 3.14,
Python 3.14 is explicitly supported and tested.

## Publication and Gateway activation

This client consumes artifacts that are already published and routes that are
already authorized. It does not publish a Registry version, watch the catalog,
create a Gateway route, or assert activation status. The manifest package can
compile deterministic publication input, while Registry publication and
Gateway reconciliation remain separate default-deny workflows. A future
gateway controller may discover published versions, but it must report
activation independently; a successful Registry search never proves a route
is live.

The decision, failure analysis, rollout, and rollback are recorded in
[ADR-0018](adr/0018-identity-scoped-registry-discovery.md).
