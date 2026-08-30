# ADR-0010: Gateway JWT verification and tenant context

- Status: Accepted
- Date: 2026-08-30
- Tracking: [tesserix-mcp-runtime#12](https://github.com/tesserix/tesserix-mcp-runtime/issues/12)

## Context

AgentGateway is the supported public ingress, but a runtime cannot treat its
headers, route, model arguments, or MCP metadata as identity. Any workload that
can reach the listener could otherwise claim another tenant. A pooled process
also needs a fresh immutable authority object for each request so one caller's
tenant, scopes, or trace state cannot become ambient state for the next.

The assets are tenant and subject identity, tool authority, credentials, and
tenant-confidential inputs and results. Threat actors include an unauthenticated
caller, an authenticated caller from another tenant, a workload inside an
over-broad trusted network, a compromised Gateway, a malicious token using URL
headers, and a compromised or unavailable JWKS service. Trust crosses twice:
from Gateway to runtime and from runtime to the configured JWKS endpoint. Both
crossings validate independently and fail closed.

The existing per-pod envelope is 50 sustained and 200 burst calls per second,
64 KiB requests, 512 KiB responses, at most 15 ms p99 runtime-added latency,
99.9% monthly invocation availability, an expected 12-tool catalog, and a
reviewed maximum of 128 tools. Planning grows from about 100 servers at 12
months to 500 at 36 months with an 80:20 read-to-write mix. Authentication adds
one local signature verification per request. JWKS network I/O occurs only on
a cold cache, rotation, or refresh and has a two-second ceiling; those exceptional
requests are availability events, not evidence that the 15 ms p99 is met.
Issue #29 owns production latency and outage evidence.

MCP SDK versions remain `>=2.1.1,<3`, locked at 2.1.1. MCP SDK 1.34 does not
exist; Python 3.14 is a separate runtime version as ADR-0002 records.

## Decision

### Verify at the transport boundary

Add `GatewayJWTContextProvider` as an `HTTPCallContextProvider`. For every
request it first requires the direct ASGI peer to match an explicit trusted
proxy CIDR, then requires exactly one bounded bearer token. It verifies the
signature with one configured asymmetric algorithm (`RS256`, `ES256`, or
`EdDSA`), exact HTTPS issuer, exact audience, required `sub` and canonical
tenant claim, `iat`, `nbf`, `exp`, bounded lifetime, and bounded `kid`.
The tenant claim cannot alias a standard subject, issuer, audience, time,
scope, actor, client, run, or token-ID claim.

The provider constructs a new frozen `AuthenticatedIdentity` and `CallContext`
per request. No tenant, subject, scope, run, trace, cancellation, or request
value is stored on a provider-wide current-context field. Concurrent tenants
share only immutable public verification keys and the single-flight refresh
lock.

Authentication runs before the official SDK parses the body or opens a tool or
ADK session. Every authentication failure becomes the same HTTP 401 shape with
only a bounded safe request ID. Tokens, claims, key IDs, URLs, upstream bodies,
and verifier exceptions cannot cross the response boundary.

### Make verified token authority dominant

Subject, tenant, and scopes come only from the verified token. Optional
forwarded subject, tenant, scope, and run headers are accepted only after the
direct-peer check and must agree. A run header may supply attribution when the
token omits `run_id`; request and W3C trace headers remain attribution, never
identity.

Remote MCP metadata under both `tesserix/runtime/*` and `tesserix/adk/*` is
non-authoritative. If supplied, tenant, subject, run, scopes, trace, and
idempotency values must equal `CallContext`; disagreement returns a stable
`authority_mismatch` before endpoint invocation. Matching duplicates do not
replace the context.

Per-tool scope, effect, approval, and object authorization remain issue #13 and
downstream repository responsibilities. This identity adapter supplies verified
authority; it does not turn possession of any valid token into permission for
every tool or object.

### Use bounded rotating JWKS with stale-known-key degradation

`HTTPSJWKSFetcher` requests one operator-configured HTTPS URL with redirects
and environment proxies disabled. Configuration rejects credentials, IP
literals, alternate ports, query strings, fragments, and hosts outside the
explicit allowlist. Responses must be JSON, at most 64 KiB, and contain at most
32 unique key IDs. Only keys for the fixed algorithm and signing use are loaded.

Keys are fresh for 15 minutes. A known fresh key verifies locally. An unknown
key forces a single-flight refresh, allowing normal rotation without waiting
for expiry. A successful refresh replaces the complete keyset and evicts keys
the issuer removed.

If refresh fails, an already-known key may be used for at most one hour from
its successful fetch. Unknown keys, an empty cache, and keys beyond that stale
window fail closed. Failed refreshes back off for five seconds. This prevents a
JWKS outage or attacker-selected `kid` from creating an unbounded fetch storm.

The stale choice is explicit: it preserves calls with a previously validated
public key during a short identity outage, but can delay emergency revocation
of a compromised signing key until the shorter of token expiry and the
one-hour stale window. Operators may reduce both token lifetime and stale age.

### Require infrastructure containment for the residual network risks

CIDR membership does not prove a workload principal. DNS validation also does
not pin the address used by the HTTP stack. Mesh authorization and NetworkPolicy
must restrict runtime ingress to AgentGateway and restrict egress to the
reviewed identity host while blocking private, loopback, link-local, and cloud
metadata destinations. Route activation remains blocked until #22, #24, and
#25 prove those deployment properties.

## Failure behavior

| Failure | Behavior |
|---|---|
| Untrusted or missing direct peer | Generic 401; forwarded request ID is not trusted |
| Missing, duplicate, malformed, forged, expired, or substituted token | Generic 401 before MCP parsing |
| Forwarded attribution disagrees with verified authority | Generic 401 before context creation |
| MCP runtime or ADK authority metadata disagrees | Stable `authority_mismatch` before tool invocation |
| Known key and fresh cache | Local verification; no network call |
| Unknown key | One single-flight refresh, then verify or fail closed |
| JWKS unavailable with an in-window known key | Verify locally during the bounded stale window |
| JWKS unavailable without a usable known key | Generic 401 |
| Malformed, duplicate, wrong-use, or oversized JWKS | Reject the refresh; stale-known-key rule only |
| Authentication task cancellation | Propagate cancellation; do not convert it to 401 |

No automatic call retry occurs. Authentication has no side effect, so duplicate
delivery creates a new context and repeats local verification safely. A crash
loses only the in-memory public-key cache; the next request performs a bounded
fetch. There is no transaction, outbox, compensation, durable migration, or
cross-process cache.

## Alternatives considered

- Trust Gateway headers after a route match: rejected because any workload
  reaching the listener could forge tenant and subject authority.
- Trust mesh identity without a runtime-audience token: rejected because it
  authenticates the Gateway workload, not the end caller or tenant grant.
- Introspect every token remotely: rejected because it adds a synchronous
  network hop, identity-service availability dependency, and credential-bearing
  request on every invocation.
- Pin public keys only in deployment configuration: rejected because routine
  rotation would require a rollout and emergency rotation would be slow.
- Honor `jku`, `jwk`, or `x5u` from the token: rejected because attacker-selected
  key locations create signature-substitution and SSRF paths.
- Fail immediately when the 15-minute fresh window ends: rejected because a
  bounded stale known key preserves availability without admitting an unknown
  key; the delayed-revocation consequence is documented and configurable.
- Add OIDC discovery: rejected for this slice because the operator already owns
  the exact issuer and JWKS contract, and dynamic discovery widens network and
  configuration trust without satisfying another required caller.

## Verification

Locally generated keys and fake fetchers cover valid immutable context,
signature and claim failures, token lifetime, duplicate headers, untrusted
peers, forwarded disagreement, concurrent tenants, rotation, removed keys,
stale outage and expiry, unknown-key rejection, single-flight refresh, URL and
response constraints, malformed/duplicate/oversized documents, and every
configuration boundary. The ASGI suite proves authentication precedes malformed
JSON parsing and two tenants remain isolated through one listener and key cache.
The exact optional ADK suite proves compatible authority behavior.

```bash
uv run --frozen pytest -q -o addopts='' tests/security/test_gateway_identity.py
uv run --frozen pytest -q -o addopts='' tests/protocol/test_streamable_http.py
uv run --isolated --frozen --extra adk pytest -q -o addopts='' compatibility/adk/test_bridge.py
```

## Consequences, cost, rollout, and rollback

Core gains direct dependencies on HTTPX and `PyJWT[crypto]`. HTTPX adds
`certifi`, `httpcore`, and `httpx` to the core resolution, moving the frozen
core profile from 31 to 34 distributions while remaining under the budget of
36. PyJWT and cryptography were already present in the resolved closure but are
now intentional direct requirements for the verifier. There is no new running
service, datastore, queue, durable storage, or background task. Network cost is
one small JWKS response per cold instance or rotation, not per invocation.

Rollout keeps the route inactive, installs exact versioned identity and network
configuration, and probes valid, invalid, cross-tenant, rotation, and outage
paths before activation. Error and refresh signals must remain payload-free.
Issue #16 owns those runtime signals; their absence must remain explicit until
the observability adapter is delivered.

Rollback drains the instance and restores the previous immutable image and a
previously verified identity configuration. If the previous image did not
independently verify a runtime-audience token, the route stays inactive; it
must not fall back to trusting forwarded identity. No Registry state, schema,
token, or durable cache needs rollback.
