# Gateway identity verification

`GatewayJWTContextProvider` verifies one gateway-issued bearer token for every
HTTP request and creates an immutable `CallContext`. Tenant, subject, and scopes
come only from the verified token. Forwarded headers and MCP `_meta` can confirm
that authority, but they cannot create or replace it.

The supported topology is:

```text
caller -> AgentGateway -> trusted network path -> runtime /mcp
                                              -> configured HTTPS JWKS endpoint
```

Do not expose the runtime directly. A trusted proxy CIDR is a source-address
check, not workload identity by itself; mesh authorization and Kubernetes
NetworkPolicy must ensure that only AgentGateway can reach the runtime. Use the
narrowest CIDR possible. For a same-pod gateway sidecar, prefer an exact
loopback range rather than a cluster-wide pod range.

## Compose the verifier

Use versioned deployment configuration for every value. The example domains
below are reserved documentation values, not production settings:

```python
from tesserix_mcp_runtime.adapters.gateway_identity import (
    GatewayIdentityConfig,
    GatewayJWTContextProvider,
)
from tesserix_mcp_runtime.adapters.streamable_http import (
    StreamableHTTPConfig,
    StreamableHTTPLimits,
    StreamableHTTPTransport,
)

identity = GatewayJWTContextProvider(
    GatewayIdentityConfig(
        issuer="https://identity.example.invalid",
        audience="urn:example:tesserix-mcp-runtime",
        jwks_url="https://identity.example.invalid/.well-known/jwks.json",
        jwks_allowed_hosts=("identity.example.invalid",),
        trusted_proxy_cidrs=("127.0.0.1/32",),
        algorithm="RS256",
        tenant_claim="tenant_id",
    )
)

transport = StreamableHTTPTransport(
    config=StreamableHTTPConfig(),
    limits=StreamableHTTPLimits(),
    context_provider=identity,
    telemetry=my_protocol_telemetry,
)
```

The approved fixed algorithms are `RS256`, `ES256`, and `EdDSA`. Choose exactly
one per provider. The verifier never accepts the token header as the algorithm
policy and rejects symmetric algorithms.

## Trust hierarchy and contract

Authentication happens before MCP body parsing and before a tool or ADK session
is opened:

1. The direct ASGI peer address must belong to `trusted_proxy_cidrs`.
2. Exactly one bounded `Authorization: Bearer ...` value is required.
3. The fixed algorithm, signature, issuer, audience, `kid`, and required claims
   are verified against the configured JWKS.
4. Token time invariants and maximum lifetime are checked with the configured
   skew.
5. Forwarded attribution must be absent or agree with verified authority.
6. The resulting frozen `CallContext` is the only authority passed downstream.
7. Any `tesserix/runtime/*` or `tesserix/adk/*` MCP authority metadata that is
   present must equal that context or the tool call fails before invocation.

### Required token claims

| Claim | Contract |
|---|---|
| `iss` | Exact configured HTTPS issuer |
| `aud` | One string equal to the exact configured runtime audience; arrays are rejected |
| `sub` | Non-empty visible text, at most 512 characters |
| configured tenant claim | One non-empty canonical tenant, at most 256 characters |
| `iat`, `nbf`, `exp` | Finite numeric dates inside the clock and lifetime policy |
| `kid` header | Non-empty visible key ID, at most 128 characters |

`scope` or `scp` may be a space-separated string or a string list. If both are
present, they must describe the same set. The result is deduplicated by
rejection, sorted, and limited to 64 entries of at most 256 characters each.
The default maximum token lifetime is one hour and the default clock skew is 30
seconds. The configured tenant claim must be independent from standard
identity, authority, time, scope, actor, client, run, and token-ID claims; for
example, it cannot alias `sub`.

### Forwarded attribution

| Input | Behavior after token verification |
|---|---|
| `x-jwt-claim-sub` | Optional; must equal `sub` |
| `x-jwt-claim-tenant-id` | Optional; must equal the canonical tenant claim |
| `x-jwt-claim-scope` | Optional; its normalized scope set must agree |
| `x-tesserix-run-id` | Must equal token `run_id`; supplies it only when the token omits it |
| `x-request-id` | Optional bounded correlation ID; never identity |
| `traceparent`, `tracestate` | Optional trace attribution from the trusted path |
| `Idempotency-Key` | Optional bounded mutation replay key; never identity or authorization |
| `X-Tesserix-Approval-Id` | Optional bounded approval lookup reference; never approval by itself |
| `X-Tesserix-Timeout-Ms` | Optional positive decimal caller budget; may shorten but never extend the 30-second gateway maximum |

If neither the token nor the trusted gateway supplies a run ID, the request ID
is used. Duplicate identity, attribution, or call-control headers fail closed.
Timeout values that are empty, zero, non-decimal, non-ASCII, leading-zero, or
longer than nine digits also fail closed. Values from tool arguments are never
inspected as identity.

Malformed optional trace context does not change verified identity or reject a
tool call. It is discarded, the observation adapter starts a safe local trace,
and only the stable `malformed_trace_context` reason is emitted. The supplied
header value is never echoed into logs, spans, metrics, or errors.

MCP metadata with the prefixes `tesserix/runtime/` and `tesserix/adk/` is never
promoted to authority. Matching values are tolerated for compatibility;
mismatched tenant, subject, run, scopes, trace, idempotency, or approval
metadata returns the stable `authority_mismatch` code with only the safe
request ID. The concrete [tool policy](tool-policy.md) validates the exact
approval record and requires idempotency for mutating tools.

## JWKS retrieval, caching, and rotation

The default envelope is deliberately finite:

| Policy | Default |
|---|---:|
| JWKS request timeout | 2 seconds |
| Serialized JWKS maximum | 65,536 bytes |
| Keys per JWKS | 32 |
| Fresh cache window | 900 seconds |
| Maximum stale known-key window | 3,600 seconds |
| Failed-refresh backoff | 5 seconds |

The fetcher accepts only the configured HTTPS URL on the default HTTPS port.
Credentials, IP-literal hosts, query strings, fragments, redirects, environment
proxies, non-JSON responses, duplicate `kid` values, wrong-use keys, and
malformed or over-limit documents are rejected.

Fresh known keys verify locally. An unknown `kid` forces one single-flight
refresh even while the cache is fresh. A successful refresh atomically replaces
the keyset, so removed keys stop working. During a fetch failure, only an
already-known key may be used, and only until the maximum stale age. An unknown
key, an empty cache, or an expired stale cache always fails closed. Backoff
prevents an identity outage or attacker-selected unknown key from creating a
refresh flood.

The stale policy trades bounded availability for delayed signing-key revocation:
if the issuer removes a compromised key while JWKS is unreachable, that cached
key can remain usable for at most the stale window, while token time checks
still apply. Set a shorter stale window where the issuer's emergency-revocation
objective requires it.

## Failure behavior

Every authentication failure returns HTTP 401 before MCP parsing. If a bounded
request ID was obtained from the trusted path it is returned; otherwise a
generated value is used. The response never contains the token, claims, raw
`kid`, issuer or JWKS URL, upstream response, cryptographic detail, or exception
text. Cancellation still propagates instead of being converted to 401.

The provider has no retry beyond the next request after the five-second
backoff. A JWKS timeout does not mutate external state, and concurrent misses
share one fetch. There is no datastore, background refresh task, credential
cache, or cross-process cache to recover after a crash.

## Network controls and residual risk

Application validation prevents token-controlled JWKS destinations and obvious
URL abuse. It does not pin resolved IP addresses. DNS rebinding, a compromised
allowlisted identity host, or a cluster-wide trusted CIDR can bypass an
application-only assumption. Production must therefore apply matching DNS and
egress policy, block private, loopback, link-local, and metadata destinations,
and restrict runtime ingress to the intended Gateway workload identity.

## Rollout and rollback

Roll out with the route inactive, inject the exact issuer, audience, tenant
claim, host allowlist, and narrow proxy CIDRs, then run valid, expired,
wrong-audience, cross-tenant, rotation, and JWKS-outage probes. Activate only
after NetworkPolicy and mesh source containment are observed. Monitor generic
401 rate and JWKS refresh failures without logging tokens or claims. Issue #16
owns the payload-free runtime counters; do not claim refresh observability until
that sink is wired. Gateway HTTP status logs remain the interim rejection
signal.

Rollback drains the instance and restores the previous immutable image and
verified identity configuration. If the previous image did not independently
verify runtime-audience tokens, keep the public route inactive instead of
falling back to forwarded-header trust. No schema, Registry record, token, or
durable cache requires migration or compensation.

## Verification

Run the identity and transport security suites without external network:

```bash
uv run --frozen pytest -q -o addopts='' tests/security/test_gateway_identity.py
uv run --frozen pytest -q -o addopts='' tests/protocol/test_streamable_http.py
```

See [ADR-0010](adr/0010-gateway-jwt-and-tenant-context.md) for the decision,
alternatives, quantitative reasoning, residual risks, and dependency cost.
