# ADR-0013: Redaction and connection-pinned egress

## Status

Accepted.

## Context

Tool handlers cross two high-risk boundaries: dependency data returns toward a
model-facing caller, and runtime requests leave the workload for product APIs.
A backing service can echo credentials or sensitive payloads. A tool argument,
redirect, DNS answer, alternate IP representation, or rebinding event can turn
an HTTP client into an SSRF path.

This package is a reusable library rather than a deployment, so request rate,
dependency latency, pod count, and availability SLO are not yet evidenced.
Issue #29 owns production load and soak evidence. This decision instead sets
non-bypassable per-process safety ceilings and a deterministic failure model.
Policy and redaction overhead excluding DNS and remote I/O should remain small
relative to the dependency call; no production p99 claim is made here.

The design must remain lightweight. It may reuse the existing HTTPX stack but
must not add a proxy service, policy datastore, queue, cache, or control-plane
dependency.

## Decision

### Final-boundary redaction

Define a runtime-checkable `RedactionPolicy` and built-in `SecretRedactor`.
The built-in policy removes configured exact values, structured credential
keys, authorization and token assignments, JWT shapes, and private-key blocks.
`SecretValue` renders redacted for ordinary string, format, and repr paths and
requires an explicit reveal at outbound use.

`Application` applies redaction after tool serialization and before returning
any success. It revalidates the redacted value against the same JSON and result
byte ceilings. Redaction failure maps to a stable internal failure; expansion
beyond the ceiling maps to `result_too_large`. Neither path returns the raw
result.

Application errors, protocol telemetry, and tool-policy audits redact their
string fields before a sink. Internal exception messages remain absent from the
public error and telemetry contracts. Outbound credential headers are
represented by `SecretValue`; exact credential bytes echoed by a dependency
are removed before its response is returned to handler code.

The same policy instance is injectable into every component. A replacement is
trusted only to make output safer; the runtime still owns JSON and byte bounds.

### Typed egress authority

Define immutable `EgressDestination` and `EgressManifest` contracts. A
destination is a canonical HTTPS host plus exact port. The manifest contains
at most 256 unique destinations and defaults to empty. Paths and query values
are not authority.

`DeclaredEgressPolicy` authorizes only manifest entries. Public IP space is the
default. Private or otherwise non-public space requires a separate, canonical,
operator-supplied CIDR policy; a registry manifest cannot grant it.

### Connection pinning

Provide `OutboundHTTPClient` over HTTPX and a directly declared HTTP Core
dependency. A custom HTTP Core network backend performs the security check at
the connection boundary:

1. Resolve the original manifest host immediately before connect.
2. Reject the complete DNS answer if any value is invalid, non-public, or an
   embedded internal IPv4 form.
3. Connect to one validated IP rather than resolving the host again.
4. Preserve the original host in the HTTP origin so TLS SNI, certificate
   verification, and Host remain correct.
5. Validate the network stream's actual peer and require it to equal the
   selected address before returning the stream to HTTP Core.

This makes resolution and connection one policy operation and removes the
preflight-DNS time-of-check/time-of-use gap. Missing peer metadata fails closed.
Unix-domain connections are denied. Custom TLS contexts must retain hostname
checking, required certificate verification, and a TLS 1.2 or newer minimum.

### URLs and redirects

Only canonical `https` URLs are accepted. Credentials, fragments,
secret-shaped query keys, malformed escapes, encoded authorities, and alternate
numeric IP representations are rejected. Each redirect is followed manually,
bounded, and checked as a new destination. Redirect bodies are not buffered.
Authorization, cookies, and secret-shaped headers are stripped on an origin
change, and a redirect location containing a released credential is denied.
Only seven reviewed application methods are accepted; `CONNECT`, `TRACE`, and
custom methods cannot turn an allowlisted dependency into a tunnel.

The adapter drives the guarded transport directly instead of using HTTPX's
stateful high-level client. It therefore has no shared cookie jar and does not
execute HTTPX's full-URL INFO request logger. Dependency `Set-Cookie` state is
never replayed into another tenant request.

### Limits and failure model

The client defaults to 256 KiB request bodies, 1 MiB responses, three
redirects, a ten-second whole-request timeout, 32 connections, 64 headers, and
32 KiB of headers. Hard maxima are 1 MiB request and response bodies, ten
redirects, 30 seconds, 256 connections, 128 headers, and 64 KiB of headers.
The caller's application deadline can end the operation earlier. The client
requests identity content encoding and rejects encoded responses before any
decompression step.

Every client failure uses `ErrorResponse`: stable code, fixed message, safe
request identifier, and retryability. Rejected hosts, IPs, URLs, response
bodies, dependency exception text, stack traces, versions, and SQL never enter
the response. The client itself does not retry. Runtime retries remain limited
to reads or verified idempotent mutations under the original deadline.

### Audit and deployment boundary

There is no payload logging. Optional egress audit contains only redacted
request identifier, method, destination digest, stable outcome, and status.
Sink failure is counted and nonfatal after a completed request.

Application policy is not a substitute for network isolation. Kubernetes,
mesh, firewall, and DNS policy must match the manifest before a route is
enabled. This deployment proof remains with issues #24 and #25.

## Dependency and failure analysis

- DNS unavailable or malformed: stable `unavailable`; no connection.
- DNS includes one forbidden value: stable `forbidden`; no connection.
- Connected peer differs or lacks address metadata: close it before request
  bytes, then stable `forbidden`.
- Remote timeout: stable `timeout` under the earlier runtime deadline.
- Oversized response: close stream and return `result_too_large`.
- Redaction policy raises or returns an unusual value: fail closed with a safe
  internal diagnostic.
- Audit sink fails: count the failure; do not repeat completed remote work.
- Mesh policy is unavailable or stricter: connection fails as `unavailable`;
  application policy never relaxes it.

The only dependency graph change is making already-installed HTTP Core a
direct runtime dependency because the adapter intentionally uses its public
network-backend contract. No state, migration, cache invalidation, distributed
transaction, or recovery workflow is introduced.

## Alternatives considered

### Let each tool create HTTPX clients

Rejected. Destination policy, proxy behavior, redirects, DNS validation,
limits, errors, and audit would diverge and be difficult to prove.

### Validate DNS before calling a normal HTTP client

Rejected. The client could resolve again after validation, leaving DNS
rebinding and alternate-answer races. It also would not validate the actual
peer before request bytes.

### Rely only on gateway or mesh egress policy

Rejected as a sole control. Those layers are required defense in depth but do
not provide typed per-tool intent, safe response errors, or local testability.

### Disable all redirects and IP destinations

Rejected as the only model. Bounded redirects and canonical public IPs can be
safe when every hop and peer is revalidated. Operators may set redirects to
zero and publish no IP destinations where product policy is stricter.

### Run a separate egress proxy or redaction service

Rejected for the foundation. It adds availability, latency, tenancy, cost,
deployment, and incident boundaries without removing the need for local final
result checks.

## Security and residual risk

The policy blocks direct private, loopback, link-local, metadata, multicast,
reserved, unspecified, mapped IPv4, 6to4, and NAT64-embedded internal targets.
A compromised allowlisted public service can still proxy a request or return
malicious but schema-valid data. Backing APIs must independently authorize
tenant objects, and output schemas plus redaction remain mandatory.

Pattern redaction cannot discover every unknown unlabelled secret. Credentials
must use `SecretValue`, manifests and schemas must reject secret material, and
trusted handler code must not explicitly reveal secrets into results or side
channels. Opaque bounded request bodies are not DLP-scanned and must never
carry revealed credentials. Incident response must rotate any potentially
exposed credential.

A process-wide union of tool destinations would weaken least privilege even
though every destination remained valid. Composition must bind a client to one
tool manifest or an identical reviewed authority set. Third-party HTTP Core
DEBUG logging is also outside the redacted audit contract and must remain
disabled under the production logger policy owned by issue #16.

## Verification

Unit and property tests use no real network by default. They cover structured
redaction ceilings, exact canaries, stable errors, manifest authority, public
and non-public address classes, mixed DNS answers, connected-peer changes,
redirects, header stripping, response bounds, and payload-free audit.

`security/ssrf_harness.py` runs separately on an isolated loopback TLS server
with an ephemeral certificate. It proves explicit IPv4 and IPv6 internal policy
and denies metadata redirects, private redirects, DNS rebinding,
credential-bearing URLs, encoded hosts, and alternate IP forms. The security
CI workflow runs this harness.

The clean rebuilt wheel is 83,880 bytes, or 85.3% of ADR-0012's 96 KiB hard
ceiling. This decision does not raise the package budget.

## Rollout

1. Publish the additive runtime contracts and adapter.
2. Start each tool with an empty egress manifest.
3. Add reviewed exact destinations and configure one shared redactor.
4. Align mesh, DNS, and workload network policy.
5. Run unit, threat-model, compatibility, and isolated SSRF gates.
6. Enable routes gradually and observe only bounded error/audit signals.

## Rollback

Deploy the previous wheel or revert this decision. There is no persisted state
or migration. Disable affected tool routes before rollback unless equivalent
gateway and network controls are independently proven, because the previous
runtime lacks these final redaction and connection-pinning controls.

## Consequences

Tools reuse one secure client rather than reimplementing HTTP behavior. Policy,
redaction, audit, and resolver contracts remain independently replaceable and
testable. The cost is an explicit manifest, one DNS lookup per new connection,
response buffering up to the finite ceiling, and deliberate coupling to HTTP
Core's public network backend in the adapter layer.
