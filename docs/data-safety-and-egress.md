# Data safety and outbound HTTP

The runtime has two independent, replaceable security policies:

- `RedactionPolicy` removes known credentials and supported secret shapes at
  result, error, telemetry, protocol, and policy-audit boundaries.
- `EgressPolicy` authorizes exact HTTPS destinations from an immutable
  `EgressManifest` and validates DNS and the connected peer.

Neither policy accepts model arguments as configuration. A tool request can
select a path or safe query value under an already declared authority, but it
cannot add a host, port, scheme, internal network, redirect exception, or
redaction exception.

## Compose one redaction policy

Use `SecretValue` for credential-bearing values. Ordinary string conversion,
formatting, and representation return `[REDACTED]`; `reveal()` is intentionally
explicit and should occur only in the outbound adapter.

```python
from tesserix_mcp_runtime import SecretRedactor, SecretValue

api_key = SecretValue("replace-with-secret-manager-value")
redactor = SecretRedactor(known_secrets=(api_key,))
```

Pass the same policy to `Application`, `ToolPolicy`,
`StreamableHTTPTransport`, and `OutboundHTTPClient`. The default application
policy still redacts supported secret-shaped fields, JWTs, private keys, and
authorization assignments, but exact configured values are needed to remove a
bare credential from otherwise unlabelled text.

The built-in policy is bounded to 64 levels, 65,536 JSON nodes, and 1 MiB of
text. Operators may lower these values but cannot raise the hard maxima. It
clones structured results instead of mutating handler-owned values. A custom
policy that raises, returns an unusual value, or expands beyond the runtime
result ceiling produces a stable internal or `result_too_large` failure; the
unredacted result is never returned.

Error responses retain only stable code, message, request identifier, and
retryability. Internal exception messages, response bodies, URLs, hosts,
dependency versions, stack traces, and SQL fragments are not part of the
client contract. Exception type and request identifiers are redacted before
telemetry.

Secret-pattern matching is defense in depth, not a secret-discovery system.
Unknown unlabelled secrets cannot be detected reliably. Keep credentials in
`SecretValue`, reject secret fields in manifests and tool schemas, and never
call `reveal()` in a serializer, exception, log, metric, trace, audit field,
process argument, or URL.

## Declare exact destinations

The egress manifest contains HTTPS authorities only. Paths and query values
are request data and do not extend authority.

```python
from tesserix_mcp_runtime import (
    DeclaredEgressPolicy,
    EgressDestination,
    EgressManifest,
)
from tesserix_mcp_runtime.adapters.outbound_http import OutboundHTTPClient

manifest = EgressManifest(destinations=(EgressDestination(host="orders.api.example", port=443),))
policy = DeclaredEgressPolicy(manifest=manifest)
client = OutboundHTTPClient(policy=policy, redactor=redactor)
```

Issue #18 owns registry manifest generation. It must populate this exact typed
contract after schema validation; it must not synthesize destinations from a
tool argument or arbitrary URL. The empty manifest is default deny. Compose a
client per tool manifest (or only for tools with an identical reviewed
authority set); never create a process-wide union that lets one tool borrow
another tool's network capability.

An internal destination needs a separate operator policy:

```python
policy = DeclaredEgressPolicy(
    manifest=manifest,
    permitted_internal_networks=("10.24.8.0/24",),
)
```

Publishing a destination does not grant an internal CIDR. Internal ranges are
an operator-owned deployment decision and must also be enforced by Kubernetes,
mesh, firewall, and DNS policy.

## Connection-time enforcement

For every new TCP connection, the provided client:

1. Parses a canonical HTTPS URL and rejects user information, fragments,
   secret-shaped query keys, malformed escapes, encoded authorities, and
   alternate numeric IP forms.
2. Requires the exact canonical host and effective port in `EgressManifest`.
3. Resolves DNS immediately before connect and rejects the whole answer if any
   address is private, loopback, link-local, metadata, multicast, reserved,
   unspecified, IPv4-mapped, 6to4, or NAT64-embedded internal space.
4. Connects to the selected validated IP, while retaining the original host
   for TLS SNI, certificate verification, and the HTTP Host header.
5. Reads the actual connected peer from the network stream and rejects and
   closes it before sending request bytes if it differs or is no longer
   authorized.
6. Repeats destination and connection checks for every redirect. Cross-origin
   redirects never receive authorization, cookie, or secret-shaped headers,
   and a redirect cannot move a released `SecretValue` into its URL.

TLS hostname and certificate verification are mandatory. A custom trust
context must require certificates, enable hostname checking, and set TLS 1.2
or newer as its minimum; an unverified context is rejected at composition.

Known protected values are rejected in URLs and ordinary header names or
values before DNS. A `SecretValue` header is the explicit credential-release
path. Request bodies remain opaque bounded bytes and are not a DLP boundary;
never reveal or serialize credentials into them.

The client does not use environment proxy variables. Unix sockets are denied.
It accepts only `GET`, `HEAD`, `OPTIONS`, `POST`, `PUT`, `PATCH`, and `DELETE`;
`CONNECT`, `TRACE`, and custom tunnelling methods are denied. It drives the
guarded transport without HTTPX's stateful cookie jar or request logger, so a
dependency cookie cannot cross tenant calls and enabling dependency INFO logs
cannot expose full URLs. It has no automatic retry; the outer runtime may retry
only a read or verified idempotent mutation under the original deadline.

## Finite HTTP envelope

Defaults and hard maxima are:

| Limit | Default | Hard maximum |
|---|---:|---:|
| Request body | 256 KiB | 1 MiB |
| Response body | 1 MiB | 1 MiB |
| Redirects | 3 | 10 |
| Whole request timeout | 10 seconds | 30 seconds |
| Connections | 32 | 256 |
| Headers | 64 | 128 |
| Header bytes | 32 KiB | 64 KiB |

The outer `Application` deadline remains authoritative and can cancel an
outbound request earlier. Response content length and streamed bytes are both
checked. The client requests identity encoding and rejects encoded responses
before decompression, removing decompression-bomb expansion from this boundary.
Redirect bodies are not buffered. Credential values supplied as
`SecretValue` headers are also removed if a backing service echoes them in a
response header or body.

## Audit and logging

Payload logging is absent by default. An explicitly configured
`OutboundHTTPAuditSink` receives only:

- redacted request identifier;
- HTTP method;
- SHA-256 destination fingerprint;
- stable outcome;
- final status code.

It never receives URL, query, host, headers, credentials, request body, or
response body. Audit-sink failure is counted and does not turn a completed
dependency request into a duplicate-prone retry.

Keep third-party `httpcore` DEBUG logging disabled in production. It is not the
runtime audit contract and may include dependency response headers. Issue #16
owns enforcement of the production logger and telemetry allowlist.

## Verification

The default pytest suite uses a scripted network backend and does not open
sockets. It covers exact authorities, mixed DNS answers, connected-peer
replacement, redirects, secret forwarding, error shape, limits, and canaries.

Run the separate loopback-only TLS harness for connection evidence:

```console
uv run --frozen python security/ssrf_harness.py
```

The harness generates an ephemeral self-signed certificate in a private
temporary directory and proves explicit IPv4 and IPv6 internal access plus
metadata-redirect, private-redirect, DNS-rebinding, credential-bearing URL,
encoded-host, and alternate-IP denial. It never contacts an external service.

## Rollout and rollback

Roll out with an empty manifest, then add reviewed destinations one tool at a
time. Observe stable `forbidden`, `timeout`, `unavailable`, and
`result_too_large` outcomes without enabling payload logs. Validate matching
mesh and DNS restrictions before route activation.

Rollback by deploying the previous wheel or reverting the change. No data
migration or external service is involved. Rolling back removes application
SSRF pinning and final result redaction, so it is safe only while the affected
tool routes are disabled or an equivalent gateway and network boundary is
proven.
