# Adversarial security verification

`tesserix-mcp-testkit` provides a reusable security contract for MCP packages,
images, registries, gateways, and runtimes. It complements the functional
conformance contract: conformance proves supported behavior, while this suite
proves untrusted identities, tenants, destinations, artifacts, and workflow
paths are denied without effects or disclosures.

The default package tests are offline. The release journey separately exercises
the built image behind the pinned Agentic Registry and AgentGateway components.
No production token, customer payload, tenant record, kubeconfig, or live cloud
authority belongs in either lane.

## Contract 1.0 matrix

Contract 1.0 contains 51 required cases and scans 12 named sinks.

| Area | Cases | Required evidence | What must hold |
|---|---:|---|---|
| Tenancy | 9 | Black box | Another tenant gets no artifact, route, result, cache hint, count, or existence signal |
| Identity | 9 | Black box | Malformed, expired, forged, wrong-claim, revoked, and unknown outage identities fail before effects; cached known keys follow bounded policy |
| Authority | 6 | Black box | Headers, claims, scopes, approvals, confirms, and replays cannot add authority or duplicate effects |
| Egress | 8 | Isolated network | Redirect, encoded/IPv6/private/metadata/loopback/rebinding/alternate-port targets fail before connection |
| Redaction | 12 | Artifact or black box | The configured canary is absent from every named sink |
| Control plane | 3 | Black box | Forged, unsigned, or under-scoped route state cannot activate traffic |
| CI and dependencies | 4 | Static | Actions are immutable, permissions are least privilege, pull requests are contained, and release policy is enforced |

The public constants are `SECURITY_CONTRACT_VERSION`, `SECURITY_CASES`, and
`REQUIRED_SECURITY_SURFACES`. Each case declares its exact
`SecurityEvidenceKind`; a producer cannot substitute a static assertion for a
required black-box or isolated-network observation.

## Record a case without retaining its payload

Use the result factory at the observation boundary. Pass only a synthetic,
bounded, non-secret projection such as status, effect count, and disclosure
count. The factory scans the bytes, stores their SHA-256 digest, and discards
the observation.

```python
from tesserix_mcp_testkit import SecurityEvidenceKind, make_security_result

result = make_security_result(
    case_id="identity.malformed",
    evidence_kind=SecurityEvidenceKind.BLACK_BOX,
    evidence=b'{"disclosures":0,"status":401,"tool_effects":0}',
    passed=True,
    request_id="request-malformed-token",
    canaries=("SyntheticProjectCanary8Kq3",),
)
```

Black-box and isolated-network results require a bounded request ID. Artifact
and static cases may omit it. Empty, oversized, unknown, wrong-mode, canary, or
secret-shaped evidence raises `SecurityReportError`; no partial result is
returned.

## Scan every named sink

Supply exactly one value for every `SecuritySurface`. The scanner requires the
complete set, rejects secret material, and returns only sink names, digests,
and sizes.

```python
from tesserix_mcp_testkit import (
    REQUIRED_SECURITY_SURFACES,
    scan_security_surfaces,
)

surface_evidence = scan_security_surfaces(
    {surface: captured_sinks[surface] for surface in REQUIRED_SECURITY_SURFACES},
    canaries=("SyntheticProjectCanary8Kq3",),
)
```

The required sinks are manifest, semantic annotations, schema, errors, results,
logs, traces, metrics, audit, crash dump, SBOM, and release assets. When a new
sink can retain runtime or release data, add it to the contract and its
conformance capture in the same reviewed change. Do not hide it inside an
existing aggregate merely to keep the set unchanged.

## Assemble release evidence

`SecuritySubject` binds the exact source revision and package, image, manifest,
and SBOM digests. `SecurityReport` additionally binds the runtime, Registry,
and Gateway component revisions, all case results, all surfaces, findings, and
the preparer. `to_json()` emits sorted canonical JSON with a trailing newline.

A valid report must contain every required case exactly once. Each redaction
case must reference the exact digest returned for its named sink, and the
runtime component revision must equal `SecuritySubject.image_digest`. Unknown,
missing, duplicate, or mismatched identities fail closed.

The report never includes raw observations, JWTs, authorization headers,
private keys, request bodies, tool payloads, or customer data. Archive the
sanitized inputs used to reproduce the run only where the release journey
already permits them and rescan the entire retained artifact directory before
upload.

## Findings and retests

A failed result must have one `SecurityFinding` with:

- the same case ID and contract severity;
- a stable `SEC-NNNN` finding ID;
- a bounded accountable owner;
- concrete remediation;
- `open` disposition with no retest digest, or `remediated` with the exact
  retest digest.

An open finding blocks serialization. Recording remediation does not turn a
failed required case into release evidence: rerun the case, set the result to
passed only when the public boundary succeeds, and bind the finding's
`retest_digest` to that successful result. The report rejects stale or
different retest evidence.

## Independent GA review

Nightly and release-candidate runs may emit `review: null`. Before GA, an
independent reviewer examines the exact report scope, component pins, retained
sanitized artifacts, findings, and run logs. Attach a `SecurityReview` whose:

- reviewer differs from `prepared_by`;
- approval is true;
- timestamp is not earlier than `created_at`; and
- `scope_digest` equals `report.review_scope_digest()`.

Serialize the reviewed object with
`report.to_json(require_independent_review=True)`. Any changed subject,
component, result, surface, or finding changes the scope digest and invalidates
the review. A self-review, denial, stale timestamp, or copied digest fails
closed.

## Real release journey

The reusable `.github/workflows/release-journey.yml` lane builds the core and
journey images, builds the pinned Registry commit, pulls AgentGateway by digest,
and runs the black-box matrix through public HTTP and MCP interfaces. It also
runs the host-isolated SSRF and CI/dependency checks and writes
`artifacts/journey/security-evidence.json`.

During a verifier dependency outage, the fake identity service keeps the same
synthetic signing key but returns 503 from token and JWKS endpoints. This proves
an already-known key follows the bounded cached-verification policy and an
unknown key fails closed, without accidentally mixing key rotation or changed
ephemeral host ports into the observation.

The route-scope case uses the pinned Registry's own `requireServerScope`
export. An otherwise valid Backend and HTTPRoute without their expected
`AgentgatewayPolicy` cannot produce an activation configuration. The scoped
export must target that exact HTTPRoute and require
`mcp:<tenant>:<server>` as an exact key in the Zitadel roles-map claim; the live
Gateway then rejects a correctly signed tenant token carrying only a lookalike
route scope before a subsequent exactly scoped health probe succeeds.

Run the offline affected tests with:

```bash
uv run --frozen pytest
uv run --frozen python security/check_ci_attack_paths.py
uv run --frozen python security/ssrf_harness.py
```

The real journey needs Docker, checksum-verified Compose, the pinned Registry
source, and the digest-pinned Gateway image. Prefer the reusable workflow so
those inputs and the evidence retention policy stay identical to release CI.
Local runs must use synthetic state and a disposable output directory.

## Compatibility and versioning

`SECURITY_CONTRACT_VERSION` uses `major.minor` independently of the package
version. Adding optional helper behavior is compatible. Adding a required case
or sink, removing or renaming one, changing a case's expectation/severity/mode,
or weakening report acceptance requires a major contract review. A downstream
repository should pin a compatible testkit version and record the exact
contract version with its evidence.

The built runtime currently proves Python 3.14 and MCP SDK 2.1.1; the separate
client compatibility lane includes 1.28.1. MCP SDK 1.34 does not exist in the
checked or authoritative dependency evidence and must not be claimed. Python
3.14 and an MCP SDK version are separate compatibility dimensions.

See [ADR-0025](adr/0025-adversarial-security-evidence.md) for the decision,
threat model, evidence policy, cost, rollout, and rollback.
