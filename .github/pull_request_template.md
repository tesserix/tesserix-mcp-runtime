## Outcome

Describe the user-visible or operational outcome and link the issue with
`Closes #NUMBER`.

## Evidence

Include the red test, green test, and every command actually run. Attach only
sanitized output; never include credentials, tokens, tenant payloads, or
production data.

- [ ] Tests: new behavior and failure paths are covered; the affected full suite passed.
- [ ] Security: trust boundaries, authorization, inputs, dependencies, and secret handling were reviewed.
- [ ] Rollout: deployment order, monitoring, and success criteria are stated, or no rollout is required.
- [ ] Rollback: a concrete reversal path is stated and any irreversible step is called out.
- [ ] Compatibility: supported Python, MCP, ADK, Registry, and Gateway impacts are recorded.

## Risk and operations

State failure behavior, observability impact, cost impact, and any assumption
that remains unverified.
