# ADR-0030: Retain polling reconciliation baseline

- Status: Accepted
- Date: 2026-08-31
- Tracking: [tesserix-mcp-runtime#34](https://github.com/tesserix/tesserix-mcp-runtime/issues/34)

At 500 routes, 30-second polling has 60-second representative-sandbox p99
activation, 0.33 Registry RPS, and no missed schedules, under the 120-second
activation SLO. Retain the idempotent polling baseline. Events add an outbox,
at-least-once delivery, deduplication, ordering, replay, dead letter, state,
and recovery path without demonstrated benefit. Any later event supplement
must retain periodic full reconciliation, preserve Registry desired-state
ownership, and roll back through one GitOps revert.
