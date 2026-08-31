# Gateway reconciliation decision

The measured representative sandbox replay in
[`reconciliation-observations.json`](../benchmarks/reconciliation-observations.json)
meets the 120-second activation target at the 36-month 500-route volume: 30s
polling produced 60s p99 activation and 0.33 Registry RPS, with no missed
schedules. Therefore polling remains the selected design. There is no
speculative event controller in this repository.

Registry remains desired-state owner and Kubernetes remains reconciled state.
Polling is idempotent, digest/generation verified, retains last-known-good
routes, and is repaired by a complete snapshot rather than an incremental
partial read.

## When to reconsider

Reconsider only after production or equivalent sandbox evidence shows either
activation p99 above 120 seconds, sustained Registry/Kubernetes load beyond
the reviewed 500-route plan, repeated missed schedules, or operational toil
that cannot be reduced by interval/ETag tuning. Compare tuned polling,
generation/ETag polling, webhook trigger plus periodic repair, and a
long-running controller against the same route count and activation budget.

## Event design constraints

If evidence justifies an event supplement, the Registry transaction writes an
outbox record with the desired-state generation and immutable digest. Delivery
is at-least-once; the consumer is idempotent by route identity/generation and
does not let out of order delivery make an older generation win. It retains a
bounded replay cursor, sends exhausted records to a dead letter path, alerts on
backlog/freshness, and always runs periodic full reconciliation. Event loss,
consumer restart, Registry outage, and controller downtime preserve existing
routes and recover from the full snapshot.

Webhook/event processing never publishes from a runtime pod and never becomes
the sole repair mechanism. A Registry outage serves last-known-good routes;
new activation waits or publishes fail visibly. Rollback from any future event
supplement is one GitOps change:

```sh
git revert --no-edit <event-reconciler-change>
```

Argo CD then restores the current polling CronJob and its exact immutable
image. A non-production game day must replay duplicates, gaps, reordering,
restart, full resync, and rollback before any event path receives traffic.
