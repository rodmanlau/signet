# Scale

Stay on one Signet machine and one Managed Postgres Basic cluster while every condition below is still true. Read this when a measurement or a complaint says one machine is no longer enough. Do not add a second machine, a larger Postgres plan, or Redis before a trigger in this guide fires.

## Stay on one machine

Stay while all of these hold.

- Proof traffic stays under about 10 requests per second, sustained.
- Postgres CPU stays under 50%, and the `pg` pool is not waiting for a connection.
- p50 of `POST /agent-proof` stays under 100ms after warmup.
- Losing an in-flight Allow ticket on deploy is acceptable. The person opens Allow again.
- One region, `iad`, meets the product need.

Under 1 proof per second, stay on one machine. That rate is not a reason to add a machine.

`fly.toml` sets `min_machines_running` to 1. A deploy restarts that machine. The deploy does not start a second machine.

## Triggers

Check these weekly, or when an alert fires. When a trigger fires, do its action. This page names the action. It does not add Redis, a grant cache, or another region.

| Id | Trigger | Action |
| --- | --- | --- |
| T1 | You need more than one Signet process. That includes high availability, or a rolling deploy that must not drop Allow tickets held on one machine. | Run two or more Signet machines only after the Postgres cutover. A later program puts Allow tickets in Redis and removes reliance on the JSON volume. |
| T2 | The `pg` pool waits, Postgres reports connection errors under load, or client connections sit near the plan cap. Basic lists 200 client connections. | Raise the pool carefully, then upgrade the Managed Postgres plan. Do not add Signet machines first. |
| T3 | p50 latency of `POST /agent-proof` stays over 100ms, or p99 stays over 300ms, for 15 minutes, and CPU is the limiter. | Find what limits the request before you scale. Fix an index or a query first. Then scale Postgres vertically. |
| T4 | People report that deploys drop in-flight Allow tickets more than rarely. | A later program moves tickets to Redis with a TTL of 600 seconds. Grants stay in Postgres. |
| T5 | Grant lookups dominate Postgres CPU, and p50 or p99 still misses the T3 limits. | A later program adds a Redis cache or an in-process cache in front of grants. Invalidate that cache on Allow and on Revoke. Postgres stays the source of truth. |
| T6 | Another region is required for latency or for residency. | Start a separate program. Do not add a region in this deploy. |

The `pg` pool in this process uses at most 10 connections. That limit is `max` in `createPgPool`. A wait on those connections is T2. It is not a reason to add a second machine.

## Read the signals

### Process count

```text
fly status --app signet
fly machines list --app signet
```

Count machines in state `started`. One started machine is the stay state. More than one started machine means T1 already happened, or a deploy left an extra machine up. Do not leave a second machine up to chase a rate under 1 proof per second.

### Proof rate and unauthorized proofs

`GET /metrics` returns plain text for this process since it started. Each metric is one line.

```text
signet_agent_proof_total 12
signet_agent_proof_unauthorized_total 3
```

`signet_agent_proof_total` counts completed `POST /agent-proof` responses with status 200. `signet_agent_proof_unauthorized_total` counts status 403 when the body error is `unauthorized`. Signet does not count other statuses.

On the public host, read the counters from the app.

```text
curl -sS https://signet.fly.dev/metrics
```

Read the URL twice. Subtract the first `signet_agent_proof_total` from the second. Do the same for `signet_agent_proof_unauthorized_total`. Add those two differences and divide by the seconds between the reads. The result is a lower bound on proof traffic. Compare it with about 10 requests per second, and with 1 proof per second. The counters reset when the process restarts.

### Pool wait and connection errors

`GET /metrics` does not report pool wait. Read Postgres and Fly instead.

The Fly dashboard for the Managed Postgres cluster shows CPU and client connections. CPU under 50% and connections far from 200 are the stay state. Basic lists 200 client connections.

The Signet process writes `postgres pool error:` to stderr when the `pg` pool emits an error.

```text
fly logs --app signet
```

Proofs that stall while Postgres CPU is low, together with connection errors or that stderr line, are T2. Filling the 10 pool connections is a pool problem. Add capacity on Postgres before you add a Signet machine.

### Latency

`GET /metrics` does not record duration. After warmup, time `POST /agent-proof` for a key that already has a grant. p50 under 100ms is the stay state. p50 over 100ms, or p99 over 300ms, for 15 minutes, with CPU as the limiter, is T3.

Fly HTTP metrics for app `signet` are the other view of request duration. Use those when you are not sampling the route yourself.

### Allow tickets

There is no ticket counter. A person who had to open Allow again after a deploy is the signal. Rare loss is acceptable, and it is not T4. Loss that people report more than rarely is T4.

Tickets live in memory on the one machine. A restart drops tickets that were not Allowed yet. Grants in Postgres are not dropped by that restart.

### Grant lookups

Each `POST /agent-proof` calls `isGranted` on the grant map loaded at startup. That call does not query Postgres. Postgres CPU on the current process is not grant-lookup traffic.

T5 applies when grant checks hit Postgres, that work dominates Postgres CPU, and p50 is still over 100ms or p99 is still over 300ms. Until then, do not add a grant cache. `signet_agent_proof_total` still tells you how often proofs complete.

## Match a symptom to an action

| You see | Action |
| --- | --- |
| You need a second Signet machine for availability, or a deploy must keep in-flight Allow tickets. | T1. A later program puts Allow tickets in Redis and removes reliance on the JSON volume. Do not add the machine while tickets still live only in this process. |
| `postgres pool error:` in `fly logs --app signet`, proofs waiting on a connection, or client connections near 200. | T2. Raise the pool carefully, then upgrade the Managed Postgres plan. Do not add a Signet machine first. |
| p50 latency of `POST /agent-proof` over 100ms, or p99 over 300ms, for 15 minutes, and CPU is the limiter. | T3. Find the limiter. Fix the query or the index. Scale Postgres vertically after that. |
| People say deploys drop in-flight Allow tickets more than rarely. | T4. A later program moves tickets to Redis with a TTL of 600 seconds. Grants stay in Postgres. |
| Grant lookups dominate Postgres CPU, and latency still misses 100ms p50 or 300ms p99. | T5. A later program adds a cache in front of grants and invalidates it on Allow and on Revoke. |
| Another region is required for latency or for residency. | T6. Start a separate program. Do not add a region in this deploy. |
| Proof traffic is under 1 proof per second, or every stay condition still holds. | Stay on one Signet machine and one Managed Postgres Basic cluster. |
