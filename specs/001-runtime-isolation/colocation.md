# Colocation Policy

**Spec:** [`spec.md`](spec.md)

When agents **must** share RAM (same-role pool, hot cache, coordination queue),
runtime allows it only inside an explicit **colocation group**. Storage
containment in `hyperbus-core` is unchanged.

## Policy file

```yaml
tenant_id: acme
colocation_policy:
  default_profile: isolate

workers:
  - id: support-primary
    agent_id: support-bot
    regions: [support, hyperbus-meta]
    profile: pool
    colocate_group: support-pool

  - id: support-fallback
    agent_id: support-bot
    regions: [support, hyperbus-meta]
    profile: pool
    colocate_group: support-pool

  - id: billing-bot
    agent_id: billing-bot
    regions: [billing, hyperbus-meta]
    profile: isolate
    colocate_group: billing-solo

  groups:
    support-pool:
      max_workers: 4
      shared_ram: true
      trust: same_agent_id   # only identical agent_id + grant set
    billing-solo:
      shared_ram: false
```

## Rules

1. **`isolate` (default):** one `agent_id` per process; no `shared.namespace()`.
2. **`pool`:** workers with the same `colocate_group` may share RAM via
   `hyperbus_runtime.shared.namespace(group_name)`.
3. **`cohost`:** same container, separate PIDs; optional `/dev/shm/hb-{tenant}-{group}/`.
4. **`inline`:** same Python process; maximum sharing, minimum boundary — same trust only.
5. **Cross-group:** denied unless `allow_ram_share_with: [other-group]` is set
   and an audit event is emitted with `approved_by`.

## What shared RAM must not hold

| Data | Shared RAM | Use instead |
|---|---|---|
| Billing invoice bytes | No (in support pool) | HyperBus region `billing` |
| Cross-region PII | No | Routed channels + region keys |
| Same-role ticket cache | Yes (within support-pool) | `shared.namespace("support-pool")` |
| Job queue between support replicas | Yes | RAM or Redis scoped to group |

## Residual risk statement

> Agents in the same colocation group can read each other's in-process state.
> HyperBus still denies cross-region **stored** memory via engine grants.

Publish this in deployment docs and audit logs when groups are formed.

## API

```python
from hyperbus_runtime import worker, shared

worker.bind_from_env()  # HB_TENANT_ID, HB_AGENT_ID, optional HB_COLOCATION_POLICY

cache = shared.namespace()  # bound to worker's colocate_group; cross-group requires policy
cache["active_tickets"] = {...}

checkpointer = worker.checkpointer()  # always via engine RPC (or perf in-process)
```

## Audit events

| Event | When |
|---|---|
| `colocation.group.join` | Worker starts in a group |
| `colocation.ram.shared` | `shared_ram: true` active |
| `colocation.policy.override` | `allow_ram_share_with` used |

Emitted through core `AuditSink` on the engine host when configured.
