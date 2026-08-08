# Perf profile — in-process engine (weaker containment)

**Spec:** [`spec.md`](spec.md) AC-6.3 / US-3.3

The default runtime path keeps Postgres credentials and `HyperBusEngine` in the
**engine sidecar**. Workers call storage through RPC so capability checks always
run on the engine host.

The **`perf` profile** opts into an **in-process** `HyperBusEngine` inside the
worker for lower latency. This is an explicit tradeoff:

| | Default (sidecar) | `perf` profile |
|---|---|---|
| Checkpoint latency | +0.05–1 ms RPC hop | In-process |
| Postgres credentials | Engine container only | **Worker holds `DATABASE_URL`** |
| Bypass risk | Worker lacks backend imports | Mis-packaged worker could import backend |
| Identity binding | `HB_AGENT_ID` still enforced | Same |

## Enable

```bash
export HB_ISOLATION_PROFILE=perf
export HB_TENANT_ID=acme
export HB_AGENT_ID=support-bot
export HB_DEFAULT_REGION=support
export HB_GRANTS_FILE=/etc/hyperbus/grants.yaml
export DATABASE_URL=postgresql://...
# No HYPERBUS_SOCKET / HYPERBUS_ENGINE_URL required
hyperbus-worker python /app/graph.py
```

## Threat model statement

> The perf profile **does not** provide execution-boundary containment against
> a compromised worker reading database credentials or importing storage backends
> directly. Use only when all agents in the process share the same trust level
> and latency dominates (for example single-role replicas on a hardened node).

Do **not** mix support and billing agents under `perf` on the same host unless
they are intentionally same-trust (equivalent to `inline`).
