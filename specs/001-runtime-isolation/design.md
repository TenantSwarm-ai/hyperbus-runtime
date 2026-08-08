# Design: Runtime Isolation

**Spec:** [`spec.md`](spec.md)

## Components

```text
┌─────────────────────────────────────────────────────────────┐
│ hyperbus_runtime.worker                                      │
│  • WorkerContext (env-bound identity)                        │
│  • hyperbus-worker CLI → exec user graph                     │
│  • Injects config["configurable"] for hyperbus-langgraph       │
└───────────────────────────┬─────────────────────────────────┘
                            │ EngineClient (RPC)
┌───────────────────────────▼─────────────────────────────────┐
│ hyperbus_runtime.engine_daemon                               │
│  • hyperbus-engine CLI                                       │
│  • HyperBusEngine + CapabilityRegistry + AuditSink           │
│  • PostgresBackend (credentials here only)                   │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
                       PostgreSQL
```

## IPC

**v1 transport:** Unix domain socket on Linux (`HYPERBUS_SOCKET`).

**Fallback:** HTTP on localhost (`HYPERBUS_ENGINE_URL`) for Docker Compose
where binding a host socket is awkward.

Message shape (illustrative):

```json
{
  "op": "get_tuple",
  "agent_id": "support-bot",
  "tenant_id": "acme",
  "thread_id": "ticket-8812",
  "checkpoint_ns": "",
  "checkpoint_id": "..."
}
```

Responses mirror engine exceptions: `CapabilityError`, `TenantIsolationError`
→ RPC error codes; never collapse types.

**Performance note:** Authorization in core is ~400 ns/check. Postgres put p50
~2 ms on local Docker (hyperbus-core scorecard). Same-host Unix socket adds
~0.05–0.3 ms — negligible vs LLM latency; matters for in-memory backend only.

## Docker layout

```text
networks:
  hb-internal: engine ↔ postgres
  hb-agents:   workers ↔ engine (workers NOT on hb-internal)

services:
  postgres
  hyperbus-engine   # hyperbus-engine CLI, grants volume
  support-bot       # hyperbus-worker, no DATABASE_URL
  billing-bot       # hyperbus-worker, no DATABASE_URL
```

Worker Dockerfile:

```dockerfile
FROM python:3.12-slim
RUN pip install hyperbus-runtime[langgraph]
# intentionally NO hyperbus-core[postgres]
COPY app/ /app/
ENV HB_TENANT_ID=acme HB_AGENT_ID=support-bot
CMD ["hyperbus-worker", "python", "/app/graph.py"]
```

Engine Dockerfile:

```dockerfile
FROM python:3.12-slim
RUN pip install hyperbus-runtime[postgres]
CMD ["hyperbus-engine", "--tenant", "acme", "--grants", "/etc/hyperbus/grants.yaml"]
```

## systemd layout (Linux)

| Unit | User | Role |
|---|---|---|
| `hyperbus-engine@acme.service` | `hb-engine-acme` | Engine + Postgres client |
| `support-bot.service` | `hb-agent-support` | Worker |
| `billing-bot.service` | `hb-agent-billing` | Worker |

Socket: `/run/hyperbus/acme.sock`, group `hb-agents`.

Optional: map Unix peer credentials (`SO_PEERCRED`) → `agent_id` so workers
cannot spoof identity at the RPC layer.

## Performance profile (`perf`)

Optional worker-local `HyperBusEngine` with Postgres URL — skips RPC hop.

**Tradeoff:** worker holds DB credentials and could import backend directly if
mis-packaged. Document as degraded containment; not the default.

## Identity flow

```text
Orchestrator (K8s/env) → HB_AGENT_ID=support-bot
                      → WorkerContext (immutable)
                      → EngineClient RPC (agent_id in every message)
                      → HyperBusEngine._authorize()
                      → CapabilityRegistry.check()
```

LangGraph `config["configurable"]["hyperbus_agent_id"]` from the graph is
**ignored** when runtime is active.

## Out of scope for v1

- mTLS between worker and engine (localhost trust boundary)
- Automatic Kata/gVisor `RuntimeClass` provisioning
- Grant mutation over RPC (use `GrantControlPlane` on engine host or sidecar admin port later)
