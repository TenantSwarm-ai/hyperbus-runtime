# HyperBus Runtime

Process isolation and agent identity binding for HyperBus deployments.

**Sibling to [`hyperbus-core`](https://github.com/TenantSwarm-ai/hyperbus-core)** —
Core enforces storage containment (tenant keys, region-in-key, capability grants).
Runtime enforces **execution boundaries**: which agents share RAM, how `agent_id`
is bound, and that workers never hold database credentials.

## Status

**Pre-alpha scaffold.** Spec and package layout are in place; RPC engine daemon
and LangGraph worker integration are not yet implemented. See
[`specs/001-runtime-isolation/spec.md`](specs/001-runtime-isolation/spec.md).

## Problem

HyperBus Core answers: *may this agent read/write this stored region?*

It does **not** isolate live process memory. If two agents run in one Python
interpreter, a compromised agent can read the other's heap. Runtime closes that
gap with **one process/container per agent role** (default) and an **engine
sidecar** workers call over IPC.

## Architecture

```text
support-bot container          billing-bot container
  (HB_AGENT=support-bot)         (HB_AGENT=billing-bot)
         │                                │
         └──────────┬─────────────────────┘
                    ▼ RPC (Unix socket / localhost HTTP)
            hyperbus-engine container
                    │
                    ▼
                 postgres
```

Workers use `hyperbus-runtime` + `hyperbus-langgraph`. Engine holds
`HyperBusEngine`, `CapabilityRegistry`, and Postgres credentials.

## Isolation profiles

| Profile | RAM sharing | Use when |
|---|---|---|
| `isolate` (default) | None — one role per process | Mixed-trust agents (support vs billing) |
| `pool` | Same `colocate_group`, same grants | N replicas of one role |
| `cohost` | Shared container, separate PIDs + shm | Fast handoff, some boundary |
| `inline` | Same process, shared heap | Max perf, same trust only |

See [`specs/001-runtime-isolation/colocation.md`](specs/001-runtime-isolation/colocation.md).

## Install

```bash
pip install hyperbus-runtime[langgraph,postgres]
```

For local development against a checkout of `hyperbus-core`:

```bash
pip install -e ../hyperbus-core
pip install -e '.[dev,langgraph,postgres]'
```

## Quick start (when implemented)

```bash
# Terminal 1 — engine sidecar
hyperbus-engine --tenant acme --grants /etc/hyperbus/acme-grants.yaml \
  --socket /run/hyperbus/acme.sock

# Terminal 2 — agent worker
export HB_TENANT_ID=acme HB_AGENT_ID=support-bot HB_DEFAULT_REGION=support
export HYPERBUS_SOCKET=/run/hyperbus/acme.sock
hyperbus-worker python /app/support/graph.py
```

Docker Compose example: [`examples/docker-compose/`](examples/docker-compose/).

## What this repo does not claim

- MicroVM provisioning (use E2B, K8s Agent Sandbox, Kata, etc.)
- Encryption-at-rest or hardware attestation
- Prompt-injection detection

Storage guarantees remain in Core; runtime adds execution-boundary guarantees
documented in the spec.

## Spec

- [`specs/001-runtime-isolation/spec.md`](specs/001-runtime-isolation/spec.md) — requirements and AC
- [`specs/001-runtime-isolation/design.md`](specs/001-runtime-isolation/design.md) — IPC, Docker, systemd
- Pointer from core: [`hyperbus-core/specs/012-runtime-isolation`](https://github.com/TenantSwarm-ai/hyperbus-core/blob/main/specs/012-runtime-isolation/spec.md)

## License

Apache License 2.0 — same as HyperBus Core.
