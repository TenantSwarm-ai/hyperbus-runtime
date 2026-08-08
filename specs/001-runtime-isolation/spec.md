# Feature Spec: Runtime Isolation

**Status:** Beta  
**Repository:** `hyperbus-runtime` (sibling to `hyperbus-core`)  
**Constitution:** HyperBus org — Articles II.4, VII.2, VII.3  
**Core pointer:** [`hyperbus-core/specs/012-runtime-isolation`](https://github.com/TenantSwarm-ai/hyperbus-core/blob/main/specs/012-runtime-isolation/spec.md)

## 1. Problem Statement

`hyperbus-core` structurally contains **persisted** agent memory: region-in-key
addressing and fail-closed capability grants on every engine operation. It does
not isolate **live RAM** between agents in the same tenant.

A prompt-injected support agent running in the same process as a billing agent
can read in-process state even when HyperBus denies billing **checkpoints**.
Integrators need a reference runtime that:

1. Binds `tenant_id` and `agent_id` from deployment identity, not LLM input
2. Keeps `StorageBackend` and database credentials out of agent worker images
3. Defaults to one agent role per process/container
4. Allows **opt-in** RAM sharing only within explicit colocation groups

## 2. User Goals

- **G1:** As a platform engineer, I run each agent role in its own container so
  compromised agents cannot read another role's heap.
- **G2:** As a platform engineer, I delegate all checkpoint I/O to a HyperBus
  engine sidecar so workers cannot bypass capability checks via raw backend access.
- **G3:** As a platform engineer with trusted replicas, I colocate same-role
  agents in one process when latency matters, without weakening cross-region storage grants.
- **G4:** As a security reviewer, I can point to tests that spoofing `agent_id`
  from graph config does not elevate grants.

## 3. Non-Goals

- Provisioning MicroVMs, gVisor, or Kata (integrators compose with Agent Sandbox, E2B, etc.)
- Replacing `hyperbus-langgraph` — runtime wraps the adapter, does not fork it
- Hosted multi-tenant control plane (VII.3)
- In-process "RAM capability ACLs" inside a shared interpreter (advisory; out of scope)

## 4. Isolation Profiles

| Profile | Processes | RAM | Default |
|---|---|---|---|
| `isolate` | 1 agent role per process/container | Not shared | **Yes** |
| `pool` | N workers, same `colocate_group` | Shared within group | No |
| `cohost` | N PIDs, one container | Optional `/dev/shm` per group | No |
| `inline` | N agents, one Python process | Shared heap | No |

Cross-group RAM sharing requires explicit `allow_ram_share_with` in policy (audited).

## 5. User Stories & Acceptance Criteria

### US-1: Engine sidecar

**As a** deployment operator, **I want** a long-running engine daemon per tenant,
**so that** workers never hold Postgres credentials.

- **AC-1.1:** `hyperbus-engine` loads grants YAML, constructs `HyperBusEngine` + backend.
- **AC-1.2:** Engine exposes RPC: `put`, `get`, `list`, `delete_thread` (mapped to engine methods).
- **AC-1.3:** Every RPC includes `agent_id`; engine runs `_authorize()` before storage.
- **AC-1.4:** Worker containers cannot reach Postgres network (compose/K8s example provided).

### US-2: Worker identity binding

**As a** platform engineer, **I want** immutable worker identity,
**so that** prompt injection cannot rewrite `hyperbus_agent_id`.

- **AC-2.1:** `WorkerContext` reads `HB_TENANT_ID`, `HB_AGENT_ID`, `HB_DEFAULT_REGION` from env at startup.
- **AC-2.2:** Values injected into LangGraph `config["configurable"]` override caller-supplied keys.
- **AC-2.3:** Red-team test: graph config with `hyperbus_agent_id=billing-bot` on a support worker still authorizes as support.

### US-3: Worker has no backend

**As a** security reviewer, **I want** workers to lack `StorageBackend` imports,
**so that** agents cannot bypass the engine.

- **AC-3.1:** Worker image Dockerfile does not install postgres drivers unless running engine profile.
- **AC-3.2:** `hyperbus_runtime.client.EngineClient` is the only storage path from workers.
- **AC-3.3:** Documented `perf` profile may embed in-process engine in worker **only** with explicit opt-in and separate threat-model doc (weaker bypass story).

### US-4: Default isolation

**As a** platform engineer, **I want** separate containers per agent role by default.

- **AC-4.1:** Docker Compose example runs `support-bot` and `billing-bot` as separate services.
- **AC-4.2:** systemd example runs separate units with distinct Linux users.
- **AC-4.3:** Startup fails if `isolate` profile assigns two different `agent_id` values to one worker process.

### US-5: Colocation (opt-in RAM sharing)

**As a** platform engineer, **I want** same-role replicas to share RAM when needed.

- **AC-5.1:** `colocate_group` in worker config; only peers in the same group may use `shared.namespace()`.
- **AC-5.2:** Agents in different groups cannot attach to the same shared namespace (separate process or no mount).
- **AC-5.3:** Audit event emitted on colocation group join and on `allow_ram_share_with` override.
- **AC-5.4:** Storage containment unchanged — billing region still denied to support agent via engine.

### US-6: Performance profiles

**As a** platform engineer, **I want** documented latency tradeoffs.

- **AC-6.1:** Default transport is Unix domain socket on Linux.
- **AC-6.2:** Design doc states expected IPC overhead vs in-process engine (same-host order: 0.05–1 ms per call).
- **AC-6.3:** Optional `perf` profile documented with weaker "no bypass" guarantees.

## 6. Dependencies

- `hyperbus-core` — `HyperBusEngine`, `CapabilityRegistry`, backends
- `hyperbus-langgraph` — `HyperBusSaver` wired through `EngineClient`
- Optional: PyYAML for grants file loading

## 7. Verification

Adversarial tests (sibling repo `tests/`):

- Identity spoof from graph config → still denied cross-region
- Direct backend import in worker → not available in default image
- Colocation group boundary → shared namespace inaccessible across groups
- Engine RPC without `agent_id` → rejected

Storage containment regressions remain in `hyperbus-core` CI.

## 8. Reference deployments

- `examples/docker-compose/` — support + billing + engine + postgres
- `examples/systemd/` — bare Linux units and socket layout

See [`design.md`](design.md) and [`colocation.md`](colocation.md).
