"""Agent worker entrypoint — identity binding and graph execution."""

from __future__ import annotations

import os
import runpy
import sys
import threading
from typing import TYPE_CHECKING

from hyperbus_runtime import shared
from hyperbus_runtime.checkpointer import IdentityBoundSaver
from hyperbus_runtime.client import connect_from_env
from hyperbus_runtime.config import ColocationPolicy, WorkerContext
from hyperbus_runtime.isolate import pid_file_guard, register_isolate_agent
from hyperbus_runtime.perf import create_local_engine, is_perf_profile
from hyperbus_runtime.runtime_audit import make_colocation_audit_emitter

if TYPE_CHECKING:
    from hyperbus_runtime.client import EngineClient

_worker_lock = threading.RLock()
_bound: WorkerContext | None = None
_client: EngineClient | None = None
_policy: ColocationPolicy | None = None


def bind_from_env() -> WorkerContext:
    """Load and validate worker identity from environment."""
    global _bound, _policy
    with _worker_lock:
        if _bound is not None:
            return _bound
        ctx = WorkerContext.from_env()
        policy_path = os.environ.get("HB_COLOCATION_POLICY")
        policy: ColocationPolicy | None = None
        if policy_path:
            policy = ColocationPolicy.from_yaml(policy_path)
            if policy.tenant_id != ctx.tenant_id:
                msg = f"policy tenant {policy.tenant_id!r} != worker {ctx.tenant_id!r}"
                raise RuntimeError(msg)
        ctx.validate_profile()
        register_isolate_agent(ctx.agent_id, profile=ctx.profile)
        pid_file_guard(ctx.agent_id, profile=ctx.profile, tenant_id=ctx.tenant_id)
        _policy = policy
        _bound = ctx
        shared.bind_context(ctx, policy=policy)
        return ctx


def _ensure_bound() -> WorkerContext:
    return bind_from_env()


def get_client() -> EngineClient:
    """Return the worker's engine RPC client, connecting on first use."""
    global _client
    with _worker_lock:
        ctx = _ensure_bound()
        if is_perf_profile(ctx.profile):
            msg = "perf profile uses in-process engine; EngineClient is unavailable"
            raise RuntimeError(msg)
        if _client is None:
            _client = connect_from_env(tenant_id=ctx.tenant_id, agent_id=ctx.agent_id)
            shared.bind_context(
                ctx,
                policy=_policy,
                audit_emitter=make_colocation_audit_emitter(
                    _client,
                    tenant_id=ctx.tenant_id,
                    agent_id=ctx.agent_id,
                ),
            )
        return _client


def checkpointer() -> IdentityBoundSaver:
    """Return a LangGraph checkpointer backed by the engine sidecar."""
    ctx = _ensure_bound()
    if is_perf_profile(ctx.profile):
        return IdentityBoundSaver(ctx, local_engine=create_local_engine(ctx))
    client = get_client()
    return IdentityBoundSaver(ctx, client)


def inject_langgraph_config(config: dict | None = None) -> dict:
    """Merge worker-bound identity into LangGraph configurable keys."""
    ctx = _ensure_bound()
    merged = dict(config or {})
    configurable = dict(merged.get("configurable") or {})
    configurable.update(ctx.langgraph_configurable())
    merged["configurable"] = configurable
    return merged


def main() -> None:
    """CLI: hyperbus-worker <command> [args...]"""
    if len(sys.argv) < 2:
        print("Usage: hyperbus-worker <command> [args...]", file=sys.stderr)
        sys.exit(2)
    bind_from_env()
    if not is_perf_profile(_bound.profile if _bound else ""):
        get_client()
    sys.argv = sys.argv[1:]
    if sys.argv[0] == "python" and len(sys.argv) > 1:
        sys.argv = sys.argv[1:]
        runpy.run_path(sys.argv[0], run_name="__main__")
        return
    os.execvp(sys.argv[0], sys.argv)
