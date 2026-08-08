"""Agent worker entrypoint — identity binding and graph execution."""

from __future__ import annotations

import os
import runpy
import sys
from typing import TYPE_CHECKING

from hyperbus_runtime import shared
from hyperbus_runtime.checkpointer import IdentityBoundSaver
from hyperbus_runtime.client import connect_from_env
from hyperbus_runtime.config import ColocationPolicy, WorkerContext

if TYPE_CHECKING:
    from hyperbus_runtime.client import EngineClient

_bound: WorkerContext | None = None
_client: EngineClient | None = None


def bind_from_env() -> WorkerContext:
    """Load and validate worker identity from environment."""
    global _bound
    ctx = WorkerContext.from_env()
    policy_path = os.environ.get("HB_COLOCATION_POLICY")
    if policy_path:
        policy = ColocationPolicy.from_yaml(policy_path)
        if policy.tenant_id != ctx.tenant_id:
            msg = f"policy tenant {policy.tenant_id!r} != worker {ctx.tenant_id!r}"
            raise RuntimeError(msg)
    ctx.validate_profile()
    shared.bind_context(ctx)
    _bound = ctx
    return ctx


def get_client() -> EngineClient:
    """Return the worker's engine RPC client, connecting on first use."""
    global _client
    if _client is None:
        ctx = bind_from_env()
        _client = connect_from_env(tenant_id=ctx.tenant_id, agent_id=ctx.agent_id)
    return _client


def checkpointer() -> IdentityBoundSaver:
    """Return a LangGraph checkpointer backed by the engine sidecar."""
    ctx = bind_from_env()
    return IdentityBoundSaver(ctx, get_client())


def inject_langgraph_config(config: dict | None = None) -> dict:
    """Merge worker-bound identity into LangGraph configurable keys."""
    ctx = bind_from_env()
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
    get_client()
    sys.argv = sys.argv[1:]
    if sys.argv[0] == "python" and len(sys.argv) > 1:
        sys.argv = sys.argv[1:]
        runpy.run_path(sys.argv[0], run_name="__main__")
        return
    os.execvp(sys.argv[0], sys.argv)
