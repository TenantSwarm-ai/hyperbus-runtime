"""Agent worker entrypoint — identity binding and graph execution."""

from __future__ import annotations

import os
import runpy
import sys
from typing import TYPE_CHECKING

from hyperbus_runtime import shared
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


def checkpointer():
    """Return a LangGraph checkpointer backed by the engine sidecar (planned)."""
    bind_from_env()
    connect_from_env()
    msg = (
        "Runtime checkpointer wrapper over hyperbus-langgraph is not implemented. "
        "Track specs/001-runtime-isolation/spec.md US-1/US-2."
    )
    raise NotImplementedError(msg)


def main() -> None:
    """CLI: hyperbus-worker <command> [args...]"""
    if len(sys.argv) < 2:
        print("Usage: hyperbus-worker <command> [args...]", file=sys.stderr)
        sys.exit(2)
    bind_from_env()
    connect_from_env()
    sys.argv = sys.argv[1:]
    if sys.argv[0] == "python" and len(sys.argv) > 1:
        sys.argv = sys.argv[1:]
        runpy.run_path(sys.argv[0], run_name="__main__")
        return
    os.execvp(sys.argv[0], sys.argv)
