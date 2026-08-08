"""Opt-in shared RAM namespaces for colocation groups."""

from __future__ import annotations

import threading
from typing import Any

from hyperbus_runtime.config import WorkerContext

_group_stores: dict[str, dict[str, Any]] = {}
_group_lock = threading.Lock()
_bound_context: WorkerContext | None = None


def bind_context(ctx: WorkerContext) -> None:
    global _bound_context
    _bound_context = ctx


def namespace(name: str | None = None) -> dict[str, Any]:
    """Return a group-scoped mutable store (in-process only).

    Requires profile pool/cohost/inline and a colocate_group on the bound context.
    Cross-process sharing uses OS primitives (shm, cohost profile) — not this dict.
    """
    if _bound_context is None:
        msg = "Call worker.bind_from_env() before shared.namespace()"
        raise RuntimeError(msg)
    ctx = _bound_context
    if ctx.profile == "isolate":
        msg = "shared.namespace() forbidden in isolate profile"
        raise RuntimeError(msg)
    group = name or ctx.colocate_group
    if not group:
        msg = "colocate_group required for shared RAM"
        raise RuntimeError(msg)
    with _group_lock:
        if group not in _group_stores:
            _group_stores[group] = {}
        return _group_stores[group]
