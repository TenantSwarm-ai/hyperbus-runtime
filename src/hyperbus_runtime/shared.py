"""Opt-in shared RAM namespaces for colocation groups."""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from typing import Any

from hyperbus_runtime.colocation import (
    ColocationAccessError,
    assert_namespace_access,
    is_cross_group_override,
    resolve_worker_group,
)
from hyperbus_runtime.config import ColocationPolicy, WorkerContext

_log = logging.getLogger("hyperbus_runtime.shared")

_group_stores: dict[str, dict[str, Any]] = {}
_state_lock = threading.Lock()
_bound_context: WorkerContext | None = None
_bound_policy: ColocationPolicy | None = None
_audit_emitter: Callable[[str, dict[str, Any]], None] | None = None
_audit_events: list[dict[str, Any]] = []


def bind_context(
    ctx: WorkerContext,
    *,
    policy: ColocationPolicy | None = None,
    audit_emitter: Callable[[str, dict[str, Any]], None] | None = None,
) -> None:
    global _bound_context, _bound_policy, _audit_emitter
    with _state_lock:
        _bound_context = ctx
        _bound_policy = policy
        _audit_emitter = audit_emitter
        if policy and ctx.colocate_group:
            resolve_worker_group(policy, ctx, worker_id=ctx.worker_id)
        if ctx.colocate_group:
            _record_audit_locked(
                "colocation.group.join",
                group=ctx.colocate_group,
                profile=ctx.profile,
                agent_id=ctx.agent_id,
            )
            group = policy.groups.get(ctx.colocate_group) if policy else None
            if group and group.shared_ram and ctx.profile in ("pool", "cohost", "inline"):
                _record_audit_locked(
                    "colocation.ram.shared",
                    group=ctx.colocate_group,
                    profile=ctx.profile,
                    agent_id=ctx.agent_id,
                )


def namespace(name: str | None = None) -> dict[str, Any]:
    """Return a group-scoped mutable store (in-process only).

    Requires profile pool/cohost/inline and a colocate_group on the bound context.
    Cross-process sharing uses OS primitives (shm, cohost profile) — not this dict.
    """
    with _state_lock:
        if _bound_context is None:
            msg = "Call worker.bind_from_env() before shared.namespace()"
            raise RuntimeError(msg)
        ctx = _bound_context
        policy = _bound_policy
    if ctx.profile == "isolate":
        msg = "shared.namespace() forbidden in isolate profile"
        raise RuntimeError(msg)
    target_group = name or ctx.colocate_group
    if not target_group:
        msg = "colocate_group required for shared RAM"
        raise RuntimeError(msg)
    try:
        assert_namespace_access(ctx, policy, target_group)
    except ColocationAccessError as exc:
        raise RuntimeError(str(exc)) from exc
    if is_cross_group_override(ctx, target_group):
        approved_by = os.environ.get("HB_COLOCATION_APPROVED_BY", "policy")
        _record_audit(
            "colocation.policy.override",
            home_group=ctx.colocate_group,
            target_group=target_group,
            agent_id=ctx.agent_id,
            approved_by=approved_by,
        )
    with _state_lock:
        if target_group not in _group_stores:
            _group_stores[target_group] = {}
        return _group_stores[target_group]


def audit_events() -> list[dict[str, Any]]:
    """Return colocation audit events emitted in this process."""
    with _state_lock:
        return list(_audit_events)


def reset_for_tests() -> None:
    global _bound_context, _bound_policy, _audit_emitter
    with _state_lock:
        _bound_context = None
        _bound_policy = None
        _audit_emitter = None
        _group_stores.clear()
        _audit_events.clear()


def _record_audit(event_type: str, **detail: Any) -> None:
    with _state_lock:
        _record_audit_locked(event_type, **detail)


def _record_audit_locked(event_type: str, **detail: Any) -> None:
    if _bound_context is None:
        return
    event = {
        "event_type": event_type,
        "tenant_id": _bound_context.tenant_id,
        "agent_id": _bound_context.agent_id,
        "detail": detail,
    }
    _audit_events.append(event)
    _log.info("hyperbus colocation audit: %s", event)
    if _audit_emitter is not None:
        _audit_emitter(event_type, detail)
