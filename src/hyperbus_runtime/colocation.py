"""Colocation group access control for shared RAM namespaces."""

from __future__ import annotations

import threading

from hyperbus_runtime.config import ColocationGroup, ColocationPolicy, WorkerContext

_group_bind_count: dict[str, int] = {}
_group_lock = threading.Lock()


class ColocationAccessError(RuntimeError):
    """Raised when a worker attempts unauthorized shared RAM access."""


def resolve_worker_group(
    policy: ColocationPolicy,
    ctx: WorkerContext,
    *,
    worker_id: str | None,
) -> ColocationGroup | None:
    """Return the colocation group spec for the bound worker, if any."""
    if not ctx.colocate_group:
        return None
    group = policy.groups.get(ctx.colocate_group)
    if group is None:
        msg = f"unknown colocate_group {ctx.colocate_group!r} in policy"
        raise RuntimeError(msg)
    if worker_id:
        spec = policy.worker_spec(worker_id)
        if spec and spec.get("colocate_group") not in (None, ctx.colocate_group):
            msg = (
                f"worker {worker_id!r} policy group "
                f"{spec.get('colocate_group')!r} != env {ctx.colocate_group!r}"
            )
            raise RuntimeError(msg)
        if spec and spec.get("agent_id") not in (None, ctx.agent_id):
            msg = (
                f"worker {worker_id!r} policy agent_id "
                f"{spec.get('agent_id')!r} != env {ctx.agent_id!r}"
            )
            raise RuntimeError(msg)
    _register_group_bind(ctx, policy, group)
    _assert_same_agent_trust(ctx, policy, group)
    return group


def _register_group_bind(
    ctx: WorkerContext,
    policy: ColocationPolicy,
    group: ColocationGroup,
) -> None:
    _ = policy
    with _group_lock:
        count = _group_bind_count.get(ctx.colocate_group or "", 0) + 1
        if count > group.max_workers:
            msg = (
                f"colocate_group {ctx.colocate_group!r} exceeds "
                f"max_workers={group.max_workers} in this process"
            )
            raise RuntimeError(msg)
        if ctx.colocate_group:
            _group_bind_count[ctx.colocate_group] = count


def _assert_same_agent_trust(
    ctx: WorkerContext,
    policy: ColocationPolicy,
    group: ColocationGroup,
) -> None:
    if group.trust != "same_agent_id":
        return
    for entry in policy.workers:
        if entry.get("colocate_group") != ctx.colocate_group:
            continue
        expected = entry.get("agent_id")
        if expected and expected != ctx.agent_id:
            msg = (
                f"colocate_group {ctx.colocate_group!r} trust=same_agent_id but "
                f"worker spec expects {expected!r}, got {ctx.agent_id!r}"
            )
            raise RuntimeError(msg)


def assert_namespace_access(
    ctx: WorkerContext,
    policy: ColocationPolicy | None,
    target_group: str,
) -> None:
    """Fail closed unless the worker may attach to target_group."""
    home_group = ctx.colocate_group
    if not home_group:
        msg = "colocate_group required for shared RAM"
        raise RuntimeError(msg)
    if policy is not None:
        home_spec = policy.groups.get(home_group)
        if home_spec and not home_spec.shared_ram and target_group == home_group:
            msg = f"colocate_group {home_group!r} has shared_ram=false"
            raise ColocationAccessError(msg)
    if target_group == home_group:
        return
    if policy is None:
        msg = (
            f"cross-group shared RAM to {target_group!r} requires "
            "HB_COLOCATION_POLICY with allow_ram_share_with"
        )
        raise ColocationAccessError(msg)
    group = policy.groups.get(home_group)
    if group is None:
        msg = f"unknown colocate_group {home_group!r} in policy"
        raise RuntimeError(msg)
    if target_group not in group.allow_ram_share_with:
        msg = (
            f"colocate_group {home_group!r} may not share RAM with "
            f"{target_group!r}; set allow_ram_share_with in policy"
        )
        raise ColocationAccessError(msg)


def is_cross_group_override(
    ctx: WorkerContext,
    target_group: str,
) -> bool:
    return bool(ctx.colocate_group and target_group != ctx.colocate_group)


def reset_for_tests() -> None:
    with _group_lock:
        _group_bind_count.clear()
