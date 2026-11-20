"""Optional perf profile — in-process engine with weaker containment."""

from __future__ import annotations

import os
from pathlib import Path

from hyperbus_core import HyperBusEngine

from hyperbus_runtime.audit_checkpoint import load_audit_checkpoint
from hyperbus_runtime.config import WorkerContext
from hyperbus_runtime.engine_boot import PostgresBackend, create_engine

PERF_PROFILE = "perf"


def is_perf_profile(profile: str) -> bool:
    return profile == PERF_PROFILE


def create_local_engine(ctx: WorkerContext) -> HyperBusEngine:
    """Construct an in-process HyperBusEngine for the perf profile.

    Boots through the same grant rebuild as the engine sidecar (``engine_boot``),
    so a grant revoked at runtime stays revoked after a restart when
    ``DATABASE_URL`` is set. ``HYPERBUS_AUDIT_CHECKPOINT`` is honoured when set.
    """
    grants_path = os.environ.get("HB_GRANTS_FILE")
    if not grants_path:
        msg = "perf profile requires HB_GRANTS_FILE for capability enforcement"
        raise RuntimeError(msg)
    database_url = os.environ.get("DATABASE_URL")
    if database_url and PostgresBackend is None:
        msg = "perf profile requires hyperbus-core[postgres] when DATABASE_URL is set"
        raise RuntimeError(msg)
    checkpoint_path = os.environ.get("HYPERBUS_AUDIT_CHECKPOINT")
    checkpoint = (
        load_audit_checkpoint(Path(checkpoint_path), tenant_id=ctx.tenant_id)
        if checkpoint_path
        else None
    )
    engine, _ = create_engine(
        tenant_id=ctx.tenant_id,
        grants_path=Path(grants_path),
        database_url=database_url,
        audit_checkpoint=checkpoint,
    )
    return engine
