"""Optional perf profile — in-process engine with weaker containment."""

from __future__ import annotations

import os
from pathlib import Path

from hyperbus_core import HyperBusEngine, InMemoryBackend

from hyperbus_runtime.config import WorkerContext
from hyperbus_runtime.grants import load_grants_yaml

try:
    from hyperbus_core import PostgresBackend
except ImportError:  # pragma: no cover - optional extra
    PostgresBackend = None  # type: ignore[misc, assignment]

PERF_PROFILE = "perf"


def is_perf_profile(profile: str) -> bool:
    return profile == PERF_PROFILE


def create_local_engine(ctx: WorkerContext) -> HyperBusEngine:
    """Construct an in-process HyperBusEngine for the perf profile."""
    grants_path = os.environ.get("HB_GRANTS_FILE")
    if not grants_path:
        msg = "perf profile requires HB_GRANTS_FILE for capability enforcement"
        raise RuntimeError(msg)
    registry = load_grants_yaml(Path(grants_path), tenant_id=ctx.tenant_id)
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        if PostgresBackend is None:
            msg = "perf profile requires hyperbus-core[postgres] when DATABASE_URL is set"
            raise RuntimeError(msg)
        backend = PostgresBackend(database_url)
    else:
        backend = InMemoryBackend()
    return HyperBusEngine(ctx.tenant_id, backend, registry)
