"""Engine boot shared by the sidecar and the in-process perf profile.

Both paths rebuild grants from the tenant's audit log (spec 003 AC-6.1, AC-6.2).
This module is the one place that constructs storage backends and audit stores
for the runtime. It imports no RPC or identity code, so the perf profile does not
pull the sidecar's server stack into a worker process.
"""

from __future__ import annotations

from pathlib import Path
from typing import TypeAlias

from hyperbus_core import (
    HyperBusEngine,
    InMemoryAuditStore,
    InMemoryBackend,
    PostgresAuditStore,
    rebuild_registry,
)

from hyperbus_runtime.grants import load_grants_seed

try:
    from hyperbus_core import PostgresBackend
except ImportError:  # pragma: no cover - optional extra
    PostgresBackend = None  # type: ignore[misc, assignment]

AuditStore: TypeAlias = InMemoryAuditStore | PostgresAuditStore
_SEED_SOURCE = "grants-yaml"


def build_backend(database_url: str | None):
    if database_url:
        if PostgresBackend is None:
            msg = "Postgres backend requested but hyperbus-core[postgres] is not installed"
            raise RuntimeError(msg)
        return PostgresBackend(database_url)
    return InMemoryBackend()


def build_audit_store(database_url: str | None) -> AuditStore:
    """Durable grant audit when a database is configured, volatile otherwise (AC-6.1, AC-6.3)."""
    if database_url:
        return PostgresAuditStore(database_url)
    return InMemoryAuditStore()


def create_engine(
    *,
    tenant_id: str,
    grants_path: Path,
    database_url: str | None,
    audit_checkpoint: tuple[int, str] | None = None,
) -> tuple[HyperBusEngine, AuditStore]:
    """Rebuild the tenant's grants from its audit log, then build the engine.

    The YAML seed fills only regions the log has never decided (AC-6.2). A
    revoked grant therefore stays revoked after restart. Any integrity failure
    raises before an engine exists, so the process does not start (spec 014 AC-14.6).
    """
    audit = build_audit_store(database_url)
    _, seed = load_grants_seed(grants_path, tenant_id=tenant_id)
    rebuilt = rebuild_registry(
        audit,
        tenant_id,
        seed=seed,
        seed_source=_SEED_SOURCE,
        checkpoint=audit_checkpoint,
    )
    backend = build_backend(database_url)
    engine = HyperBusEngine(tenant_id, backend, rebuilt.registry, audit=audit)
    return engine, audit
