"""Boot rebuilds grants from the audit log (spec 003 AC-6.1, AC-6.2, AC-6.6; core 014)."""

from __future__ import annotations

import os
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from hyperbus_core import (
    AuditIntegrityError,
    CapabilityError,
    CapabilityRegistry,
    HyperBusEngine,
    InMemoryAuditStore,
    Permission,
    PostgresAuditStore,
    checkpoint_of,
    replay_tenant_grants,
)
from hyperbus_core.audit_chain import GENESIS_HASH

from hyperbus_runtime import engine_daemon
from hyperbus_runtime.audit_checkpoint import load_audit_checkpoint, write_audit_checkpoint
from hyperbus_runtime.audit_checkpoint import main as audit_checkpoint_main
from hyperbus_runtime.engine_daemon import create_engine

TENANT = "acme"


def _grants_file(directory: Path, *, tenant: str = TENANT) -> Path:
    path = directory / f"grants-{uuid.uuid4().hex[:8]}.yaml"
    path.write_text(
        f"tenant_id: {tenant}\ngrants:\n  support-bot:\n    support: READ_WRITE\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def shared_audit(monkeypatch: pytest.MonkeyPatch) -> InMemoryAuditStore:
    """One log that survives restarts. ``create_engine`` builds a store per boot."""
    store = InMemoryAuditStore()
    monkeypatch.setattr(engine_daemon, "_build_audit_store", lambda database_url: store)
    return store


def _operator_revoke(store: InMemoryAuditStore, agent: str, region: str) -> None:
    """Write the revoke the way an operator control plane does: straight to the log."""
    CapabilityRegistry(tenant_id=TENANT, audit=store).revoke(
        agent, region, actor_id="operator"
    )


def _assert_denied(engine_obj: HyperBusEngine, agent: str, region: str) -> None:
    with pytest.raises(CapabilityError):
        engine_obj.get("t1", "c1", region=region, agent_id=agent)


def test_seeded_grant_is_enforced_on_first_boot(shared_audit: InMemoryAuditStore, tmp_path: Path) -> None:
    engine_obj, audit = create_engine(
        tenant_id=TENANT, grants_path=_grants_file(tmp_path), database_url=None
    )

    assert audit is shared_audit
    assert engine_obj.get("t1", "c1", region="support", agent_id="support-bot") is None


def test_revoked_grant_stays_revoked_after_restart(shared_audit: InMemoryAuditStore, tmp_path: Path) -> None:
    grants = _grants_file(tmp_path)
    create_engine(tenant_id=TENANT, grants_path=grants, database_url=None)
    _operator_revoke(shared_audit, "support-bot", "support")

    restarted, _ = create_engine(tenant_id=TENANT, grants_path=grants, database_url=None)

    _assert_denied(restarted, "support-bot", "support")
    seeds = [e for e in shared_audit.events if e.event_type == "grant.created"]
    assert len(seeds) == 1, "a restart must not append the seed again"


def test_restart_without_a_revoke_keeps_the_seeded_grant(shared_audit: InMemoryAuditStore, tmp_path: Path) -> None:
    grants = _grants_file(tmp_path)
    create_engine(tenant_id=TENANT, grants_path=grants, database_url=None)

    restarted, _ = create_engine(tenant_id=TENANT, grants_path=grants, database_url=None)

    assert restarted.get("t1", "c1", region="support", agent_id="support-bot") is None


def test_tampered_log_refuses_boot(shared_audit: InMemoryAuditStore, tmp_path: Path) -> None:
    grants = _grants_file(tmp_path)
    create_engine(tenant_id=TENANT, grants_path=grants, database_url=None)
    shared_audit.events[0] = replace(shared_audit.events[0], permission="READ")

    with pytest.raises(AuditIntegrityError):
        create_engine(tenant_id=TENANT, grants_path=grants, database_url=None)


def test_checkpoint_stops_a_deleted_revoke_from_restoring_access(
    shared_audit: InMemoryAuditStore, tmp_path: Path
) -> None:
    grants = _grants_file(tmp_path)
    create_engine(tenant_id=TENANT, grants_path=grants, database_url=None)
    _operator_revoke(shared_audit, "support-bot", "support")
    checkpoint = checkpoint_of(replay_tenant_grants(shared_audit, TENANT))
    create_engine(tenant_id=TENANT, grants_path=grants, database_url=None, audit_checkpoint=checkpoint)

    shared_audit.events.pop()  # the revoke disappears from the tail of the log

    with pytest.raises(AuditIntegrityError, match="past the log tip"):
        create_engine(
            tenant_id=TENANT,
            grants_path=grants,
            database_url=None,
            audit_checkpoint=checkpoint,
        )


def test_tail_deletion_is_accepted_without_a_checkpoint(
    shared_audit: InMemoryAuditStore, tmp_path: Path
) -> None:
    """Documented limit (core 014 AC-14.9): the chain alone cannot see a removed tail."""
    grants = _grants_file(tmp_path)
    create_engine(tenant_id=TENANT, grants_path=grants, database_url=None)
    _operator_revoke(shared_audit, "support-bot", "support")
    shared_audit.events.pop()

    restarted, _ = create_engine(tenant_id=TENANT, grants_path=grants, database_url=None)

    assert restarted.get("t1", "c1", region="support", agent_id="support-bot") is None


def test_audit_store_follows_the_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    assert isinstance(engine_daemon._build_audit_store(None), InMemoryAuditStore)
    durable = engine_daemon._build_audit_store("postgresql://127.0.0.1:1/unused")
    assert isinstance(durable, PostgresAuditStore)


def test_write_then_load_checkpoint_round_trips(tmp_path: Path) -> None:
    store = InMemoryAuditStore()
    CapabilityRegistry(tenant_id=TENANT, audit=store).grant(
        "support-bot", "support", Permission.READ_WRITE
    )
    path = tmp_path / "checkpoint.yaml"

    written = write_audit_checkpoint(path, store, tenant_id=TENANT)

    assert load_audit_checkpoint(path, tenant_id=TENANT) == written == checkpoint_of(
        replay_tenant_grants(store, TENANT)
    )


def test_checkpoint_file_is_never_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.yaml"
    path.write_text("keep me", encoding="utf-8")

    with pytest.raises(FileExistsError):
        write_audit_checkpoint(path, InMemoryAuditStore(), tenant_id=TENANT)
    assert path.read_text(encoding="utf-8") == "keep me"


@pytest.fixture
def checkpoint_file(tmp_path: Path) -> Path:
    return tmp_path / "checkpoint.yaml"


@pytest.mark.parametrize(
    "body",
    [
        "- not\n- a mapping\n",
        "tenant_id: other\nsequence: 0\nevent_hash: '" + "0" * 64 + "'\n",
        "tenant_id: acme\nsequence: true\nevent_hash: '" + "0" * 64 + "'\n",
        "tenant_id: acme\nsequence: -1\nevent_hash: '" + "0" * 64 + "'\n",
        "tenant_id: acme\nsequence: 1\nevent_hash: 'NOT-HEX'\n",
        "tenant_id: acme\nsequence: 1\nevent_hash: '" + "A" * 64 + "'\n",
    ],
    ids=[
        "not-a-mapping",
        "other-tenant",
        "bool-sequence",
        "negative-sequence",
        "non-hex-hash",
        "uppercase-hash",
    ],
)
def test_malformed_checkpoint_is_refused(checkpoint_file: Path, body: str) -> None:
    checkpoint_file.write_text(body, encoding="utf-8")

    with pytest.raises(ValueError):
        load_audit_checkpoint(checkpoint_file, tenant_id=TENANT)


def test_checkpoint_cli_requires_a_database_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(SystemExit, match="Postgres URL is required"):
        audit_checkpoint_main(["--tenant", TENANT, "--out", str(tmp_path / "cp.yaml")])


@pytest.mark.skipif(
    not os.environ.get("HYPERBUS_TEST_DATABASE_URL"),
    reason="set HYPERBUS_TEST_DATABASE_URL to run the Postgres boot test",
)
def test_checkpoint_cli_writes_the_genesis_checkpoint_for_an_empty_log(tmp_path: Path) -> None:
    url = os.environ["HYPERBUS_TEST_DATABASE_URL"]
    tenant = f"acme-{uuid.uuid4().hex[:10]}"
    out = tmp_path / "checkpoint.yaml"

    audit_checkpoint_main(["--tenant", tenant, "--out", str(out), "--database-url", url])

    assert load_audit_checkpoint(out, tenant_id=tenant) == (0, GENESIS_HASH)


@pytest.mark.skipif(
    not os.environ.get("HYPERBUS_TEST_DATABASE_URL"),
    reason="set HYPERBUS_TEST_DATABASE_URL to run the Postgres boot test",
)
def test_restart_on_postgres_keeps_the_revocation(tmp_path: Path) -> None:
    url = os.environ["HYPERBUS_TEST_DATABASE_URL"]
    tenant = f"acme-{uuid.uuid4().hex[:10]}"
    grants = _grants_file(tmp_path, tenant=tenant)

    _, first_audit = create_engine(tenant_id=tenant, grants_path=grants, database_url=url)
    CapabilityRegistry(tenant_id=tenant, audit=first_audit).revoke(
        "support-bot", "support", actor_id="operator"
    )
    restarted, second_audit = create_engine(tenant_id=tenant, grants_path=grants, database_url=url)

    assert isinstance(second_audit, PostgresAuditStore)
    _assert_denied(restarted, "support-bot", "support")
