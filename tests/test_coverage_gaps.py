"""Additional coverage for colocation, isolate, peer cred, and engine daemon."""

from __future__ import annotations

import os
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

from hyperbus_runtime.colocation import resolve_worker_group
from hyperbus_runtime.config import ColocationGroup, ColocationPolicy, WorkerContext
from hyperbus_runtime.engine_daemon import create_engine, serve_engine
from hyperbus_runtime.isolate import pid_file_guard, reset_for_tests
from hyperbus_runtime.peer_cred import load_peer_agent_map, read_peer_identity
from hyperbus_runtime.perf import create_local_engine
from hyperbus_runtime.client import _RpcTransportClient
from hyperbus_runtime.rpc_dispatch import dispatch_request


def test_resolve_worker_group_unknown_group() -> None:
    policy = ColocationPolicy(
        tenant_id="acme",
        groups={"support-pool": ColocationGroup(name="support-pool")},
    )
    ctx = WorkerContext(
        tenant_id="acme",
        agent_id="support-bot",
        profile="pool",
        colocate_group="missing",
    )
    with pytest.raises(RuntimeError, match="unknown colocate_group"):
        resolve_worker_group(policy, ctx, worker_id=None)


def test_resolve_worker_group_worker_spec_mismatch() -> None:
    policy = ColocationPolicy(
        tenant_id="acme",
        workers=[{"id": "w1", "colocate_group": "other"}],
        groups={"support-pool": ColocationGroup(name="support-pool")},
    )
    ctx = WorkerContext(
        tenant_id="acme",
        agent_id="support-bot",
        profile="pool",
        colocate_group="support-pool",
    )
    with pytest.raises(RuntimeError, match="policy group"):
        resolve_worker_group(policy, ctx, worker_id="w1")


def test_pid_file_guard_blocks_conflict(tmp_path: Path) -> None:
    reset_for_tests()
    guard = tmp_path / "guard"
    guard.write_text("acme:billing-bot", encoding="utf-8")
    with patch.dict(os.environ, {"HB_ISOLATE_GUARD_FILE": str(guard)}):
        with pytest.raises(RuntimeError, match="isolate guard file"):
            pid_file_guard("support-bot", profile="inline", tenant_id="acme")


def test_pid_file_guard_writes_marker(tmp_path: Path) -> None:
    reset_for_tests()
    guard = tmp_path / "guard-new"
    with patch.dict(os.environ, {"HB_ISOLATE_GUARD_FILE": str(guard)}):
        pid_file_guard("support-bot", profile="cohost", tenant_id="acme")
    assert guard.read_text(encoding="utf-8") == "acme:support-bot"


def test_read_peer_identity_returns_none_without_option() -> None:
    client, server = socket.socketpair()
    try:
        with patch("hyperbus_runtime.peer_cred.socket.SO_PEERCRED", None, create=True):
            assert read_peer_identity(server) is None
    finally:
        client.close()
        server.close()


def test_load_peer_agent_map_invalid(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("peer_agents: not-a-map\n", encoding="utf-8")
    with pytest.raises(ValueError, match="uid"):
        load_peer_agent_map(path)


def test_create_local_engine_with_grants(grants_file) -> None:
    ctx = WorkerContext(tenant_id="acme", agent_id="support-bot", profile="perf")
    with patch.dict(os.environ, {"HB_GRANTS_FILE": str(grants_file)}):
        engine = create_local_engine(ctx)
    assert engine.enforces_capabilities is True


def test_create_local_engine_postgres_missing(
    grants_file,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = WorkerContext(tenant_id="acme", agent_id="support-bot", profile="perf")
    monkeypatch.setenv("HB_GRANTS_FILE", str(grants_file))
    monkeypatch.setenv("DATABASE_URL", "postgresql://example")
    with patch("hyperbus_runtime.perf.PostgresBackend", None):
        with pytest.raises(RuntimeError, match="perf profile requires"):
            create_local_engine(ctx)


def test_serve_engine_requires_transport(grants_file) -> None:
    engine, audit = create_engine(
        tenant_id="acme",
        grants_path=grants_file,
        database_url=None,
    )
    with pytest.raises(RuntimeError, match="At least one"):
        serve_engine(
            engine,
            audit,
            tenant_id="acme",
            socket_path=None,
            listen=None,
            peer_agent_map_path=None,
        )


def test_serve_engine_http_requires_rpc_token(grants_file) -> None:
    engine, audit = create_engine(
        tenant_id="acme",
        grants_path=grants_file,
        database_url=None,
    )
    with pytest.raises(RuntimeError, match="HYPERBUS_RPC_TOKEN"):
        serve_engine(
            engine,
            audit,
            tenant_id="acme",
            socket_path=None,
            listen="127.0.0.1:8080",
            peer_agent_map_path=None,
            rpc_token=None,
        )


def test_runtime_audit_requires_event_type(engine_server_with_audit) -> None:
    _, engine, audit = engine_server_with_audit
    response = dispatch_request(
        engine,
        {
            "op": "runtime.audit",
            "tenant_id": "acme",
            "agent_id": "support-bot",
            "kwargs": {"detail": {}},
        },
        expected_tenant_id="acme",
        audit=audit,
    )
    assert response["ok"] is False


def test_runtime_audit_rejects_unknown_event(engine_server_with_audit) -> None:
    url, _engine, _audit = engine_server_with_audit
    client = _RpcTransportClient(http_url=url)
    with pytest.raises(RuntimeError, match="not allowed"):
        client.call(
            "runtime.audit",
            tenant_id="acme",
            agent_id="support-bot",
            kwargs={"event_type": "evil.event", "detail": {}},
        )
