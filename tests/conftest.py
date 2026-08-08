"""Shared pytest fixtures for engine RPC integration tests."""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest
from hyperbus_core import HyperBusEngine, InMemoryAuditStore, InMemoryBackend

import hyperbus_runtime.worker as worker_module
from hyperbus_runtime import shared
from hyperbus_runtime.async_runner import reset_for_tests as reset_async_runner
from hyperbus_runtime.colocation import reset_for_tests as reset_colocation
from hyperbus_runtime.grants import load_grants_yaml
from hyperbus_runtime.isolate import reset_for_tests as reset_isolate
from hyperbus_runtime.rpc_server import HttpRpcServer

RPC_TEST_TOKEN = "test-rpc-token"


@pytest.fixture(autouse=True)
def rpc_token_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HYPERBUS_RPC_TOKEN", RPC_TEST_TOKEN)


@pytest.fixture(autouse=True)
def reset_runtime_globals() -> Iterator[None]:
    worker_module._bound = None
    worker_module._client = None
    worker_module._policy = None
    shared.reset_for_tests()
    reset_isolate()
    reset_colocation()
    reset_async_runner()
    yield
    worker_module._bound = None
    worker_module._client = None
    worker_module._policy = None
    shared.reset_for_tests()
    reset_isolate()
    reset_colocation()
    reset_async_runner()


@pytest.fixture
def grants_file(tmp_path):
    path = tmp_path / "grants.yaml"
    path.write_text(
        """
tenant_id: acme
grants:
  support-bot:
    support: READ_WRITE
    hyperbus-meta: READ_WRITE
  billing-bot:
    billing: READ_WRITE
    hyperbus-meta: READ_WRITE
""",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def colocation_policy_file(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
tenant_id: acme
colocation_policy:
  default_profile: isolate
workers:
  - id: support-primary
    agent_id: support-bot
    profile: pool
    colocate_group: support-pool
groups:
  support-pool:
    max_workers: 4
    shared_ram: true
  billing-solo:
    shared_ram: false
    allow_ram_share_with: []
""",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def engine_server(grants_file) -> Iterator[tuple[str, HyperBusEngine]]:
    audit = InMemoryAuditStore()
    registry = load_grants_yaml(grants_file, tenant_id="acme", audit=audit)
    engine = HyperBusEngine("acme", InMemoryBackend(), registry, audit=audit)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    host, port = sock.getsockname()
    sock.close()
    server = HttpRpcServer(
        host,
        port,
        engine=engine,
        tenant_id="acme",
        audit=audit,
        rpc_token=RPC_TEST_TOKEN,
    )
    server.start()
    try:
        yield f"http://127.0.0.1:{port}", engine
    finally:
        server.stop()


@pytest.fixture
def engine_server_with_audit(
    grants_file,
) -> Iterator[tuple[str, HyperBusEngine, InMemoryAuditStore]]:
    audit = InMemoryAuditStore()
    registry = load_grants_yaml(grants_file, tenant_id="acme", audit=audit)
    engine = HyperBusEngine("acme", InMemoryBackend(), registry, audit=audit)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    host, port = sock.getsockname()
    sock.close()
    server = HttpRpcServer(
        host,
        port,
        engine=engine,
        tenant_id="acme",
        audit=audit,
        rpc_token=RPC_TEST_TOKEN,
    )
    server.start()
    try:
        yield f"http://127.0.0.1:{port}", engine, audit
    finally:
        server.stop()
