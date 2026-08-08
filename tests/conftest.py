"""Shared pytest fixtures for engine RPC integration tests."""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest
from hyperbus_core import HyperBusEngine, InMemoryBackend

from hyperbus_runtime import shared
from hyperbus_runtime.grants import load_grants_yaml
from hyperbus_runtime.rpc_server import HttpRpcServer
import hyperbus_runtime.worker as worker_module


@pytest.fixture(autouse=True)
def reset_runtime_globals() -> Iterator[None]:
    worker_module._bound = None
    worker_module._client = None
    shared._bound_context = None
    shared._group_stores.clear()
    shared._audit_events.clear()
    yield
    worker_module._bound = None
    worker_module._client = None
    shared._bound_context = None
    shared._group_stores.clear()
    shared._audit_events.clear()


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
def engine_server(grants_file, tmp_path) -> Iterator[tuple[str, HyperBusEngine]]:
    audit_path = tmp_path / "unused"
    _ = audit_path
    registry = load_grants_yaml(grants_file, tenant_id="acme")
    engine = HyperBusEngine("acme", InMemoryBackend(), registry)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    host, port = sock.getsockname()
    sock.close()
    server = HttpRpcServer(host, port, engine=engine, tenant_id="acme")
    server.start()
    try:
        yield f"http://127.0.0.1:{port}", engine
    finally:
        server.stop()
