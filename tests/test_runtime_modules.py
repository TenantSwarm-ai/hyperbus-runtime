"""Additional tests for runtime modules and edge cases."""

from __future__ import annotations

import os
import socket
import threading
from unittest.mock import patch

import pytest
from hyperbus_core import HyperBusEngine, InMemoryAuditStore, InMemoryBackend

from hyperbus_runtime.client import _RpcTransportClient
from hyperbus_runtime.engine_daemon import _build_backend
from hyperbus_runtime.rpc_server import HttpRpcServer
from hyperbus_runtime.grants import load_grants_yaml
from hyperbus_runtime.remote_engine import RemoteHyperBusEngine
from hyperbus_runtime.rpc_codec import decode, encode
from hyperbus_runtime.rpc_dispatch import dispatch_request
from hyperbus_runtime.rpc_server import UnixRpcServer
from hyperbus_runtime import shared
from hyperbus_runtime.worker import bind_from_env, main


def test_rpc_codec_rejects_unknown_type() -> None:
    with pytest.raises(TypeError, match="cannot encode"):
        encode(object())


def test_remote_engine_rejects_agent_mismatch(engine_server) -> None:
    url, _engine = engine_server
    client = _RpcTransportClient(http_url=url)
    remote = RemoteHyperBusEngine(
        client,
        tenant_id="acme",
        bound_agent_id="support-bot",
    )
    with pytest.raises(RuntimeError, match="bound agent"):
        remote.get("t1", "c1", region="support", agent_id="billing-bot")


def test_client_raises_tenant_isolation_error(engine_server) -> None:
    url, engine = engine_server
    response = dispatch_request(
        engine,
        {
            "op": "put",
            "tenant_id": "acme",
            "agent_id": "support-bot",
            "args": ["../evil", "c1"],
            "kwargs": {"state": {}, "metadata": {}, "region": "support"},
        },
        expected_tenant_id="acme",
    )
    assert response["ok"] is False
    assert response["error"]["type"] == "TenantIsolationError"


def _short_unix_path(name: str) -> str:
    return f"/tmp/{name}.sock"


def test_unix_rpc_server_roundtrip(grants_file) -> None:
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("Unix sockets unavailable")
    registry = load_grants_yaml(grants_file, tenant_id="acme")
    engine = HyperBusEngine("acme", InMemoryBackend(), registry)
    socket_path = _short_unix_path("hb-runtime-roundtrip")
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    server = UnixRpcServer(socket_path, engine=engine, tenant_id="acme")
    server.start()
    try:
        client = _RpcTransportClient(socket_path=socket_path)
        result = client.call(
            "runtime.ping",
            tenant_id="acme",
            agent_id="support-bot",
        )
        assert result == {"tenant_id": "acme"}
    finally:
        server.stop()


def test_build_backend_in_memory() -> None:
    backend = _build_backend(None)
    assert isinstance(backend, InMemoryBackend)


def test_build_backend_postgres_missing() -> None:
    with patch("hyperbus_runtime.engine_daemon.PostgresBackend", None):
        with pytest.raises(RuntimeError, match="Postgres backend requested"):
            _build_backend("postgresql://example")


def test_shared_namespace_requires_bind() -> None:
    with pytest.raises(RuntimeError, match="bind_from_env"):
        shared.namespace()


def test_shared_namespace_requires_group() -> None:
    from hyperbus_runtime.config import WorkerContext

    shared.bind_context(
        WorkerContext(
            tenant_id="acme",
            agent_id="support-bot",
            profile="pool",
            colocate_group=None,
        )
    )
    with pytest.raises(RuntimeError, match="colocate_group"):
        shared.namespace()


def test_worker_main_usage(capsys) -> None:
    with patch("sys.argv", ["hyperbus-worker"]):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 2


def test_worker_main_exec_python(tmp_path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    script = tmp_path / "hello.py"
    script.write_text('print("hello-from-worker")\n', encoding="utf-8")
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "http://127.0.0.1:1")
    with patch("sys.argv", ["hyperbus-worker", "python", str(script)]):
        main()
    assert "hello-from-worker" in capsys.readouterr().out


def test_http_rpc_server_start_stop(grants_file) -> None:
    audit = InMemoryAuditStore()
    engine = HyperBusEngine(
        "acme",
        InMemoryBackend(),
        load_grants_yaml(grants_file, tenant_id="acme"),
        audit=audit,
    )
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    _, port = sock.getsockname()
    sock.close()
    server = HttpRpcServer(
        "127.0.0.1",
        port,
        engine=engine,
        tenant_id="acme",
        audit=audit,
    )
    server.start()
    server.stop()


def test_grants_invalid_agent_map(tmp_path) -> None:
    path = tmp_path / "grants.yaml"
    path.write_text(
        "tenant_id: acme\ngrants:\n  bot: not-a-map\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="region map"):
        load_grants_yaml(path)


def test_dispatch_unsupported_op(engine_server) -> None:
    _, engine = engine_server
    response = dispatch_request(
        engine,
        {
            "op": "not_real",
            "tenant_id": "acme",
            "agent_id": "support-bot",
        },
        expected_tenant_id="acme",
    )
    assert response["error"]["type"] == "RpcValidationError"


def test_client_invalid_transport() -> None:
    with pytest.raises(ValueError, match="Engine client requires"):
        _RpcTransportClient()
