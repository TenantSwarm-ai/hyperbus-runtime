"""Tests for Unix RPC client/server internals."""

from __future__ import annotations

import json
import socket

import pytest
from hyperbus_core import HyperBusEngine, InMemoryBackend

from hyperbus_runtime.client import _RpcTransportClient
from hyperbus_runtime.grants import load_grants_yaml
from hyperbus_runtime.rpc_server import UnixRpcServer, _handle_unix_connection


def _short_unix_path(name: str) -> str:
    return f"/tmp/{name}.sock"


def test_handle_unix_connection_multiple_requests(grants_file) -> None:
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("Unix sockets unavailable")
    registry = load_grants_yaml(grants_file, tenant_id="acme")
    engine = HyperBusEngine("acme", InMemoryBackend(), registry)
    client_sock, server_sock = socket.socketpair()
    try:
        thread = __import__("threading").Thread(
            target=_handle_unix_connection,
            args=(server_sock,),
            kwargs={"engine": engine, "tenant_id": "acme"},
            daemon=True,
        )
        thread.start()
        payload = json.dumps(
            {"op": "runtime.ping", "tenant_id": "acme", "agent_id": "support-bot"}
        )
        client_sock.sendall((payload + "\n").encode("utf-8"))
        line = client_sock.makefile("rb").readline()
        response = json.loads(line.decode("utf-8"))
        assert response["ok"] is True
        thread.join(timeout=2)
    finally:
        client_sock.close()
        server_sock.close()


def test_unix_rpc_server_start_stop(grants_file) -> None:
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("Unix sockets unavailable")
    import os

    registry = load_grants_yaml(grants_file, tenant_id="acme")
    engine = HyperBusEngine("acme", InMemoryBackend(), registry)
    socket_path = _short_unix_path("hb-runtime-stop")
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

