"""HTTP and Unix-socket RPC servers for the engine sidecar."""

from __future__ import annotations

import grp
import json
import os
import socket
import socketserver
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from hyperbus_core import AuditSink, HyperBusEngine

from hyperbus_runtime.peer_cred import load_peer_agent_map, read_peer_identity, resolve_agent_id
from hyperbus_runtime.rpc_dispatch import dispatch_request


def _secure_unix_socket(path: str, *, group_name: str | None) -> None:
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
    if not group_name:
        return
    try:
        gid = grp.getgrnam(group_name).gr_gid
    except KeyError:
        print(
            f"hyperbus-engine: socket group {group_name!r} not found; "
            f"leaving default ownership on {path!r}",
            file=__import__("sys").stderr,
        )
        return
    os.chown(path, -1, gid)


class RpcHttpHandler(BaseHTTPRequestHandler):
    engine: HyperBusEngine
    tenant_id: str
    audit: AuditSink | None
    rpc_token: str | None

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/rpc":
            self.send_error(404)
            return
        if self.rpc_token and self.headers.get("X-HyperBus-Token") != self.rpc_token:
            self.send_error(401, "Missing or invalid RPC token")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON body")
            return
        response = dispatch_request(
            self.engine,
            payload,
            expected_tenant_id=self.tenant_id,
            audit=self.audit,
        )
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _handle_unix_connection(
    conn: socket.socket,
    *,
    engine: HyperBusEngine,
    tenant_id: str,
    audit: AuditSink | None,
    peer_agent_map: dict[int, str],
) -> None:
    peer = read_peer_identity(conn)
    file_obj = conn.makefile("rb")
    try:
        while True:
            line = file_obj.readline()
            if not line:
                break
            try:
                payload = json.loads(line.decode("utf-8"))
                declared = payload.get("agent_id")
                peer_agent_id: str | None = None
                if isinstance(declared, str):
                    peer_agent_id = resolve_agent_id(
                        declared_agent_id=declared,
                        peer=peer,
                        peer_agent_map=peer_agent_map,
                    )
                response = dispatch_request(
                    engine,
                    payload,
                    expected_tenant_id=tenant_id,
                    audit=audit,
                    peer_agent_id=peer_agent_id,
                )
            except Exception as exc:  # noqa: BLE001 - one RPC envelope per line
                from hyperbus_runtime.rpc_dispatch import _rpc_error_payload

                response = {"ok": False, "error": _rpc_error_payload(exc)}
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
    finally:
        file_obj.close()
        conn.close()


class UnixRpcServer:
    """Newline-delimited JSON RPC over a Unix domain socket."""

    def __init__(
        self,
        socket_path: str,
        *,
        engine: HyperBusEngine,
        tenant_id: str,
        audit: AuditSink | None = None,
        peer_agent_map: dict[int, str] | None = None,
        socket_group: str | None = None,
    ) -> None:
        self._socket_path = socket_path
        self._engine = engine
        self._tenant_id = tenant_id
        self._audit = audit
        self._peer_agent_map = peer_agent_map or {}
        self._socket_group = socket_group
        self._server: socketserver.ThreadingUnixStreamServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)
        parent = os.path.dirname(self._socket_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        engine = self._engine
        tenant_id = self._tenant_id
        audit = self._audit
        peer_agent_map = self._peer_agent_map
        socket_path = self._socket_path
        socket_group = self._socket_group

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                _handle_unix_connection(
                    self.request,
                    engine=engine,
                    tenant_id=tenant_id,
                    audit=audit,
                    peer_agent_map=peer_agent_map,
                )

        self._server = socketserver.ThreadingUnixStreamServer(
            socket_path,
            _Handler,
        )
        _secure_unix_socket(socket_path, group_name=socket_group)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="hyperbus-unix-rpc",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)


class HttpRpcServer:
    """Threaded HTTP server exposing POST /rpc."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        engine: HyperBusEngine,
        tenant_id: str,
        audit: AuditSink | None = None,
        rpc_token: str | None = None,
    ) -> None:
        handler = type(
            "BoundRpcHttpHandler",
            (RpcHttpHandler,),
            {
                "engine": engine,
                "tenant_id": tenant_id,
                "audit": audit,
                "rpc_token": rpc_token,
            },
        )
        self._httpd = ThreadingHTTPServer((host, port), handler)
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self._httpd.server_address

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="hyperbus-http-rpc",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
