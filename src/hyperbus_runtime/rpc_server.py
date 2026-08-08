"""HTTP and Unix-socket RPC servers for the engine sidecar."""

from __future__ import annotations

import json
import os
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from hyperbus_core import HyperBusEngine

from hyperbus_runtime.rpc_dispatch import dispatch_request


class RpcHttpHandler(BaseHTTPRequestHandler):
    engine: HyperBusEngine
    tenant_id: str

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/rpc":
            self.send_error(404)
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
) -> None:
    file_obj = conn.makefile("rb")
    try:
        while True:
            line = file_obj.readline()
            if not line:
                break
            payload = json.loads(line.decode("utf-8"))
            response = dispatch_request(
                engine,
                payload,
                expected_tenant_id=tenant_id,
            )
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
    ) -> None:
        self._socket_path = socket_path
        self._engine = engine
        self._tenant_id = tenant_id
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
        socket_path = self._socket_path

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                _handle_unix_connection(
                    self.request,
                    engine=engine,
                    tenant_id=tenant_id,
                )

        self._server = socketserver.ThreadingUnixStreamServer(
            socket_path,
            _Handler,
        )
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
    ) -> None:
        handler = type(
            "BoundRpcHttpHandler",
            (RpcHttpHandler,),
            {"engine": engine, "tenant_id": tenant_id},
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
