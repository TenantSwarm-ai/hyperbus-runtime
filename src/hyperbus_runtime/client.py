"""RPC client from worker to hyperbus-engine sidecar."""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import Any, Protocol

from hyperbus_core import CapabilityError, TenantIsolationError

from hyperbus_runtime.rpc_codec import decode, encode


class EngineClient(Protocol):
    """Storage path for workers — no direct StorageBackend access."""

    def call(
        self,
        op: str,
        *,
        tenant_id: str,
        agent_id: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
    ) -> Any:
        """Dispatch an engine operation (put, get_tuple, list, ...)."""


class _RpcTransportClient:
    def __init__(
        self,
        *,
        http_url: str | None = None,
        socket_path: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not http_url and not socket_path:
            msg = "Engine client requires http_url or socket_path"
            raise ValueError(msg)
        self._http_url = http_url.rstrip("/") if http_url else None
        self._socket_path = socket_path
        self._timeout = timeout

    def call(
        self,
        op: str,
        *,
        tenant_id: str,
        agent_id: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
    ) -> Any:
        payload = {
            "op": op,
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "args": encode(args or []),
            "kwargs": encode(kwargs or {}),
        }
        response = self._post(payload)
        if response.get("ok"):
            return decode(response.get("result"))
        error = response.get("error") or {}
        self._raise_remote(error)
        msg = "Unreachable"
        raise RuntimeError(msg)

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        if self._http_url is not None:
            return self._post_http(body)
        return self._post_unix(body)

    def _post_http(self, body: bytes) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self._http_url}/rpc",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            msg = f"Engine RPC HTTP {exc.code}: {detail}"
            raise RuntimeError(msg) from exc

    def _post_unix(self, body: bytes) -> dict[str, Any]:
        assert self._socket_path is not None
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self._timeout)
            sock.connect(self._socket_path)
            sock.sendall(body + b"\n")
            chunks: list[bytes] = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
        line = b"".join(chunks).split(b"\n", 1)[0]
        return json.loads(line.decode("utf-8"))

    @staticmethod
    def _raise_remote(error: dict[str, Any]) -> None:
        error_type = error.get("type", "RpcError")
        message = error.get("message", "engine RPC failed")
        if error_type == "CapabilityError":
            raise CapabilityError(message)
        if error_type == "TenantIsolationError":
            raise TenantIsolationError(message)
        raise RuntimeError(f"{error_type}: {message}")


def connect_from_env(*, tenant_id: str, agent_id: str) -> EngineClient:
    """Build client from HYPERBUS_SOCKET or HYPERBUS_ENGINE_URL."""
    socket_path = os.environ.get("HYPERBUS_SOCKET")
    http_url = os.environ.get("HYPERBUS_ENGINE_URL")
    if not socket_path and not http_url:
        msg = "Set HYPERBUS_SOCKET or HYPERBUS_ENGINE_URL for worker → engine RPC"
        raise RuntimeError(msg)
    _ = tenant_id, agent_id
    return _RpcTransportClient(http_url=http_url, socket_path=socket_path)
