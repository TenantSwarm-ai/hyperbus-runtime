"""RPC client from worker to hyperbus-engine sidecar."""

from __future__ import annotations

import os
from typing import Any, Protocol


class EngineClient(Protocol):
    """Storage path for workers — no direct StorageBackend access."""

    def call(self, op: str, **payload: Any) -> Any:
        """Dispatch an engine operation (put, get_tuple, list, ...)."""


class _StubEngineClient:
    """Placeholder until Unix-socket / HTTP transport is implemented."""

    def __init__(self, socket_path: str | None, http_url: str | None) -> None:
        self._socket_path = socket_path
        self._http_url = http_url

    def call(self, op: str, **payload: Any) -> Any:
        msg = (
            "EngineClient RPC is not implemented yet. "
            f"Would call op={op!r} agent_id={payload.get('agent_id')!r} "
            f"socket={self._socket_path!r} url={self._http_url!r}"
        )
        raise NotImplementedError(msg)


def connect_from_env() -> EngineClient:
    """Build client from HYPERBUS_SOCKET or HYPERBUS_ENGINE_URL."""
    socket_path = os.environ.get("HYPERBUS_SOCKET")
    http_url = os.environ.get("HYPERBUS_ENGINE_URL")
    if not socket_path and not http_url:
        msg = "Set HYPERBUS_SOCKET or HYPERBUS_ENGINE_URL for worker → engine RPC"
        raise RuntimeError(msg)
    return _StubEngineClient(socket_path, http_url)
