"""Remote HyperBusEngine proxy backed by EngineClient RPC."""

from __future__ import annotations

from typing import Any

from hyperbus_runtime.client import EngineClient


class RemoteHyperBusEngine:
    """Drop-in engine replacement for HyperBusSaver in worker processes."""

    def __init__(
        self,
        client: EngineClient,
        *,
        tenant_id: str,
        bound_agent_id: str,
    ) -> None:
        self._client = client
        self._tenant_id = tenant_id
        self._bound_agent_id = bound_agent_id

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            msg = f"{type(self).__name__!r} object has no attribute {name!r}"
            raise AttributeError(msg)

        def _call(*args: Any, **kwargs: Any) -> Any:
            kwargs.setdefault("agent_id", self._bound_agent_id)
            if kwargs.get("agent_id") != self._bound_agent_id:
                msg = (
                    f"Remote engine calls must use bound agent "
                    f"{self._bound_agent_id!r}, got {kwargs.get('agent_id')!r}"
                )
                raise RuntimeError(msg)
            return self._client.call(
                name,
                tenant_id=self._tenant_id,
                agent_id=self._bound_agent_id,
                args=list(args),
                kwargs=kwargs,
            )

        return _call
