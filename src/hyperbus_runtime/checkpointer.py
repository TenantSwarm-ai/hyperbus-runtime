"""Identity-bound LangGraph checkpointer over the engine sidecar."""

from __future__ import annotations

from typing import Any

from hyperbus_core import HyperBusEngine, InMemoryBackend
from hyperbus_langgraph import HyperBusSaver
from langchain_core.runnables import RunnableConfig

from hyperbus_runtime.client import EngineClient
from hyperbus_runtime.config import WorkerContext
from hyperbus_runtime.remote_engine import RemoteHyperBusEngine


class IdentityBoundSaver(HyperBusSaver):
    """HyperBusSaver that always authorizes with worker-bound identity."""

    def __init__(
        self,
        ctx: WorkerContext,
        client: EngineClient | None = None,
        *,
        local_engine: HyperBusEngine | None = None,
    ) -> None:
        super().__init__(
            tenant_id=ctx.tenant_id,
            backend=InMemoryBackend(),
            capabilities=None,
            region=ctx.default_region,
            agent_id=ctx.agent_id,
        )
        self._worker_ctx = ctx
        if local_engine is not None:
            self._engine = local_engine
        else:
            if client is None:
                msg = "IdentityBoundSaver requires EngineClient or local_engine"
                raise ValueError(msg)
            self._engine = RemoteHyperBusEngine(
                client,
                tenant_id=ctx.tenant_id,
                bound_agent_id=ctx.agent_id,
            )

    def _scope_of(self, config: RunnableConfig | None) -> dict[str, Any]:
        _ = config
        return {
            "region": self._worker_ctx.default_region,
            "agent_id": self._worker_ctx.agent_id,
        }
