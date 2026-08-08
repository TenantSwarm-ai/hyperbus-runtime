"""Emit runtime audit events through the engine sidecar."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from hyperbus_runtime.client import EngineClient


def make_colocation_audit_emitter(
    client: EngineClient,
    *,
    tenant_id: str,
    agent_id: str,
) -> Callable[[str, dict[str, Any]], None]:
    def emit(event_type: str, detail: dict[str, Any]) -> None:
        client.call(
            "runtime.audit",
            tenant_id=tenant_id,
            agent_id=agent_id,
            kwargs={
                "event_type": event_type,
                "detail": detail,
            },
        )

    return emit
