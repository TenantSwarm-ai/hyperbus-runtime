"""Dispatch RPC operations to HyperBusEngine."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

from hyperbus_core import CapabilityError, HyperBusEngine, TenantIsolationError

from hyperbus_runtime.rpc_codec import decode, encode

_PUBLIC_ENGINE_OPS = {
    name
    for name, member in inspect.getmembers(HyperBusEngine)
    if not name.startswith("_")
    and callable(member)
    and name
    not in {
        "channel_region_map",
        "tenant_id",
        "enforces_capabilities",
    }
}


class RpcError(Exception):
    """Base class for RPC-layer failures."""

    error_type: str = "RpcError"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class RpcValidationError(RpcError):
    error_type = "RpcValidationError"


def _rpc_error_payload(exc: BaseException) -> dict[str, str]:
    if isinstance(exc, CapabilityError):
        return {"type": "CapabilityError", "message": str(exc)}
    if isinstance(exc, TenantIsolationError):
        return {"type": "TenantIsolationError", "message": str(exc)}
    if isinstance(exc, RpcError):
        return {"type": exc.error_type, "message": exc.message}
    return {"type": type(exc).__name__, "message": str(exc)}


def _validate_request(
    payload: dict[str, Any],
    *,
    expected_tenant_id: str,
) -> tuple[str, str, list[Any], dict[str, Any]]:
    op = payload.get("op")
    if not isinstance(op, str) or not op:
        raise RpcValidationError("RPC request requires non-empty op")
    if op not in _PUBLIC_ENGINE_OPS and op != "runtime.ping":
        raise RpcValidationError(f"Unsupported engine op {op!r}")

    tenant_id = payload.get("tenant_id")
    agent_id = payload.get("agent_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise RpcValidationError("RPC request requires tenant_id")
    if tenant_id != expected_tenant_id:
        raise RpcValidationError(
            f"tenant_id {tenant_id!r} != engine tenant {expected_tenant_id!r}"
        )
    if not isinstance(agent_id, str) or not agent_id:
        raise RpcValidationError("RPC request requires agent_id")

    raw_args = payload.get("args", [])
    raw_kwargs = payload.get("kwargs", {})
    if not isinstance(raw_args, list):
        raise RpcValidationError("args must be a list")
    if not isinstance(raw_kwargs, dict):
        raise RpcValidationError("kwargs must be a dict")

    kwargs = decode(raw_kwargs)
    if "agent_id" in kwargs and kwargs["agent_id"] != agent_id:
        raise RpcValidationError("kwargs agent_id must match request agent_id")
    kwargs["agent_id"] = agent_id
    return op, agent_id, decode(raw_args), kwargs


def dispatch_request(
    engine: HyperBusEngine,
    payload: dict[str, Any],
    *,
    expected_tenant_id: str,
) -> dict[str, Any]:
    """Execute one RPC request and return a response envelope."""
    try:
        op, _agent_id, args, kwargs = _validate_request(
            payload,
            expected_tenant_id=expected_tenant_id,
        )
        if op == "runtime.ping":
            return {"ok": True, "result": {"tenant_id": expected_tenant_id}}
        method = getattr(engine, op)
        if inspect.iscoroutinefunction(method):
            result = asyncio.run(method(*args, **kwargs))
        else:
            result = method(*args, **kwargs)
        return {"ok": True, "result": encode(result)}
    except Exception as exc:  # noqa: BLE001 - mapped to RPC envelope
        return {"ok": False, "error": _rpc_error_payload(exc)}
