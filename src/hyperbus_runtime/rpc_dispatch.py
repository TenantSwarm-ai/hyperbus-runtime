"""Dispatch RPC operations to HyperBusEngine."""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from typing import Any

from hyperbus_core import AuditEvent, AuditSink, CapabilityError, HyperBusEngine, TenantIsolationError

from hyperbus_runtime.async_runner import run_async
from hyperbus_runtime.rpc_codec import decode, encode
from hyperbus_runtime.rpc_ops import ALLOWED_ENGINE_OPS, ALLOWED_RUNTIME_AUDIT_EVENTS

_RUNTIME_OPS = frozenset({"runtime.ping", "runtime.audit"})


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
    if isinstance(exc, PermissionError):
        return {"type": "PermissionError", "message": str(exc)}
    if isinstance(exc, RpcError):
        return {"type": exc.error_type, "message": exc.message}
    return {"type": type(exc).__name__, "message": str(exc)}


def _validate_request(
    payload: dict[str, Any],
    *,
    expected_tenant_id: str,
    peer_agent_id: str | None = None,
) -> tuple[str, str, list[Any], dict[str, Any]]:
    op = payload.get("op")
    if not isinstance(op, str) or not op:
        raise RpcValidationError("RPC request requires non-empty op")
    if op not in ALLOWED_ENGINE_OPS and op not in _RUNTIME_OPS:
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
    if peer_agent_id is not None and peer_agent_id != agent_id:
        raise RpcValidationError(
            f"RPC agent_id {agent_id!r} != unix peer mapped {peer_agent_id!r}"
        )

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


def _dispatch_runtime(
    op: str,
    *,
    audit: AuditSink | None,
    tenant_id: str,
    agent_id: str,
    kwargs: dict[str, Any],
) -> Any:
    if op == "runtime.ping":
        return {"tenant_id": tenant_id}
    if op == "runtime.audit":
        if audit is None:
            msg = "engine audit sink is not configured"
            raise RpcValidationError(msg)
        event_type = kwargs.get("event_type")
        detail = kwargs.get("detail") or {}
        if not isinstance(event_type, str) or not event_type:
            raise RpcValidationError("runtime.audit requires event_type")
        if event_type not in ALLOWED_RUNTIME_AUDIT_EVENTS:
            raise RpcValidationError(f"runtime.audit event_type {event_type!r} not allowed")
        if not isinstance(detail, dict):
            raise RpcValidationError("runtime.audit detail must be a dict")
        audit.emit(
            AuditEvent(
                event_type=event_type,
                tenant_id=tenant_id,
                agent_id=agent_id,
                detail=detail,
                at=datetime.now(timezone.utc),
            )
        )
        return {"emitted": True}
    msg = f"Unsupported runtime op {op!r}"
    raise RpcValidationError(msg)


def dispatch_request(
    engine: HyperBusEngine,
    payload: dict[str, Any],
    *,
    expected_tenant_id: str,
    audit: AuditSink | None = None,
    peer_agent_id: str | None = None,
) -> dict[str, Any]:
    """Execute one RPC request and return a response envelope."""
    try:
        op, _agent_id, args, kwargs = _validate_request(
            payload,
            expected_tenant_id=expected_tenant_id,
            peer_agent_id=peer_agent_id,
        )
        if op in _RUNTIME_OPS:
            result = _dispatch_runtime(
                op,
                audit=audit,
                tenant_id=expected_tenant_id,
                agent_id=_agent_id,
                kwargs=kwargs,
            )
            return {"ok": True, "result": encode(result)}
        method = getattr(engine, op)
        if inspect.iscoroutinefunction(method):
            result = run_async(method(*args, **kwargs))
        else:
            result = method(*args, **kwargs)
        return {"ok": True, "result": encode(result)}
    except Exception as exc:  # noqa: BLE001 - mapped to RPC envelope
        return {"ok": False, "error": _rpc_error_payload(exc)}
