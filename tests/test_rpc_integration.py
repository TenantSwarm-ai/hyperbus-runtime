"""Tests for RPC dispatch and server integration."""

from __future__ import annotations

import pytest
from hyperbus_core import CapabilityError

from hyperbus_runtime.client import _RpcTransportClient
from hyperbus_runtime.rpc_dispatch import RpcValidationError, dispatch_request


def test_dispatch_put_and_get(engine_server) -> None:
    url, engine = engine_server
    client = _RpcTransportClient(http_url=url)
    client.call(
        "put",
        tenant_id="acme",
        agent_id="support-bot",
        args=["thread-1", "c1"],
        kwargs={
            "state": {"messages": ["hello"]},
            "metadata": {},
            "region": "support",
        },
    )
    record = client.call(
        "get",
        tenant_id="acme",
        agent_id="support-bot",
        args=["thread-1", "c1"],
        kwargs={"region": "support"},
    )
    assert record.state == {"messages": ["hello"]}
    assert engine is not None


def test_dispatch_denies_cross_region(engine_server) -> None:
    url, _engine = engine_server
    client = _RpcTransportClient(http_url=url)
    client.call(
        "put",
        tenant_id="acme",
        agent_id="billing-bot",
        args=["invoice-1", "c1"],
        kwargs={"state": {"total": 42}, "metadata": {}, "region": "billing"},
    )
    with pytest.raises(CapabilityError):
        client.call(
            "get",
            tenant_id="acme",
            agent_id="support-bot",
            args=["invoice-1", "c1"],
            kwargs={"region": "billing"},
        )


def test_dispatch_requires_agent_id(engine_server) -> None:
    url, engine = engine_server
    response = dispatch_request(
        engine,
        {"op": "runtime.ping", "tenant_id": "acme"},
        expected_tenant_id="acme",
    )
    assert response["ok"] is False
    assert response["error"]["type"] == "RpcValidationError"


def test_dispatch_rejects_spoofed_kwargs_agent_id(engine_server) -> None:
    url, engine = engine_server
    response = dispatch_request(
        engine,
        {
            "op": "runtime.ping",
            "tenant_id": "acme",
            "agent_id": "support-bot",
            "kwargs": {"agent_id": "billing-bot"},
        },
        expected_tenant_id="acme",
    )
    assert response["ok"] is False
    assert response["error"]["type"] == "RpcValidationError"


def test_dispatch_ping(engine_server) -> None:
    url, _engine = engine_server
    client = _RpcTransportClient(http_url=url)
    result = client.call(
        "runtime.ping",
        tenant_id="acme",
        agent_id="support-bot",
    )
    assert result == {"tenant_id": "acme"}


def test_connect_from_env_requires_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HYPERBUS_SOCKET", raising=False)
    monkeypatch.delenv("HYPERBUS_ENGINE_URL", raising=False)
    from hyperbus_runtime.client import connect_from_env

    with pytest.raises(RuntimeError, match="HYPERBUS_SOCKET"):
        connect_from_env(tenant_id="acme", agent_id="support-bot")
