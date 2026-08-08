"""Tests for runtime audit RPC."""

from __future__ import annotations

from hyperbus_runtime.client import _RpcTransportClient


def test_runtime_audit_emits_to_engine_store(engine_server_with_audit) -> None:
    url, _engine, audit = engine_server_with_audit
    client = _RpcTransportClient(http_url=url)
    result = client.call(
        "runtime.audit",
        tenant_id="acme",
        agent_id="support-bot",
        kwargs={
            "event_type": "colocation.group.join",
            "detail": {"group": "support-pool"},
        },
    )
    assert result == {"emitted": True}
    events = audit.events_for("acme")
    assert any(event.event_type == "colocation.group.join" for event in events)
