"""Tests for worker identity binding and runtime checkpointer."""

from __future__ import annotations

import pytest
from hyperbus_core import CapabilityError
from langgraph.checkpoint.base import Checkpoint, CheckpointMetadata

from hyperbus_runtime.client import _RpcTransportClient
from hyperbus_runtime.worker import bind_from_env, checkpointer, inject_langgraph_config


def _support_env(monkeypatch: pytest.MonkeyPatch, engine_url: str) -> None:
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HB_DEFAULT_REGION", "support")
    monkeypatch.setenv("HB_ISOLATION_PROFILE", "isolate")
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", engine_url)


def test_identity_bound_saver_ignores_spoofed_agent_id(
    engine_server,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, _engine = engine_server
    _support_env(monkeypatch, url)
    saver = checkpointer()
    config = {
        "configurable": {
            "thread_id": "ticket-8812",
            "hyperbus_agent_id": "billing-bot",
            "hyperbus_region": "billing",
        }
    }
    checkpoint: Checkpoint = {
        "v": 1,
        "id": "c-spoof-test",
        "ts": "2026-01-01T00:00:00Z",
        "channel_values": {},
        "channel_versions": {},
        "versions_seen": {},
        "updated_channels": set(),
    }
    metadata: CheckpointMetadata = {"source": "test", "step": 1, "writes": {}}
    saver.put(config, checkpoint, metadata, {})
    with pytest.raises(CapabilityError):
        _RpcTransportClient(http_url=url).call(
            "get",
            tenant_id="acme",
            agent_id="support-bot",
            args=["ticket-8812", "c-spoof-test"],
            kwargs={"region": "billing"},
        )


def test_inject_langgraph_config_overrides_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HB_DEFAULT_REGION", "support")
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "http://127.0.0.1:1")
    merged = inject_langgraph_config(
        {"configurable": {"hyperbus_agent_id": "billing-bot", "thread_id": "t1"}}
    )
    assert merged["configurable"]["hyperbus_agent_id"] == "support-bot"
    assert merged["configurable"]["hyperbus_region"] == "support"
    assert merged["configurable"]["thread_id"] == "t1"


def test_checkpointer_put_and_get_tuple(
    engine_server,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, _engine = engine_server
    _support_env(monkeypatch, url)
    saver = checkpointer()
    config = {"configurable": {"thread_id": "ticket-1"}}
    checkpoint: Checkpoint = {
        "v": 1,
        "id": "c1",
        "ts": "2026-01-01T00:00:00Z",
        "channel_values": {"messages": []},
        "channel_versions": {"messages": 1},
        "versions_seen": {},
        "updated_channels": {"messages"},
    }
    metadata: CheckpointMetadata = {"source": "test", "step": 1, "writes": {}}
    saved = saver.put(config, checkpoint, metadata, {})
    assert saved["id"] == "c1"
    loaded = saver.get_tuple(config)
    assert loaded is not None
    assert loaded.checkpoint["id"] == "c1"


def test_bind_from_env_records_colocation_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hyperbus_runtime import shared

    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HB_ISOLATION_PROFILE", "pool")
    monkeypatch.setenv("HB_COLOCATE_GROUP", "support-pool")
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "http://127.0.0.1:1")
    bind_from_env()
    events = shared.audit_events()
    assert any(event["event_type"] == "colocation.group.join" for event in events)
    assert any(event["event_type"] == "colocation.ram.shared" for event in events)
