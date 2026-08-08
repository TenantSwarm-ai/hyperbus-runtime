"""Tests for perf profile in-process engine."""

from __future__ import annotations

import pytest

from hyperbus_runtime.config import WorkerContext
from hyperbus_runtime.perf import create_local_engine, is_perf_profile
from hyperbus_runtime.worker import checkpointer, get_client


def test_is_perf_profile() -> None:
    assert is_perf_profile("perf") is True
    assert is_perf_profile("isolate") is False


def test_perf_checkpointer_uses_local_engine(
    grants_file,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HB_DEFAULT_REGION", "support")
    monkeypatch.setenv("HB_ISOLATION_PROFILE", "perf")
    monkeypatch.setenv("HB_GRANTS_FILE", str(grants_file))
    saver = checkpointer()
    assert saver.tenant_id == "acme"
    with pytest.raises(RuntimeError, match="perf profile"):
        get_client()


def test_create_local_engine_requires_grants(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = WorkerContext(tenant_id="acme", agent_id="support-bot", profile="perf")
    monkeypatch.delenv("HB_GRANTS_FILE", raising=False)
    with pytest.raises(RuntimeError, match="HB_GRANTS_FILE"):
        create_local_engine(ctx)


def test_create_local_engine_with_grants(grants_file, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = WorkerContext(tenant_id="acme", agent_id="support-bot", profile="perf")
    monkeypatch.setenv("HB_GRANTS_FILE", str(grants_file))
    engine = create_local_engine(ctx)
    assert engine.enforces_capabilities is True
