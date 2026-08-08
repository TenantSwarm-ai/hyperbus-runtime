"""Tests for hyperbus-runtime configuration and colocation policy."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hyperbus_runtime.config import ColocationPolicy, WorkerContext
from hyperbus_runtime import shared
from hyperbus_runtime.worker import bind_from_env


def test_worker_context_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HB_DEFAULT_REGION", "support")
    ctx = WorkerContext.from_env()
    assert ctx.tenant_id == "acme"
    assert ctx.agent_id == "support-bot"
    assert ctx.default_region == "support"
    assert ctx.langgraph_configurable()["hyperbus_agent_id"] == "support-bot"


def test_worker_context_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HB_TENANT_ID", raising=False)
    monkeypatch.delenv("HB_AGENT_ID", raising=False)
    with pytest.raises(RuntimeError, match="HB_TENANT_ID"):
        WorkerContext.from_env()


def test_isolate_profile_rejects_colocate_group() -> None:
    ctx = WorkerContext(
        tenant_id="acme",
        agent_id="billing-bot",
        profile="isolate",
        colocate_group="billing-pool",
    )
    with pytest.raises(RuntimeError, match="isolate profile"):
        ctx.validate_profile()


def test_pool_profile_requires_colocate_group() -> None:
    ctx = WorkerContext(
        tenant_id="acme",
        agent_id="support-bot",
        profile="pool",
    )
    with pytest.raises(RuntimeError, match="pool profile"):
        ctx.validate_profile()


def test_colocation_policy_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
tenant_id: acme
colocation_policy:
  default_profile: isolate
workers:
  - id: support-primary
    agent_id: support-bot
    profile: pool
    colocate_group: support-pool
groups:
  support-pool:
    max_workers: 4
    shared_ram: true
""",
        encoding="utf-8",
    )
    policy = ColocationPolicy.from_yaml(path)
    assert policy.tenant_id == "acme"
    assert policy.groups["support-pool"].shared_ram is True
    spec = policy.worker_spec("support-primary")
    assert spec is not None
    assert spec["agent_id"] == "support-bot"


def test_shared_namespace_forbidden_in_isolate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HB_ISOLATION_PROFILE", "isolate")
    bind_from_env()
    with pytest.raises(RuntimeError, match="isolate profile"):
        shared.namespace()


def test_shared_namespace_in_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HB_ISOLATION_PROFILE", "pool")
    monkeypatch.setenv("HB_COLOCATE_GROUP", "support-pool")
    bind_from_env()
    store = shared.namespace()
    store["ticket"] = 8812
    assert shared.namespace()["ticket"] == 8812
