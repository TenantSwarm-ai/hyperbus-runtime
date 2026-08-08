"""Tests for colocation group enforcement."""

from __future__ import annotations

import pytest

from hyperbus_runtime.colocation import ColocationAccessError, assert_namespace_access
from hyperbus_runtime.config import ColocationGroup, ColocationPolicy, WorkerContext
from hyperbus_runtime import shared


def test_cross_group_namespace_denied_without_policy() -> None:
    ctx = WorkerContext(
        tenant_id="acme",
        agent_id="support-bot",
        profile="pool",
        colocate_group="support-pool",
    )
    with pytest.raises(ColocationAccessError):
        assert_namespace_access(ctx, None, "billing-solo")


def test_cross_group_allowed_with_policy_override() -> None:
    policy = ColocationPolicy(
        tenant_id="acme",
        groups={
            "support-pool": ColocationGroup(
                name="support-pool",
                shared_ram=True,
                allow_ram_share_with=["billing-solo"],
            ),
            "billing-solo": ColocationGroup(name="billing-solo"),
        },
    )
    ctx = WorkerContext(
        tenant_id="acme",
        agent_id="support-bot",
        profile="pool",
        colocate_group="support-pool",
    )
    assert_namespace_access(ctx, policy, "billing-solo")


def test_shared_namespace_blocks_cross_group_by_default(
    colocation_policy_file,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HB_ISOLATION_PROFILE", "pool")
    monkeypatch.setenv("HB_COLOCATE_GROUP", "support-pool")
    monkeypatch.setenv("HB_COLOCATION_POLICY", str(colocation_policy_file))
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "http://127.0.0.1:1")
    from hyperbus_runtime.worker import bind_from_env

    bind_from_env()
    shared.namespace()["secret"] = 42
    with pytest.raises(RuntimeError, match="may not share RAM"):
        shared.namespace("billing-solo")


def test_shared_ram_false_blocks_home_namespace(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
tenant_id: acme
groups:
  billing-solo:
    shared_ram: false
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "billing-bot")
    monkeypatch.setenv("HB_ISOLATION_PROFILE", "pool")
    monkeypatch.setenv("HB_COLOCATE_GROUP", "billing-solo")
    monkeypatch.setenv("HB_COLOCATION_POLICY", str(policy_path))
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "http://127.0.0.1:1")
    from hyperbus_runtime.worker import bind_from_env

    bind_from_env()
    with pytest.raises(RuntimeError, match="shared_ram=false"):
        shared.namespace()


def test_shared_namespace_override_emits_audit(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
tenant_id: acme
groups:
  support-pool:
    shared_ram: true
    allow_ram_share_with: [billing-solo]
  billing-solo:
    shared_ram: false
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HB_ISOLATION_PROFILE", "pool")
    monkeypatch.setenv("HB_COLOCATE_GROUP", "support-pool")
    monkeypatch.setenv("HB_COLOCATION_POLICY", str(policy_path))
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "http://127.0.0.1:1")
    from hyperbus_runtime.worker import bind_from_env

    bind_from_env()
    store = shared.namespace("billing-solo")
    store["linked"] = True
    events = shared.audit_events()
    assert any(event["event_type"] == "colocation.policy.override" for event in events)
