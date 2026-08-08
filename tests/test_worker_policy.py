"""Tests for worker policy validation and client error mapping."""

from __future__ import annotations

import pytest

from hyperbus_runtime.client import _RpcTransportClient
from hyperbus_runtime.worker import bind_from_env


def test_bind_from_env_rejects_policy_tenant_mismatch(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("tenant_id: other\nworkers: []\n", encoding="utf-8")
    monkeypatch.setenv("HB_TENANT_ID", "acme")
    monkeypatch.setenv("HB_AGENT_ID", "support-bot")
    monkeypatch.setenv("HB_COLOCATION_POLICY", str(policy))
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "http://127.0.0.1:1")
    with pytest.raises(RuntimeError, match="policy tenant"):
        bind_from_env()


def test_client_raises_generic_rpc_error() -> None:
    client = _RpcTransportClient(http_url="http://127.0.0.1:1")

    def fake_post(_payload):
        return {"ok": False, "error": {"type": "Boom", "message": "failed"}}

    client._post = fake_post  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="Boom"):
        client.call(
            "runtime.ping",
            tenant_id="acme",
            agent_id="support-bot",
        )
