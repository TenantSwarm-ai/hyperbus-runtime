"""Tests for async RPC dispatch paths."""

from __future__ import annotations

from hyperbus_runtime.client import _RpcTransportClient


def test_async_engine_op_via_rpc(engine_server) -> None:
    url, _engine = engine_server
    client = _RpcTransportClient(http_url=url)
    client.call(
        "put",
        tenant_id="acme",
        agent_id="support-bot",
        args=["thread-async", "c1"],
        kwargs={"state": {"x": 1}, "metadata": {}, "region": "support"},
    )
    refs = client.call(
        "alist_checkpoint_refs",
        tenant_id="acme",
        agent_id="support-bot",
        args=["thread-async"],
        kwargs={"region": "support"},
    )
    assert refs[0].checkpoint_id == "c1"
