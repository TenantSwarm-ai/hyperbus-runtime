"""Tests for RPC server edge cases and HTTP handler paths."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from hyperbus_runtime.rpc_server import HttpRpcServer, RpcHttpHandler


def test_http_handler_rejects_non_rpc_path(engine_server) -> None:
    url, _engine = engine_server
    request = urllib.request.Request(
        f"{url}/health",
        data=b"{}",
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(request, timeout=5)
    assert exc.value.code == 404


def test_http_handler_rejects_invalid_json(engine_server) -> None:
    url, _engine = engine_server
    request = urllib.request.Request(
        f"{url}/rpc",
        data=b"{not-json",
        headers={
            "Content-Type": "application/json",
            "X-HyperBus-Token": "test-rpc-token",
        },
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(request, timeout=5)
    assert exc.value.code == 400


def test_http_handler_rejects_missing_token(engine_server) -> None:
    url, _engine = engine_server
    body = json.dumps(
        {
            "op": "runtime.ping",
            "tenant_id": "acme",
            "agent_id": "support-bot",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{url}/rpc",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(request, timeout=5)
    assert exc.value.code == 401


def test_http_handler_accepts_valid_request(engine_server) -> None:
    url, _engine = engine_server
    body = json.dumps(
        {
            "op": "runtime.ping",
            "tenant_id": "acme",
            "agent_id": "support-bot",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{url}/rpc",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-HyperBus-Token": "test-rpc-token",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
    assert payload["ok"] is True


def test_rpc_http_handler_log_message_is_silent() -> None:
    handler = RpcHttpHandler.__new__(RpcHttpHandler)
    handler.log_message("ignored %s", "message")
