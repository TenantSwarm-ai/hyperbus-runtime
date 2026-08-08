"""Tests for peer credential identity binding."""

from __future__ import annotations

from pathlib import Path

import pytest

from hyperbus_runtime.peer_cred import (
    PeerIdentity,
    load_peer_agent_map,
    read_peer_identity,
    resolve_agent_id,
)


def test_load_peer_agent_map(tmp_path: Path) -> None:
    path = tmp_path / "map.yaml"
    path.write_text("peer_agents:\n  995: support-bot\n", encoding="utf-8")
    assert load_peer_agent_map(path) == {995: "support-bot"}


def test_resolve_agent_id_without_map() -> None:
    assert (
        resolve_agent_id(
            declared_agent_id="support-bot",
            peer=PeerIdentity(pid=1, uid=995, gid=995),
            peer_agent_map={},
        )
        == "support-bot"
    )


def test_resolve_agent_id_fail_closed_without_peer() -> None:
    with pytest.raises(PermissionError, match="peer credentials are unavailable"):
        resolve_agent_id(
            declared_agent_id="support-bot",
            peer=None,
            peer_agent_map={995: "support-bot"},
        )


def test_resolve_agent_id_rejects_unmapped_uid() -> None:
    with pytest.raises(PermissionError, match="not mapped"):
        resolve_agent_id(
            declared_agent_id="support-bot",
            peer=PeerIdentity(pid=1, uid=999, gid=999),
            peer_agent_map={995: "support-bot"},
        )


def test_resolve_agent_id_rejects_spoofed_declaration() -> None:
    with pytest.raises(PermissionError, match="maps to"):
        resolve_agent_id(
            declared_agent_id="billing-bot",
            peer=PeerIdentity(pid=1, uid=995, gid=995),
            peer_agent_map={995: "support-bot"},
        )


def test_read_peer_identity_returns_none_without_option() -> None:
    import socket
    from unittest.mock import patch

    client, server = socket.socketpair()
    try:
        with patch("hyperbus_runtime.peer_cred.socket.SO_PEERCRED", None, create=True):
            assert read_peer_identity(server) is None
    finally:
        client.close()
        server.close()
