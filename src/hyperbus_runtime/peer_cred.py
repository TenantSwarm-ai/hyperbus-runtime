"""Unix peer credential helpers for RPC identity binding."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class PeerIdentity:
    pid: int
    uid: int
    gid: int


def read_peer_identity(conn: socket.socket) -> PeerIdentity | None:
    """Return peer pid/uid/gid when the platform exposes SO_PEERCRED."""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        return None
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
        return PeerIdentity(pid=pid, uid=uid, gid=gid)
    except OSError:
        return None


def load_peer_agent_map(path: str | Path | None) -> dict[int, str]:
    """Load uid→agent_id map from YAML or env-style file."""
    if path is None:
        return {}
    raw: Any = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not raw:
        return {}
    mapping = raw.get("peer_agents") if isinstance(raw, dict) else raw
    if not isinstance(mapping, dict):
        msg = "peer agent map must be a uid→agent_id mapping"
        raise ValueError(msg)
    return {int(uid): str(agent_id) for uid, agent_id in mapping.items()}


def resolve_agent_id(
    *,
    declared_agent_id: str,
    peer: PeerIdentity | None,
    peer_agent_map: dict[int, str],
) -> str:
    """Bind RPC agent_id from peer credentials when a map is configured."""
    if not peer_agent_map:
        return declared_agent_id
    if peer is None:
        msg = (
            "peer agent map is configured but unix peer credentials are unavailable; "
            "refusing RPC"
        )
        raise PermissionError(msg)
    mapped = peer_agent_map.get(peer.uid)
    if mapped is None:
        msg = f"unix peer uid {peer.uid} is not mapped to an agent_id"
        raise PermissionError(msg)
    if mapped != declared_agent_id:
        msg = (
            f"unix peer uid {peer.uid} maps to {mapped!r}, "
            f"but RPC declared {declared_agent_id!r}"
        )
        raise PermissionError(msg)
    return mapped
