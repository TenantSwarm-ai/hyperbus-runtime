"""Verified mode over a real Unix socket: the kernel-reported peer uid decides (spec 003 US-2, US-3).

The test process connects as itself, so its real uid is the credential. Reloads
change which uid the map trusts, and the next call must follow that change.
"""

from __future__ import annotations

import socket
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from hyperbus_core import HyperBusEngine, InMemoryAuditStore, InMemoryBackend

from hyperbus_runtime.client import _RpcTransportClient
from hyperbus_runtime.grants import load_grants_yaml
from hyperbus_runtime import rpc_server as rpc_server_module
from hyperbus_runtime.identity_gate import IdentityGate
from hyperbus_runtime.rpc_server import UnixRpcServer
from identity_helpers import current_uid, make_rsa_key, standard_map_yaml, write_json

requires_unix = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix sockets unavailable")
# Verified Unix binding reads SO_PEERCRED, which this build supports on Linux
# only (001 AC-6.1). Elsewhere the binding fails closed; see the last test.
requires_peer_cred = pytest.mark.skipif(
    getattr(socket, "SO_PEERCRED", None) is None,
    reason="verified Unix binding needs SO_PEERCRED (Linux, 001 AC-6.1)",
)


@dataclass
class VerifiedUnix:
    client: _RpcTransportClient
    gate: IdentityGate
    audit: InMemoryAuditStore
    map_path: Path
    jwks_path: Path


def _map_text(jwks_path: Path, uid: int) -> str:
    return standard_map_yaml(jwks_path, support_uid=uid)


@pytest.fixture
def verified_unix(tmp_path: Path, grants_file: Path) -> Iterator[VerifiedUnix]:
    _private, jwks = make_rsa_key()
    jwks_path = write_json(tmp_path / "jwks.json", jwks)
    map_path = tmp_path / "identity.yaml"
    map_path.write_text(_map_text(jwks_path, current_uid()), encoding="utf-8")
    audit = InMemoryAuditStore()
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=audit)
    gate.start()
    registry = load_grants_yaml(grants_file, tenant_id="acme")
    engine = HyperBusEngine("acme", InMemoryBackend(), registry)
    socket_path = f"/tmp/hb-identity-{uuid.uuid4().hex[:12]}.sock"
    server = UnixRpcServer(socket_path, engine=engine, tenant_id="acme", gate=gate)
    server.start()
    try:
        yield VerifiedUnix(
            client=_RpcTransportClient(socket_path=socket_path),
            gate=gate,
            audit=audit,
            map_path=map_path,
            jwks_path=jwks_path,
        )
    finally:
        server.stop()
        gate.close()


def _denials(audit: InMemoryAuditStore) -> list[dict[str, object]]:
    return [dict(event.detail) for event in audit.events if event.event_type == "identity.denied"]


@requires_unix
@requires_peer_cred
def test_mapped_peer_uid_writes_and_reads_its_region(verified_unix: VerifiedUnix) -> None:
    client = verified_unix.client
    client.call(
        "put",
        tenant_id="acme",
        agent_id="support-bot",
        args=["thread-1", "c1"],
        kwargs={"state": {"messages": ["hi"]}, "metadata": {}, "region": "support"},
    )
    record = client.call(
        "get",
        tenant_id="acme",
        agent_id="support-bot",
        args=["thread-1", "c1"],
        kwargs={"region": "support"},
    )
    assert record.state == {"messages": ["hi"]}


@requires_unix
@requires_peer_cred
def test_declared_agent_cannot_speak_for_another_agent(verified_unix: VerifiedUnix) -> None:
    with pytest.raises(PermissionError, match="body_agent_mismatch"):
        verified_unix.client.call(
            "get",
            tenant_id="acme",
            agent_id="billing-bot",
            args=["thread-1", "c1"],
            kwargs={"region": "billing"},
        )
    denial = _denials(verified_unix.audit)[-1]
    assert denial["reason"] == "body_agent_mismatch"
    assert denial["transport"] == "unix"
    assert denial["declared_agent_id"] == "billing-bot"
    assert denial["identity"] == f"uid:{current_uid()}"


@requires_unix
@requires_peer_cred
def test_reload_that_drops_the_uid_denies_the_next_call(verified_unix: VerifiedUnix) -> None:
    verified_unix.map_path.write_text(
        _map_text(verified_unix.jwks_path, current_uid() + 1), encoding="utf-8"
    )
    verified_unix.gate.reload()

    with pytest.raises(PermissionError, match="uid_unmapped"):
        verified_unix.client.call(
            "get",
            tenant_id="acme",
            agent_id="support-bot",
            args=["thread-1", "c1"],
            kwargs={"region": "support"},
        )

    verified_unix.map_path.write_text(
        _map_text(verified_unix.jwks_path, current_uid()), encoding="utf-8"
    )
    verified_unix.gate.reload()
    result = verified_unix.client.call(
        "get",
        tenant_id="acme",
        agent_id="support-bot",
        args=["thread-1", "c1"],
        kwargs={"region": "support"},
    )
    assert result is None


@requires_unix
@requires_peer_cred
def test_invalid_reload_denies_every_call_until_repaired(verified_unix: VerifiedUnix) -> None:
    verified_unix.map_path.write_text("tenant_id: acme\nagents: [oops\n", encoding="utf-8")
    verified_unix.gate.reload()

    with pytest.raises(PermissionError, match="map_rejected"):
        verified_unix.client.call(
            "get",
            tenant_id="acme",
            agent_id="support-bot",
            args=["thread-1", "c1"],
            kwargs={"region": "support"},
        )
    rejected = [e for e in verified_unix.audit.events if e.event_type == "identity.map_rejected"]
    assert rejected

    verified_unix.map_path.write_text(
        _map_text(verified_unix.jwks_path, current_uid()), encoding="utf-8"
    )
    verified_unix.gate.reload()
    assert verified_unix.gate.deny_reason is None


@requires_unix
def test_unix_call_without_peer_credentials_is_refused_end_to_end(
    verified_unix: VerifiedUnix, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed where the platform gives no peer credentials. Runs on every OS."""
    monkeypatch.setattr(rpc_server_module, "read_peer_identity", lambda _conn: None)
    with pytest.raises(PermissionError, match="no_peer_credentials"):
        verified_unix.client.call(
            "get",
            tenant_id="acme",
            agent_id="support-bot",
            args=["thread-1", "c1"],
            kwargs={"region": "support"},
        )
    assert _denials(verified_unix.audit)[-1]["reason"] == "no_peer_credentials"
