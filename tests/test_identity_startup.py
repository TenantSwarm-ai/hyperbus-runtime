"""Startup refusals, HTTP credential wiring, client header, and reload plumbing (spec 003)."""

from __future__ import annotations

import json
import socket
import ssl
import threading
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from hyperbus_core import HyperBusEngine, InMemoryAuditStore, InMemoryBackend

from hyperbus_runtime.client import _RpcTransportClient
from hyperbus_runtime.engine_daemon import _reload_on_signal, validate_identity_startup
from hyperbus_runtime.grants import load_grants_yaml
from hyperbus_runtime.identity_gate import IdentityConfigError, IdentityGate
from hyperbus_runtime.rpc_server import HttpRpcServer, _bearer_token, _peer_cert
from hyperbus_runtime.tls import load_client_ssl_context, load_server_ssl_context
from identity_helpers import (
    SUPPORT_SPIFFE,
    base_claims,
    make_rsa_key,
    make_tls_pair,
    sign,
    standard_map_yaml,
    write_json,
)


def _startup(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "mode": "verified",
        "listen": None,
        "peer_agent_map_path": None,
        "identity_map_path": Path("/etc/hyperbus/identity.yaml"),
        "durable_audit": True,
        "allow_volatile_grants": False,
        "audit_checkpoint_given": True,
    }
    values.update(overrides)
    return values


# --- startup guard (AC-1.4, AC-6.3) --------------------------------------


def test_declared_mode_skips_identity_checks() -> None:
    validate_identity_startup(
        **_startup(
            mode="declared",
            listen="0.0.0.0:9000",
            identity_map_path=None,
            durable_audit=False,
        )
    )


def test_verified_mode_refuses_a_plaintext_http_listener() -> None:
    with pytest.raises(IdentityConfigError, match="TLS"):
        validate_identity_startup(**_startup(listen="127.0.0.1:9000"))


def test_verified_mode_accepts_an_http_listener_with_tls() -> None:
    validate_identity_startup(**_startup(listen="127.0.0.1:9000", tls_configured=True))


def test_tls_flags_without_a_listener_are_refused() -> None:
    with pytest.raises(IdentityConfigError, match="--listen"):
        validate_identity_startup(**_startup(mode="declared", tls_configured=True))


def test_verified_mode_refuses_the_legacy_peer_agent_map(tmp_path: Path) -> None:
    with pytest.raises(IdentityConfigError, match="--peer-agent-map"):
        validate_identity_startup(**_startup(peer_agent_map_path=tmp_path / "peers.yaml"))


def test_verified_mode_requires_an_identity_map() -> None:
    with pytest.raises(IdentityConfigError, match="requires --identity-map"):
        validate_identity_startup(**_startup(identity_map_path=None))


def test_verified_mode_requires_durable_audit_without_the_dev_flag() -> None:
    with pytest.raises(IdentityConfigError, match="durable grant audit"):
        validate_identity_startup(**_startup(durable_audit=False, allow_volatile_grants=False))


def test_volatile_grants_dev_flag_allows_verified_mode_without_durable_audit() -> None:
    validate_identity_startup(**_startup(durable_audit=False, allow_volatile_grants=True))


def test_verified_unix_socket_with_durable_audit_is_accepted() -> None:
    validate_identity_startup(**_startup())


def test_verified_durable_audit_requires_an_audit_checkpoint() -> None:
    with pytest.raises(IdentityConfigError, match="--audit-checkpoint"):
        validate_identity_startup(**_startup(audit_checkpoint_given=False))


def test_volatile_dev_path_needs_no_audit_checkpoint() -> None:
    validate_identity_startup(
        **_startup(durable_audit=False, allow_volatile_grants=True, audit_checkpoint_given=False)
    )


# --- HTTP transport refuses verified identity without TLS ----------------


@pytest.fixture
def engine(grants_file: Path) -> HyperBusEngine:
    registry = load_grants_yaml(grants_file, tenant_id="acme")
    return HyperBusEngine("acme", InMemoryBackend(), registry)


def test_http_server_refuses_gate_without_tls(engine: HyperBusEngine, tmp_path: Path) -> None:
    gate = IdentityGate(tenant_id="acme", map_path=tmp_path / "identity.yaml")
    with pytest.raises(IdentityConfigError, match="TLS"):
        HttpRpcServer("127.0.0.1", 0, engine=engine, tenant_id="acme", gate=gate)


# --- bearer and certificate extraction (AC-1.1, AC-1.5) ------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, None),
        ("", None),
        ("Bearer abc", "abc"),
        ("bearer   abc  ", "abc"),
        ("Bearer", None),
        ("Bearer ", None),
        ("Basic dXNlcjpwYXNz", None),
    ],
)
def test_bearer_token_extraction(header: str | None, expected: str | None) -> None:
    assert _bearer_token(header) == expected


class _TlsSocket:
    def __init__(self, cert: Any) -> None:
        self._cert = cert

    def getpeercert(self) -> Any:
        return self._cert


def test_plain_socket_has_no_peer_certificate() -> None:
    left, right = socket.socketpair()
    try:
        assert _peer_cert(left) is None
    finally:
        left.close()
        right.close()


def test_peer_certificate_is_returned_only_when_it_is_a_mapping() -> None:
    cert = {"subjectAltName": (("URI", SUPPORT_SPIFFE),)}
    assert _peer_cert(cast(socket.socket, _TlsSocket(cert))) == cert
    assert _peer_cert(cast(socket.socket, _TlsSocket(None))) is None
    assert _peer_cert(cast(socket.socket, _TlsSocket("not-a-dict"))) is None


# --- client sends the bearer (AC-1.5) ------------------------------------


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


@pytest.fixture
def captured_requests(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[dict[str, str]]]:
    seen: list[dict[str, str]] = []
    body = json.dumps({"ok": True, "result": {"tenant_id": "acme"}}).encode("utf-8")

    def fake_urlopen(
        request: urllib.request.Request,
        timeout: float | None = None,
        context: ssl.SSLContext | None = None,
    ) -> _FakeResponse:
        seen.append(dict(request.header_items()))
        return _FakeResponse(body)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    yield seen


def test_client_sends_identity_token_as_bearer(
    captured_requests: list[dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    # urlopen is stubbed, so no socket opens. A bearer only leaves over https (AC-1.4).
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    client = _RpcTransportClient(
        http_url="https://127.0.0.1:1",
        identity_token="tok-123",
        ssl_context=ssl.create_default_context(),
    )
    client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")
    assert captured_requests[-1]["Authorization"] == "Bearer tok-123"


def test_client_reads_identity_token_from_environment(
    captured_requests: list[dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HYPERBUS_IDENTITY_TOKEN", "from-env")
    client = _RpcTransportClient(
        http_url="https://127.0.0.1:1",
        ssl_context=ssl.create_default_context(),
    )
    client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")
    assert captured_requests[-1]["Authorization"] == "Bearer from-env"


def test_client_omits_authorization_in_declared_mode(
    captured_requests: list[dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    client = _RpcTransportClient(http_url="http://127.0.0.1:1")
    client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")
    assert "Authorization" not in captured_requests[-1]


# --- HTTP handler wiring over TLS (AC-1.1, AC-1.2, AC-1.3, AC-1.4) -------
#
# The server wraps its own sockets in TLS, so these tests run every credential
# over a real handshake against a self-signed listener certificate.


@pytest.fixture
def verified_http(
    tmp_path: Path, grants_file: Path, engine: HyperBusEngine
) -> Iterator[tuple[str, Any, ssl.SSLContext]]:
    private, jwks = make_rsa_key()
    jwks_path = write_json(tmp_path / "jwks.json", jwks)
    map_path = tmp_path / "identity.yaml"
    map_path.write_text(standard_map_yaml(jwks_path), encoding="utf-8")
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=InMemoryAuditStore())
    gate.start()
    cert, key = make_tls_pair(tmp_path)
    server = HttpRpcServer(
        "127.0.0.1",
        0,
        engine=engine,
        tenant_id="acme",
        gate=gate,
        ssl_context=load_server_ssl_context(cert_path=cert, key_path=key),
    )
    server.start()
    host, port = server.address
    try:
        yield f"https://{host}:{port}", private, load_client_ssl_context(ca_path=cert)
    finally:
        server.stop()
        gate.close()


def test_verified_bearer_reaches_the_engine(
    verified_http: tuple[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    url, private, tls = verified_http
    token = sign(private, base_claims(oid="oid-support"))
    client = _RpcTransportClient(http_url=url, identity_token=token, ssl_context=tls)
    result = client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")
    assert result == {"tenant_id": "acme"}


def test_missing_bearer_is_unauthenticated(
    verified_http: tuple[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    url, _private, tls = verified_http
    client = _RpcTransportClient(http_url=url, ssl_context=tls)
    with pytest.raises(RuntimeError, match="HTTP 401"):
        client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")


def test_bearer_for_an_unmapped_identity_is_forbidden(
    verified_http: tuple[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    url, private, tls = verified_http
    token = sign(private, base_claims(oid="oid-nobody"))
    client = _RpcTransportClient(http_url=url, identity_token=token, ssl_context=tls)
    with pytest.raises(RuntimeError, match="HTTP 403"):
        client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")


def test_shared_rpc_token_alone_does_not_authenticate_an_agent(
    tmp_path: Path, engine: HyperBusEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-1.3: the transport token passes, and the identity gate still refuses."""
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    _private, jwks = make_rsa_key()
    jwks_path = write_json(tmp_path / "jwks.json", jwks)
    map_path = tmp_path / "identity.yaml"
    map_path.write_text(standard_map_yaml(jwks_path), encoding="utf-8")
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=InMemoryAuditStore())
    gate.start()
    cert, key = make_tls_pair(tmp_path)
    server = HttpRpcServer(
        "127.0.0.1",
        0,
        engine=engine,
        tenant_id="acme",
        gate=gate,
        rpc_token="shared-secret",
        ssl_context=load_server_ssl_context(cert_path=cert, key_path=key),
    )
    server.start()
    host, port = server.address
    try:
        client = _RpcTransportClient(
            http_url=f"https://{host}:{port}",
            rpc_token="shared-secret",
            ssl_context=load_client_ssl_context(ca_path=cert),
        )
        with pytest.raises(RuntimeError, match="HTTP 401") as caught:
            client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")
        assert "no_credential" in str(caught.value)
    finally:
        server.stop()
        gate.close()


def test_body_agent_must_match_the_bearer_identity(
    verified_http: tuple[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    url, private, tls = verified_http
    token = sign(private, base_claims(oid="oid-support"))
    client = _RpcTransportClient(http_url=url, identity_token=token, ssl_context=tls)
    with pytest.raises(RuntimeError, match="HTTP 403"):
        client.call("runtime.ping", tenant_id="acme", agent_id="billing-bot")


# --- reload plumbing (AC-3.5) --------------------------------------------


class _RecordingGate:
    def __init__(self) -> None:
        self.calls = 0
        self.reloaded = threading.Event()

    def reload(self) -> None:
        self.calls += 1
        self.reloaded.set()


def test_sighup_request_reloads_the_gate_off_the_handler() -> None:
    gate = _RecordingGate()
    requested = threading.Event()
    stop = threading.Event()
    thread = threading.Thread(
        target=_reload_on_signal,
        args=(cast(IdentityGate, gate), requested, stop),
        daemon=True,
    )
    thread.start()
    requested.set()
    assert gate.reloaded.wait(timeout=5)
    stop.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert gate.calls == 1
    assert not requested.is_set()


def test_no_reload_without_a_request() -> None:
    gate = _RecordingGate()
    requested = threading.Event()
    stop = threading.Event()
    thread = threading.Thread(
        target=_reload_on_signal,
        args=(cast(IdentityGate, gate), requested, stop),
        daemon=True,
    )
    thread.start()
    stop.set()
    thread.join(timeout=5)
    assert gate.calls == 0
