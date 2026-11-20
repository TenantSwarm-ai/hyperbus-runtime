"""HTTPS for the engine listener and the worker client (spec 003 AC-1.4)."""

from __future__ import annotations

import http.client
import ssl
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from hyperbus_core import HyperBusEngine, InMemoryAuditStore, InMemoryBackend
from identity_helpers import (
    SUPPORT_SPIFFE,
    base_claims,
    make_client_ca,
    make_client_cert,
    make_rsa_key,
    make_tls_pair,
    sign,
    standard_map_yaml,
    write_json,
)

from hyperbus_runtime.client import _RpcTransportClient, connect_from_env
from hyperbus_runtime.engine_daemon import _build_listener_tls
from hyperbus_runtime.grants import load_grants_yaml
from hyperbus_runtime.identity_gate import IdentityConfigError, IdentityGate
from hyperbus_runtime.rpc_server import HttpRpcServer
from hyperbus_runtime.tls import load_client_ssl_context, load_server_ssl_context

TOKEN = "shared-secret"
INTRUDER_SPIFFE = "spiffe://acme.example/ns/prod/sa/intruder-1"


@pytest.fixture
def engine(grants_file: Path) -> HyperBusEngine:
    registry = load_grants_yaml(grants_file, tenant_id="acme")
    return HyperBusEngine("acme", InMemoryBackend(), registry)


@pytest.fixture
def tls_server(tmp_path: Path, engine: HyperBusEngine) -> Iterator[tuple[str, Path]]:
    cert, key = make_tls_pair(tmp_path)
    server = HttpRpcServer(
        "127.0.0.1",
        0,
        engine=engine,
        tenant_id="acme",
        rpc_token=TOKEN,
        ssl_context=load_server_ssl_context(cert_path=cert, key_path=key),
    )
    server.start()
    host, port = server.address
    try:
        yield f"https://{host}:{port}", cert
    finally:
        server.stop()


# --- contexts -------------------------------------------------------------


def test_server_context_has_a_tls12_floor_and_requests_no_client_certificate(tmp_path: Path) -> None:
    cert, key = make_tls_pair(tmp_path)
    ctx = load_server_ssl_context(cert_path=cert, key_path=key)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_NONE


def test_server_context_requires_a_client_certificate_when_given_a_client_ca(
    tmp_path: Path,
) -> None:
    cert, key = make_tls_pair(tmp_path / "server")
    client_ca, _client_key = make_client_ca(tmp_path / "ca")
    ctx = load_server_ssl_context(cert_path=cert, key_path=key, client_ca_path=client_ca)
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_client_context_checks_hostname_and_trusts_only_its_ca(tmp_path: Path) -> None:
    cert, _key = make_tls_pair(tmp_path)
    ctx = load_client_ssl_context(ca_path=cert)
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


# --- startup configuration ------------------------------------------------


def test_listener_tls_is_off_when_nothing_is_configured() -> None:
    assert _build_listener_tls(None, None) is None


def test_listener_tls_needs_both_the_certificate_and_the_key(tmp_path: Path) -> None:
    cert, _key = make_tls_pair(tmp_path)
    with pytest.raises(IdentityConfigError, match="set together"):
        _build_listener_tls(cert, None)


def test_listener_tls_reports_an_unreadable_key(tmp_path: Path) -> None:
    cert, _key = make_tls_pair(tmp_path)
    with pytest.raises(IdentityConfigError, match="cannot load TLS"):
        _build_listener_tls(cert, tmp_path / "missing.pem")


# --- wire behaviour -------------------------------------------------------


def test_https_call_with_the_engine_ca_reaches_the_engine(tls_server: tuple[str, Path]) -> None:
    url, cert = tls_server
    client = _RpcTransportClient(
        http_url=url,
        rpc_token=TOKEN,
        ssl_context=load_client_ssl_context(ca_path=cert),
    )
    assert client.call("runtime.ping", tenant_id="acme", agent_id="support-bot") == {
        "tenant_id": "acme"
    }


def test_client_that_does_not_trust_the_engine_certificate_is_refused(
    tls_server: tuple[str, Path],
) -> None:
    url, _cert = tls_server
    client = _RpcTransportClient(
        http_url=url,
        rpc_token=TOKEN,
        ssl_context=ssl.create_default_context(),
    )
    with pytest.raises(urllib.error.URLError) as caught:
        client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")
    assert isinstance(caught.value.reason, ssl.SSLCertVerificationError)


def test_plaintext_request_to_the_tls_port_is_not_served(tls_server: tuple[str, Path]) -> None:
    url, _cert = tls_server
    request = urllib.request.Request(
        f"http://{url.removeprefix('https://')}/rpc",
        data=b"{}",
        headers={"Content-Type": "application/json", "X-HyperBus-Token": TOKEN},
        method="POST",
    )
    with pytest.raises((OSError, http.client.HTTPException)):
        urllib.request.urlopen(request, timeout=5)


# --- client guards (fail closed) ------------------------------------------


def test_bearer_is_never_sent_over_plaintext_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    with pytest.raises(ValueError, match="plaintext"):
        _RpcTransportClient(http_url="http://127.0.0.1:1", identity_token="tok")


def test_https_engine_requires_an_explicit_trusted_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    with pytest.raises(ValueError, match="ssl_context"):
        _RpcTransportClient(http_url="https://127.0.0.1:1")


def test_connect_from_env_refuses_a_bearer_over_plaintext_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HYPERBUS_SOCKET", raising=False)
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("HYPERBUS_RPC_TOKEN", TOKEN)
    monkeypatch.setenv("HYPERBUS_IDENTITY_TOKEN", "tok")
    with pytest.raises(ValueError, match="plaintext"):
        connect_from_env(tenant_id="acme", agent_id="support-bot")


def test_connect_from_env_https_requires_a_ca(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HYPERBUS_SOCKET", raising=False)
    monkeypatch.delenv("HYPERBUS_TLS_CA", raising=False)
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "https://127.0.0.1:1")
    monkeypatch.setenv("HYPERBUS_RPC_TOKEN", TOKEN)
    with pytest.raises(RuntimeError, match="HYPERBUS_TLS_CA"):
        connect_from_env(tenant_id="acme", agent_id="support-bot")


def test_connect_from_env_reports_an_unreadable_ca(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("HYPERBUS_SOCKET", raising=False)
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "https://127.0.0.1:1")
    monkeypatch.setenv("HYPERBUS_RPC_TOKEN", TOKEN)
    monkeypatch.setenv("HYPERBUS_TLS_CA", str(tmp_path / "missing-ca.pem"))
    with pytest.raises(RuntimeError, match="cannot load TLS CA"):
        connect_from_env(tenant_id="acme", agent_id="support-bot")


def test_connect_from_env_calls_the_engine_over_https(
    tls_server: tuple[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    url, cert = tls_server
    monkeypatch.delenv("HYPERBUS_SOCKET", raising=False)
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", url)
    monkeypatch.setenv("HYPERBUS_RPC_TOKEN", TOKEN)
    monkeypatch.setenv("HYPERBUS_TLS_CA", str(cert))
    client = connect_from_env(tenant_id="acme", agent_id="support-bot")
    assert client.call("runtime.ping", tenant_id="acme", agent_id="support-bot") == {
        "tenant_id": "acme"
    }


# --- client certificates (mTLS, spec 003 AC-1.5) --------------------------


class _Mtls(NamedTuple):
    url: str
    server_ca: Path
    client_ca: Path
    client_ca_key: Path
    client_cert: Path
    client_key: Path
    private: Any


@pytest.fixture
def mtls(tmp_path: Path, engine: HyperBusEngine) -> Iterator[_Mtls]:
    """Verified listener that requires a client certificate from its client CA."""
    private, jwks = make_rsa_key()
    jwks_path = write_json(tmp_path / "jwks.json", jwks)
    map_path = tmp_path / "identity.yaml"
    map_path.write_text(standard_map_yaml(jwks_path), encoding="utf-8")
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=InMemoryAuditStore())
    gate.start()
    server_cert, server_key = make_tls_pair(tmp_path / "server")
    client_ca, client_ca_key = make_client_ca(tmp_path / "ca")
    client_cert, client_key = make_client_cert(
        tmp_path / "worker", client_ca, client_ca_key, SUPPORT_SPIFFE
    )
    server = HttpRpcServer(
        "127.0.0.1",
        0,
        engine=engine,
        tenant_id="acme",
        gate=gate,
        ssl_context=load_server_ssl_context(
            cert_path=server_cert,
            key_path=server_key,
            client_ca_path=client_ca,
        ),
    )
    server.start()
    host, port = server.address
    try:
        yield _Mtls(
            url=f"https://{host}:{port}",
            server_ca=server_cert,
            client_ca=client_ca,
            client_ca_key=client_ca_key,
            client_cert=client_cert,
            client_key=client_key,
            private=private,
        )
    finally:
        server.stop()
        gate.close()


def _worker_client(world: _Mtls, **kwargs: Any) -> _RpcTransportClient:
    return _RpcTransportClient(
        http_url=world.url,
        ssl_context=load_client_ssl_context(
            ca_path=world.server_ca,
            cert_path=world.client_cert,
            key_path=world.client_key,
        ),
        **kwargs,
    )


def test_client_certificate_maps_to_its_agent(mtls: _Mtls) -> None:
    client = _worker_client(mtls)
    assert client.call("runtime.ping", tenant_id="acme", agent_id="support-bot") == {
        "tenant_id": "acme"
    }


def test_body_agent_must_match_the_certificate_identity(mtls: _Mtls) -> None:
    client = _worker_client(mtls)
    with pytest.raises(RuntimeError, match="HTTP 403"):
        client.call("runtime.ping", tenant_id="acme", agent_id="billing-bot")


def test_client_without_a_certificate_is_refused_at_the_handshake(mtls: _Mtls) -> None:
    client = _RpcTransportClient(
        http_url=mtls.url,
        ssl_context=load_client_ssl_context(ca_path=mtls.server_ca),
    )
    with pytest.raises((OSError, http.client.HTTPException)):
        client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")


def test_certificate_from_an_untrusted_ca_is_refused_at_the_handshake(
    mtls: _Mtls, tmp_path: Path
) -> None:
    rogue_ca, rogue_key = make_client_ca(tmp_path / "rogue-ca")
    rogue_cert, rogue_client_key = make_client_cert(
        tmp_path / "rogue", rogue_ca, rogue_key, SUPPORT_SPIFFE
    )
    client = _RpcTransportClient(
        http_url=mtls.url,
        ssl_context=load_client_ssl_context(
            ca_path=mtls.server_ca,
            cert_path=rogue_cert,
            key_path=rogue_client_key,
        ),
    )
    with pytest.raises((OSError, http.client.HTTPException)):
        client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")


def test_trusted_certificate_with_an_unmapped_spiffe_id_is_forbidden(
    mtls: _Mtls, tmp_path: Path
) -> None:
    cert, key = make_client_cert(
        tmp_path / "intruder", mtls.client_ca, mtls.client_ca_key, INTRUDER_SPIFFE
    )
    client = _RpcTransportClient(
        http_url=mtls.url,
        ssl_context=load_client_ssl_context(
            ca_path=mtls.server_ca,
            cert_path=cert,
            key_path=key,
        ),
    )
    with pytest.raises(RuntimeError, match="HTTP 403") as caught:
        client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")
    assert "unmapped" in str(caught.value)


def test_a_request_with_a_certificate_and_a_bearer_is_denied(mtls: _Mtls) -> None:
    """One credential per request (AC-1.5). The gate enforces it even if the client does not."""
    token = sign(mtls.private, base_claims(oid="oid-support"))
    client = _worker_client(mtls, identity_token=token)
    with pytest.raises(RuntimeError, match="ambiguous_credential"):
        client.call("runtime.ping", tenant_id="acme", agent_id="support-bot")


def test_connect_from_env_refuses_two_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cert, key = make_client_cert(tmp_path, *make_client_ca(tmp_path / "ca"), SUPPORT_SPIFFE)
    monkeypatch.delenv("HYPERBUS_SOCKET", raising=False)
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "https://127.0.0.1:1")
    monkeypatch.setenv("HYPERBUS_RPC_TOKEN", TOKEN)
    monkeypatch.setenv("HYPERBUS_TLS_CA", str(cert))
    monkeypatch.setenv("HYPERBUS_CLIENT_TLS_CERT", str(cert))
    monkeypatch.setenv("HYPERBUS_CLIENT_TLS_KEY", str(key))
    monkeypatch.setenv("HYPERBUS_IDENTITY_TOKEN", "tok")
    with pytest.raises(RuntimeError, match="not both"):
        connect_from_env(tenant_id="acme", agent_id="support-bot")


def test_connect_from_env_needs_the_client_cert_and_key_together(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cert, _key = make_client_cert(tmp_path, *make_client_ca(tmp_path / "ca"), SUPPORT_SPIFFE)
    monkeypatch.delenv("HYPERBUS_SOCKET", raising=False)
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "https://127.0.0.1:1")
    monkeypatch.setenv("HYPERBUS_RPC_TOKEN", TOKEN)
    monkeypatch.setenv("HYPERBUS_TLS_CA", str(cert))
    monkeypatch.setenv("HYPERBUS_CLIENT_TLS_CERT", str(cert))
    monkeypatch.delenv("HYPERBUS_CLIENT_TLS_KEY", raising=False)
    with pytest.raises(RuntimeError, match="set together"):
        connect_from_env(tenant_id="acme", agent_id="support-bot")


def test_connect_from_env_never_sends_a_client_cert_in_plaintext(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cert, key = make_client_cert(tmp_path, *make_client_ca(tmp_path / "ca"), SUPPORT_SPIFFE)
    monkeypatch.delenv("HYPERBUS_SOCKET", raising=False)
    monkeypatch.delenv("HYPERBUS_IDENTITY_TOKEN", raising=False)
    monkeypatch.setenv("HYPERBUS_ENGINE_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("HYPERBUS_RPC_TOKEN", TOKEN)
    monkeypatch.setenv("HYPERBUS_CLIENT_TLS_CERT", str(cert))
    monkeypatch.setenv("HYPERBUS_CLIENT_TLS_KEY", str(key))
    with pytest.raises(RuntimeError, match="https://"):
        connect_from_env(tenant_id="acme", agent_id="support-bot")


def test_listener_client_ca_needs_a_certificate_and_key(tmp_path: Path) -> None:
    cert, _key = make_tls_pair(tmp_path)
    client_ca, _client_key = make_client_ca(tmp_path / "ca")
    with pytest.raises(IdentityConfigError, match="set together"):
        _build_listener_tls(None, None, client_ca)
    with pytest.raises(IdentityConfigError, match="set together"):
        _build_listener_tls(cert, None, client_ca)
