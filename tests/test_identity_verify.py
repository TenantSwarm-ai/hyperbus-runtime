"""Credential verification: JWT and SPIFFE (spec 003 US-4)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import threading
import time
from pathlib import Path
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization

from hyperbus_runtime.identity_map import IdentityDenied, JwtIssuerConfig, SpiffeConfig
from hyperbus_runtime.identity_verify import (
    JwksCache,
    JwksError,
    JwtVerifier,
    spiffe_id_from_peer_cert,
)
from identity_helpers import (
    AUDIENCE,
    ISSUER,
    KID,
    SUPPORT_SPIFFE,
    base_claims,
    make_rsa_key,
    peer_cert,
    sign,
    write_json,
)


def _config(**overrides: Any) -> JwtIssuerConfig:
    """Issuer config; the default JWKS source is an injected fetch, so the file is unused."""
    values: dict[str, Any] = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": None,
        "jwks_file": "/unused.json",
        "algorithms": ("RS256", "ES256"),
        "leeway_seconds": 0,
        "max_age_seconds": 60,
    }
    values.update(overrides)
    return JwtIssuerConfig(**values)


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _verifier(document: dict[str, Any], clock: _Clock | None = None) -> tuple[JwtVerifier, JwksCache, _Clock]:
    active_clock = clock or _Clock()
    cache = JwksCache(_config(), clock=active_clock, fetch=lambda: document)
    cache.refresh()
    return JwtVerifier(_config(), cache), cache, active_clock


@pytest.fixture
def signing_key() -> tuple[Any, dict[str, Any]]:
    return make_rsa_key()


def test_valid_token_returns_claims(signing_key: tuple[Any, dict[str, Any]]) -> None:
    private, jwks = signing_key
    verifier, _cache, _clock = _verifier(jwks)
    token = sign(private, base_claims(oid="oid-support"))
    claims = verifier.verify(token)
    assert claims["oid"] == "oid-support"
    assert verifier.issuer == ISSUER


@pytest.mark.parametrize(
    "claims,reason",
    [
        (base_claims(exp=int(time.time()) - 600), "expired"),
        (base_claims(nbf=int(time.time()) + 600), "not_yet_valid"),
        (base_claims(aud="someone-else"), "wrong_audience"),
        (base_claims(iss="https://evil.example"), "wrong_issuer"),
        ({k: v for k, v in base_claims().items() if k != "exp"}, "missing_claim"),
    ],
)
def test_claim_failures_map_to_reason_codes(
    signing_key: tuple[Any, dict[str, Any]],
    claims: dict[str, Any],
    reason: str,
) -> None:
    private, jwks = signing_key
    verifier, _cache, _clock = _verifier(jwks)
    with pytest.raises(IdentityDenied) as caught:
        verifier.verify(sign(private, claims))
    assert caught.value.reason == reason


def test_signature_from_another_key_is_rejected(signing_key: tuple[Any, dict[str, Any]]) -> None:
    _private, jwks = signing_key
    attacker, _ = make_rsa_key()
    verifier, _cache, _clock = _verifier(jwks)
    with pytest.raises(IdentityDenied) as caught:
        verifier.verify(sign(attacker, base_claims()))
    assert caught.value.reason == "bad_signature"


def test_alg_none_is_rejected_before_key_lookup(signing_key: tuple[Any, dict[str, Any]]) -> None:
    _private, jwks = signing_key
    verifier, _cache, _clock = _verifier(jwks)
    unsigned = pyjwt.encode(base_claims(), key=None, algorithm="none")
    with pytest.raises(IdentityDenied) as caught:
        verifier.verify(unsigned)
    assert caught.value.reason == "alg_not_allowed"


def _forge_hs256(claims: dict[str, Any], secret: bytes, kid: str) -> str:
    """Build an HS256 token by hand: PyJWT refuses to HMAC-sign with a PEM key."""

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    payload = b64(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64(signature)}"


def test_hmac_keyed_with_public_key_is_rejected(signing_key: tuple[Any, dict[str, Any]]) -> None:
    """Algorithm confusion: the public key is used as an HMAC secret."""
    private, jwks = signing_key
    verifier, _cache, _clock = _verifier(jwks)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    forged = _forge_hs256(base_claims(), public_pem, KID)
    with pytest.raises(IdentityDenied) as caught:
        verifier.verify(forged)
    assert caught.value.reason == "alg_not_allowed"


def test_unknown_kid_is_rejected(signing_key: tuple[Any, dict[str, Any]]) -> None:
    private, jwks = signing_key
    verifier, _cache, _clock = _verifier(jwks)
    with pytest.raises(IdentityDenied) as caught:
        verifier.verify(sign(private, base_claims(), kid="rotated-away"))
    assert caught.value.reason == "unknown_kid"


def test_garbage_token_is_bad_token(signing_key: tuple[Any, dict[str, Any]]) -> None:
    _private, jwks = signing_key
    verifier, _cache, _clock = _verifier(jwks)
    with pytest.raises(IdentityDenied) as caught:
        verifier.verify("not-a-jwt")
    assert caught.value.reason == "bad_token"


def test_keys_never_fetched_on_request_path(signing_key: tuple[Any, dict[str, Any]]) -> None:
    _private, jwks = signing_key
    calls: list[int] = []

    def fetch() -> dict[str, Any]:
        calls.append(1)
        return jwks

    clock = _Clock()
    cache = JwksCache(_config(), clock=clock, fetch=fetch)
    cache.refresh()
    verifier = JwtVerifier(_config(), cache)
    private, _ = signing_key
    for _ in range(3):
        verifier.verify(sign(private, base_claims()))
    assert len(calls) == 1


def test_keys_not_loaded_denies() -> None:
    cache = JwksCache(_config(), fetch=lambda: {})
    with pytest.raises(IdentityDenied) as caught:
        cache.key_for(KID)
    assert caught.value.reason == "jwks_not_loaded"


def test_stale_keys_deny_after_max_age(signing_key: tuple[Any, dict[str, Any]]) -> None:
    private, jwks = signing_key
    verifier, _cache, clock = _verifier(jwks)
    clock.now += 61
    with pytest.raises(IdentityDenied) as caught:
        verifier.verify(sign(private, base_claims()))
    assert caught.value.reason == "jwks_stale"


def test_failed_refresh_keeps_last_good_keys_until_max_age(
    signing_key: tuple[Any, dict[str, Any]],
) -> None:
    private, jwks = signing_key
    state: dict[str, Any] = {"fail": False}

    def fetch() -> dict[str, Any]:
        if state["fail"]:
            raise OSError("idp unreachable")
        return jwks

    clock = _Clock()
    cache = JwksCache(_config(), clock=clock, fetch=fetch)
    cache.refresh()
    verifier = JwtVerifier(_config(), cache)
    state["fail"] = True
    clock.now += 30
    with pytest.raises(JwksError, match="idp unreachable"):
        cache.refresh()
    verifier.verify(sign(private, base_claims()))
    clock.now += 40
    with pytest.raises(IdentityDenied) as caught:
        verifier.verify(sign(private, base_claims()))
    assert caught.value.reason == "jwks_stale"


@pytest.mark.parametrize(
    "document",
    [{"keys": []}, {"not_keys": []}, {"keys": [{"kty": "oct"}]}, []],
)
def test_invalid_jwks_documents_are_rejected(document: Any) -> None:
    cache = JwksCache(_config(), fetch=lambda: document)
    with pytest.raises(JwksError):
        cache.refresh()


def test_jwks_file_source_is_read(tmp_path: Path, signing_key: tuple[Any, dict[str, Any]]) -> None:
    private, jwks = signing_key
    path = write_json(tmp_path / "jwks.json", jwks)
    config = _config(jwks_file=str(path))
    cache = JwksCache(config)
    cache.refresh()
    verifier = JwtVerifier(config, cache)
    assert verifier.verify(sign(private, base_claims()))["iss"] == ISSUER


def test_missing_jwks_file_is_a_refresh_error(tmp_path: Path) -> None:
    cache = JwksCache(_config(jwks_file=str(tmp_path / "absent.json")))
    with pytest.raises(JwksError, match="fetch failed"):
        cache.refresh()


def test_jwks_url_source_is_fetched_over_http(signing_key: tuple[Any, dict[str, Any]]) -> None:
    private, jwks = signing_key
    body = json.dumps(jwks).encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        url = f"http://{host}:{port}/jwks"
        config = _config(jwks_file=None, jwks_url=url)  # url source only
        cache = JwksCache(config)
        cache.refresh()
        assert JwtVerifier(config, cache).verify(sign(private, base_claims()))
    finally:
        server.shutdown()
        server.server_close()


def test_background_refresh_records_failures_and_stops() -> None:
    calls: list[int] = []

    def fetch() -> dict[str, Any]:
        calls.append(1)
        raise OSError("down")

    cache = JwksCache(_config(), fetch=fetch)
    cache.start(interval_seconds=0.01)
    cache.start(interval_seconds=0.01)  # second start is a no-op
    deadline = time.monotonic() + 2.0
    while cache.last_error is None and time.monotonic() < deadline:
        time.sleep(0.01)
    cache.stop()
    assert cache.last_error is not None
    assert "down" in cache.last_error
    assert len(calls) >= 1


def test_background_refresh_defaults_to_half_max_age() -> None:
    cache = JwksCache(_config(max_age_seconds=3600), fetch=lambda: {})
    cache.start()
    cache.stop()
    cache.stop()  # idempotent


# --- SPIFFE ------------------------------------------------------------


_SPIFFE = SpiffeConfig(trust_domain="acme.example")


def test_spiffe_id_read_from_verified_peer_cert() -> None:
    assert spiffe_id_from_peer_cert(peer_cert(SUPPORT_SPIFFE), config=_SPIFFE) == SUPPORT_SPIFFE


def test_spiffe_requires_configuration() -> None:
    with pytest.raises(IdentityDenied) as caught:
        spiffe_id_from_peer_cert(peer_cert(SUPPORT_SPIFFE), config=None)
    assert caught.value.reason == "spiffe_not_configured"


def test_empty_peer_cert_is_no_credential() -> None:
    with pytest.raises(IdentityDenied) as caught:
        spiffe_id_from_peer_cert({}, config=_SPIFFE)
    assert caught.value.reason == "no_credential"


def test_cert_without_spiffe_uri_is_rejected() -> None:
    cert = {"subjectAltName": (("DNS", "support.acme.example"), ("URI", "https://x.example"))}
    with pytest.raises(IdentityDenied) as caught:
        spiffe_id_from_peer_cert(cert, config=_SPIFFE)
    assert caught.value.reason == "no_spiffe_san"


def test_cert_with_two_spiffe_uris_is_rejected() -> None:
    cert = {
        "subjectAltName": (
            ("URI", SUPPORT_SPIFFE),
            ("URI", "spiffe://acme.example/ns/prod/sa/billing-bot-1"),
        )
    }
    with pytest.raises(IdentityDenied) as caught:
        spiffe_id_from_peer_cert(cert, config=_SPIFFE)
    assert caught.value.reason == "multiple_spiffe_san"


def test_cert_from_other_trust_domain_is_rejected() -> None:
    cert = peer_cert("spiffe://evil.example/ns/prod/sa/support-bot-1")
    with pytest.raises(IdentityDenied) as caught:
        spiffe_id_from_peer_cert(cert, config=_SPIFFE)
    assert caught.value.reason == "trust_domain_mismatch"


def test_expired_and_not_yet_valid_certs_are_rejected() -> None:
    expired = peer_cert(SUPPORT_SPIFFE, not_after="Jan  1 00:00:00 2020 GMT")
    with pytest.raises(IdentityDenied) as caught:
        spiffe_id_from_peer_cert(expired, config=_SPIFFE)
    assert caught.value.reason == "expired"

    future = peer_cert(SUPPORT_SPIFFE, not_before="Jan  1 00:00:00 2100 GMT")
    with pytest.raises(IdentityDenied) as caught:
        spiffe_id_from_peer_cert(future, config=_SPIFFE)
    assert caught.value.reason == "not_yet_valid"


def test_unparseable_cert_dates_are_bad_certificate() -> None:
    cert = peer_cert(SUPPORT_SPIFFE, not_after="next tuesday")
    with pytest.raises(IdentityDenied) as caught:
        spiffe_id_from_peer_cert(cert, config=_SPIFFE)
    assert caught.value.reason == "bad_certificate"


def test_explicit_now_controls_validity_window() -> None:
    # Window is 2000-01-01 .. 2030-01-01 (UTC); 1.8e9 is 2027, 1.9e9 is 2030-03.
    cert = peer_cert(SUPPORT_SPIFFE, not_after="Jan  1 00:00:00 2030 GMT")
    assert spiffe_id_from_peer_cert(cert, config=_SPIFFE, now=1_800_000_000.0) == SUPPORT_SPIFFE
    with pytest.raises(IdentityDenied) as caught:
        spiffe_id_from_peer_cert(cert, config=_SPIFFE, now=1_900_000_000.0)
    assert caught.value.reason == "expired"
