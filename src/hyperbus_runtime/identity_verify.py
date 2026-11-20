"""Credential verification for verified identity (spec 003 US-4).

JWT: signature against a cached JWKS, issuer, audience, expiry, and an
algorithm allowlist. Keys refresh on a background thread. The request path
never performs network I/O; a key set older than its maximum age denies.

X.509 (SPIFFE): the SPIFFE ID comes from a peer certificate that the TLS layer
has already chain-verified (001 AC-7.1). This module checks the SAN, the trust
domain, and the validity dates only.
"""

from __future__ import annotations

import json
import ssl
import threading
import time
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from hyperbus_runtime.identity_map import (
    SPIFFE_SCHEME,
    IdentityDenied,
    JwtIssuerConfig,
    SpiffeConfig,
)

try:
    import jwt
    from jwt import exceptions as jwt_errors
except ImportError:  # pragma: no cover - optional extra
    jwt = None
    jwt_errors = None

_FETCH_TIMEOUT_SECONDS = 10.0
_MIN_REFRESH_SECONDS = 5.0
_MAX_REFRESH_SECONDS = 300.0


class JwksError(RuntimeError):
    """A key set could not be fetched or parsed."""


def _jwks_fetcher(config: JwtIssuerConfig) -> Callable[[], Mapping[str, Any]]:
    if config.jwks_file is not None:
        path = Path(config.jwks_file)

        def read_file() -> Mapping[str, Any]:
            return json.loads(path.read_text(encoding="utf-8"))

        return read_file

    url = config.jwks_url
    if url is None:  # pragma: no cover - map validation guarantees one source
        msg = f"verifier {config.issuer!r} has no JWKS source"
        raise JwksError(msg)

    def fetch_url() -> Mapping[str, Any]:
        with urllib.request.urlopen(url, timeout=_FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310 - https enforced at map load
            return json.loads(response.read().decode("utf-8"))

    return fetch_url


class JwksCache:
    """Signing keys for one issuer. Last good keys survive failed refreshes until max age."""

    def __init__(
        self,
        config: JwtIssuerConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
        fetch: Callable[[], Mapping[str, Any]] | None = None,
    ) -> None:
        self._config = config
        self._clock = clock
        self._fetch = fetch if fetch is not None else _jwks_fetcher(config)
        self._lock = threading.Lock()
        self._keys: Any = None
        self._fetched_at: float | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None

    @property
    def config(self) -> JwtIssuerConfig:
        return self._config

    def refresh(self) -> None:
        """Fetch and parse the key set. Raises ``JwksError``; keeps the old keys on failure."""
        try:
            document = self._fetch()
        except (OSError, ValueError) as exc:
            msg = f"JWKS fetch failed for {self._config.issuer!r}: {exc}"
            raise JwksError(msg) from exc
        keys = _parse_jwks(self._config.issuer, document)
        with self._lock:
            self._keys = keys
            self._fetched_at = self._clock()
            self.last_error = None

    def key_for(self, kid: str | None) -> Any:
        """Return the public key for ``kid``. Never fetches on the request path."""
        with self._lock:
            keys = self._keys
            fetched_at = self._fetched_at
        if keys is None or fetched_at is None:
            raise IdentityDenied("jwks_not_loaded")
        if self._clock() - fetched_at > self._config.max_age_seconds:
            raise IdentityDenied("jwks_stale")
        if kid is not None:
            for jwk in keys.keys:
                if jwk.key_id == kid:
                    return jwk.key
        raise IdentityDenied("unknown_kid")

    def start(self, *, interval_seconds: float | None = None) -> None:
        """Refresh in the background. Failures record ``last_error`` and keep serving."""
        if self._thread is not None:
            return
        interval = interval_seconds or min(
            max(self._config.max_age_seconds / 2, _MIN_REFRESH_SECONDS),
            _MAX_REFRESH_SECONDS,
        )

        def loop() -> None:
            while not self._stop.wait(interval):
                try:
                    self.refresh()
                except JwksError as exc:
                    self.last_error = str(exc)

        self._thread = threading.Thread(
            target=loop,
            name=f"hyperbus-jwks-{self._config.issuer}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


def _parse_jwks(issuer: str, document: Mapping[str, Any]) -> Any:
    keys = document.get("keys") if isinstance(document, Mapping) else None
    if not isinstance(keys, list) or not keys:
        msg = f"JWKS for {issuer!r} must contain a non-empty keys list"
        raise JwksError(msg)
    try:
        return jwt.PyJWKSet(keys)
    except (jwt_errors.PyJWTError, KeyError, TypeError, ValueError) as exc:
        msg = f"JWKS for {issuer!r} is invalid: {exc}"
        raise JwksError(msg) from exc


def _reason_for(exc: BaseException) -> str:
    table: tuple[tuple[type[BaseException], str], ...] = (
        (jwt_errors.ExpiredSignatureError, "expired"),
        (jwt_errors.ImmatureSignatureError, "not_yet_valid"),
        (jwt_errors.InvalidAudienceError, "wrong_audience"),
        (jwt_errors.InvalidIssuerError, "wrong_issuer"),
        (jwt_errors.InvalidSignatureError, "bad_signature"),
        (jwt_errors.MissingRequiredClaimError, "missing_claim"),
        (jwt_errors.InvalidAlgorithmError, "alg_not_allowed"),
    )
    for error_type, reason in table:
        if isinstance(exc, error_type):
            return reason
    return "bad_token"


class JwtVerifier:
    """Verifies one configured issuer's tokens."""

    def __init__(self, config: JwtIssuerConfig, cache: JwksCache) -> None:
        self._config = config
        self._cache = cache

    @property
    def issuer(self) -> str:
        return self._config.issuer

    def verify(self, token: str) -> dict[str, Any]:
        """Return verified claims or raise ``IdentityDenied`` with a reason code."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt_errors.PyJWTError as exc:
            raise IdentityDenied("bad_token") from exc
        # Check the algorithm before looking up a key, so an attacker-chosen
        # alg (none, HS256 keyed with the public key) never reaches key selection.
        if header.get("alg") not in self._config.algorithms:
            raise IdentityDenied("alg_not_allowed")
        key = self._cache.key_for(header.get("kid"))
        try:
            return jwt.decode(
                token,
                key=key,
                algorithms=list(self._config.algorithms),
                audience=self._config.audience,
                issuer=self._config.issuer,
                leeway=self._config.leeway_seconds,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt_errors.PyJWTError as exc:
            raise IdentityDenied(_reason_for(exc)) from exc


def spiffe_id_from_peer_cert(
    cert: Mapping[str, Any] | None,
    *,
    config: SpiffeConfig | None,
    now: float | None = None,
) -> str:
    """Return the SPIFFE ID from a chain-verified peer certificate.

    ``cert`` is ``ssl.SSLSocket.getpeercert()``. It is empty when no verified
    client certificate was presented, which denies as ``no_credential``.
    """
    if config is None:
        raise IdentityDenied("spiffe_not_configured")
    if not cert:
        raise IdentityDenied("no_credential")
    uris = [
        value
        for kind, value in cert.get("subjectAltName", ())
        if kind == "URI" and isinstance(value, str) and value.startswith(SPIFFE_SCHEME)
    ]
    if not uris:
        raise IdentityDenied("no_spiffe_san")
    if len(uris) > 1:
        raise IdentityDenied("multiple_spiffe_san")
    spiffe_id = uris[0]
    if not spiffe_id.startswith(f"{SPIFFE_SCHEME}{config.trust_domain}/"):
        raise IdentityDenied("trust_domain_mismatch")
    _check_validity(cert, now=time.time() if now is None else now)
    return spiffe_id


def _check_validity(cert: Mapping[str, Any], *, now: float) -> None:
    try:
        not_before = cert.get("notBefore")
        if isinstance(not_before, str) and ssl.cert_time_to_seconds(not_before) > now:
            raise IdentityDenied("not_yet_valid")
        not_after = cert.get("notAfter")
        if isinstance(not_after, str) and ssl.cert_time_to_seconds(not_after) <= now:
            raise IdentityDenied("expired")
    except ValueError as exc:
        raise IdentityDenied("bad_certificate") from exc
