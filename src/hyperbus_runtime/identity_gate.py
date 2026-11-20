"""Identity gate for verified mode (spec 003 US-1, US-2, US-3, US-5).

The gate keeps one immutable state object: the identity map plus its JWT
verifiers. Every request reads that object once. A reload builds a complete new
state and swaps it in, so a removed identity is denied on its next request and a
failed reload denies everything until a valid map loads (AC-3.7).
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hyperbus_core import AuditEvent, AuditSink

from hyperbus_runtime.identity_map import (
    IdentityDenied,
    IdentityMap,
    IdentityMapError,
    load_identity_map,
)
from hyperbus_runtime.identity_verify import (
    JwksCache,
    JwksError,
    JwtVerifier,
    spiffe_id_from_peer_cert,
)
from hyperbus_runtime.peer_cred import PeerIdentity

try:
    import jwt
    from jwt import exceptions as jwt_errors
except ImportError:  # pragma: no cover - optional extra
    jwt = None
    jwt_errors = None


class IdentityConfigError(RuntimeError):
    """Verified mode is configured in a way this build cannot honor."""


@dataclass(frozen=True)
class VerifiedIdentity:
    """A credential the gate verified and mapped to exactly one agent."""

    agent_id: str
    identity: str


@dataclass(frozen=True)
class _State:
    identity_map: IdentityMap | None = None
    verifiers: Mapping[str, JwtVerifier] = field(default_factory=dict)
    deny_reason: str = "map_not_loaded"


class IdentityGate:
    """Verified-mode authentication for the Unix socket and HTTP transports."""

    def __init__(
        self,
        *,
        tenant_id: str,
        map_path: str | Path,
        audit: AuditSink | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._map_path = Path(map_path)
        self._audit = audit
        self._load_lock = threading.Lock()
        self._state = _State()
        self._caches: dict[str, JwksCache] = {}

    # --- lifecycle -------------------------------------------------------

    def start(self) -> None:
        """Load the map or raise. A server must not start without a valid map."""
        self._load(initial=True)

    def reload(self) -> None:
        """Re-read the map (SIGHUP). A failed reload denies everything (AC-3.7)."""
        self._load(initial=False)

    def close(self) -> None:
        for cache in self._caches.values():
            cache.stop()
        self._caches = {}

    @property
    def deny_reason(self) -> str | None:
        """Why every request is denied, or ``None`` when a map is active."""
        state = self._state
        return None if state.identity_map is not None else state.deny_reason

    def _load(self, *, initial: bool) -> None:
        with self._load_lock:
            try:
                identity_map = load_identity_map(
                    self._map_path,
                    expected_tenant_id=self._tenant_id,
                )
                verifiers = self._build_verifiers(identity_map)
            except (IdentityMapError, JwksError) as exc:
                self._reject(str(exc))
                if initial:
                    raise
                return
            self._state = _State(identity_map=identity_map, verifiers=verifiers)
            self._emit(
                "identity.map_loaded",
                detail={
                    "digest": identity_map.digest,
                    "change_ref": identity_map.change_ref,
                    "agents": identity_map.summary(),
                },
            )

    def _reject(self, reason: str) -> None:
        self._state = _State(identity_map=None, deny_reason="map_rejected")
        self._emit("identity.map_rejected", detail={"reason": reason})

    def _build_verifiers(self, identity_map: IdentityMap) -> dict[str, JwtVerifier]:
        if identity_map.jwt_issuers and jwt is None:
            msg = "JWT identities need the identity extra: pip install 'hyperbus-runtime[identity]'"
            raise IdentityMapError(msg)
        fresh: dict[str, JwksCache] = {}
        created: list[JwksCache] = []
        for issuer, config in identity_map.jwt_issuers.items():
            existing = self._caches.get(issuer)
            if existing is not None and existing.config == config:
                fresh[issuer] = existing
                continue
            cache = JwksCache(config)
            cache.refresh()
            fresh[issuer] = cache
            created.append(cache)
        for cache in created:
            cache.start()
        for issuer, cache in self._caches.items():
            if fresh.get(issuer) is not cache:
                cache.stop()
        self._caches = fresh
        return {
            issuer: JwtVerifier(config, fresh[issuer])
            for issuer, config in identity_map.jwt_issuers.items()
        }

    # --- decisions -------------------------------------------------------

    def authenticate_unix(self, peer: PeerIdentity | None) -> VerifiedIdentity:
        """Map the connecting uid to its agent (AC-2.1). Looked up per request (AC-3.6)."""
        state = self._snapshot("unix")
        if peer is None:
            raise self._deny("no_peer_credentials", transport="unix")
        identity = f"uid:{peer.uid}"
        agent_id = state.identity_map.agent_for_uid(peer.uid)
        if agent_id is None:
            raise self._deny("uid_unmapped", transport="unix", identity=identity)
        return VerifiedIdentity(agent_id=agent_id, identity=identity)

    def authenticate_http(
        self,
        *,
        bearer: str | None,
        peer_cert: Mapping[str, Any] | None,
    ) -> VerifiedIdentity:
        """Verify exactly one credential and map it to one agent (US-1, US-4)."""
        state = self._snapshot("http")
        if bearer is not None and peer_cert:
            raise self._deny("ambiguous_credential", transport="http")
        if bearer is not None:
            return self._authenticate_bearer(state, bearer)
        if peer_cert:
            return self._authenticate_spiffe(state.identity_map, peer_cert)
        raise self._deny("no_credential", transport="http")

    def check_declared(
        self,
        verified: VerifiedIdentity,
        *,
        declared: object,
        transport: str,
    ) -> None:
        """A body or envelope ``agent_id`` may only repeat the verified one (AC-1.2, AC-2.2)."""
        if declared is None or declared == verified.agent_id:
            return
        raise self._deny(
            "body_agent_mismatch",
            transport=transport,
            http_status=403,
            identity=verified.identity,
            declared=declared,
        )

    def _authenticate_bearer(self, state: _State, bearer: str) -> VerifiedIdentity:
        if jwt is None:
            raise self._deny("jwt_unavailable", transport="http")
        # The issuer is read before the signature is checked, so only it is used
        # for lookup. Claims from an unverified token are never written to audit.
        try:
            unverified = jwt.decode(bearer, options={"verify_signature": False})
        except jwt_errors.PyJWTError as exc:
            raise self._deny("bad_token", transport="http") from exc
        issuer = unverified.get("iss")
        verifier = state.verifiers.get(issuer) if isinstance(issuer, str) else None
        if verifier is None:
            raise self._deny("unknown_issuer", transport="http")
        try:
            claims = verifier.verify(bearer)
        except IdentityDenied as exc:
            raise self._deny(exc.reason, transport="http") from exc
        identity = f"jwt:{verifier.issuer}|sub={claims.get('sub')}"
        agents = state.identity_map.agents_for_jwt(verifier.issuer, claims)
        return VerifiedIdentity(
            agent_id=self._one_agent(agents, identity=identity),
            identity=identity,
        )

    def _authenticate_spiffe(
        self,
        identity_map: IdentityMap,
        peer_cert: Mapping[str, Any],
    ) -> VerifiedIdentity:
        try:
            spiffe_id = spiffe_id_from_peer_cert(peer_cert, config=identity_map.spiffe)
        except IdentityDenied as exc:
            raise self._deny(exc.reason, transport="http") from exc
        agents = identity_map.agents_for_spiffe(spiffe_id)
        return VerifiedIdentity(
            agent_id=self._one_agent(agents, identity=spiffe_id),
            identity=spiffe_id,
        )

    def _one_agent(self, agents: set[str], *, identity: str) -> str:
        if not agents:
            raise self._deny("unmapped", transport="http", identity=identity, http_status=403)
        if len(agents) > 1:
            raise self._deny("ambiguous", transport="http", identity=identity, http_status=403)
        return next(iter(agents))

    def _snapshot(self, transport: str) -> _State:
        """Read the state once per request. Denies when no valid map is active."""
        state = self._state
        if state.identity_map is None:
            raise self._deny(state.deny_reason, transport=transport)
        return state

    # --- audit -----------------------------------------------------------

    def _deny(
        self,
        reason: str,
        *,
        transport: str,
        http_status: int = 401,
        identity: str | None = None,
        declared: object = None,
    ) -> IdentityDenied:
        self._emit(
            "identity.denied",
            detail={
                "transport": transport,
                "reason": reason,
                "identity": identity,
                "declared_agent_id": declared if isinstance(declared, str) else None,
            },
        )
        return IdentityDenied(reason, http_status=http_status, identity=identity)

    def _emit(self, event_type: str, *, detail: Mapping[str, Any]) -> None:
        if self._audit is None:
            return
        try:
            self._audit.emit(
                AuditEvent(
                    event_type=event_type,
                    tenant_id=self._tenant_id,
                    detail=dict(detail),
                )
            )
        except Exception:  # noqa: BLE001 - a broken sink must not change the decision
            return
