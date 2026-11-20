"""Identity gate decisions, audit trail, and reload semantics (spec 003 US-1..US-5)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from hyperbus_core import AuditEvent, InMemoryAuditStore

import hyperbus_runtime.identity_gate as identity_gate_module
from hyperbus_runtime.identity_gate import IdentityGate
from hyperbus_runtime.identity_map import IdentityDenied, IdentityMapError
from hyperbus_runtime.identity_verify import JwksError
from hyperbus_runtime.peer_cred import PeerIdentity
from identity_helpers import (
    AUDIENCE,
    BILLING_SPIFFE,
    ISSUER,
    SUPPORT_SPIFFE,
    base_claims,
    make_rsa_key,
    peer_cert,
    sign,
    standard_map_yaml,
    write_json,
)

SUPPORT_UID = 4242
UNKNOWN_UID = 9999


@dataclass
class World:
    gate: IdentityGate
    audit: InMemoryAuditStore
    private: Any
    jwks_path: Path
    map_path: Path


def _events(audit: InMemoryAuditStore, event_type: str) -> list[AuditEvent]:
    return [event for event in audit.events if event.event_type == event_type]


def _map_with(jwks_path: Path, *, support_body: str, jwt_claim: str = "oid") -> str:
    """Minimal map: one JWT issuer, one SPIFFE domain, and a configurable support-bot."""
    return f"""
tenant_id: acme
verifiers:
  jwt:
    - issuer: {ISSUER}
      audience: {AUDIENCE}
      jwks_file: "{jwks_path}"
      algorithms: [RS256]
      leeway_seconds: 0
  spiffe:
    trust_domain: acme.example
agents:
  support-bot:
{support_body}
  billing-bot:
    identities:
      - type: jwt
        issuer: {ISSUER}
        claim: {jwt_claim}
        match: oid-billing
"""


@pytest.fixture
def world(tmp_path: Path) -> World:
    private, jwks = make_rsa_key()
    jwks_path = write_json(tmp_path / "jwks.json", jwks)
    map_path = tmp_path / "identity.yaml"
    map_path.write_text(standard_map_yaml(jwks_path, support_uid=SUPPORT_UID), encoding="utf-8")
    audit = InMemoryAuditStore()
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=audit)
    gate.start()
    yield World(gate=gate, audit=audit, private=private, jwks_path=jwks_path, map_path=map_path)
    gate.close()


# --- startup and audit ---------------------------------------------------


def test_start_emits_map_loaded_with_digest_and_agent_summary(world: World) -> None:
    loaded = _events(world.audit, "identity.map_loaded")
    assert len(loaded) == 1
    detail = loaded[0].detail
    assert detail["change_ref"] == "CHG-TEST"
    assert len(detail["digest"]) == 64
    assert detail["agents"]["retired-bot"]["blocked"] is True
    assert detail["agents"]["support-bot"]["unix_uids"] == 1
    assert world.gate.deny_reason is None


def test_gate_without_audit_sink_still_decides(tmp_path: Path) -> None:
    _private, jwks = make_rsa_key()
    jwks_path = write_json(tmp_path / "jwks.json", jwks)
    map_path = tmp_path / "identity.yaml"
    map_path.write_text(standard_map_yaml(jwks_path, support_uid=SUPPORT_UID), encoding="utf-8")
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=None)
    gate.start()
    try:
        assert gate.authenticate_unix(PeerIdentity(1, SUPPORT_UID, 1)).agent_id == "support-bot"
        with pytest.raises(IdentityDenied):
            gate.authenticate_unix(PeerIdentity(1, UNKNOWN_UID, 1))
    finally:
        gate.close()


def test_broken_audit_sink_never_changes_a_decision(tmp_path: Path) -> None:
    class BrokenSink:
        def emit(self, event: AuditEvent) -> None:
            raise RuntimeError("sink down")

    _private, jwks = make_rsa_key()
    jwks_path = write_json(tmp_path / "jwks.json", jwks)
    map_path = tmp_path / "identity.yaml"
    map_path.write_text(standard_map_yaml(jwks_path, support_uid=SUPPORT_UID), encoding="utf-8")
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=BrokenSink())
    gate.start()
    try:
        with pytest.raises(IdentityDenied) as caught:
            gate.authenticate_unix(PeerIdentity(1, UNKNOWN_UID, 1))
        assert caught.value.reason == "uid_unmapped"
    finally:
        gate.close()


def test_invalid_map_refuses_startup(tmp_path: Path) -> None:
    map_path = tmp_path / "identity.yaml"
    map_path.write_text("tenant_id: acme\nagnets: {}\n", encoding="utf-8")
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=InMemoryAuditStore())
    with pytest.raises(IdentityMapError):
        gate.start()
    assert gate.deny_reason == "map_rejected"


def test_unfetchable_jwks_refuses_startup(tmp_path: Path) -> None:
    map_path = tmp_path / "identity.yaml"
    map_path.write_text(
        standard_map_yaml(tmp_path / "missing-jwks.json"), encoding="utf-8"
    )
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=InMemoryAuditStore())
    with pytest.raises(JwksError):
        gate.start()


def test_jwt_identities_refuse_to_load_without_pyjwt(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(identity_gate_module, "jwt", None)
    gate = IdentityGate(tenant_id="acme", map_path=world.map_path, audit=InMemoryAuditStore())
    with pytest.raises(IdentityMapError, match="identity extra"):
        gate.start()


def test_before_start_every_request_is_denied(tmp_path: Path) -> None:
    gate = IdentityGate(tenant_id="acme", map_path=tmp_path / "none.yaml")
    with pytest.raises(IdentityDenied) as caught:
        gate.authenticate_unix(PeerIdentity(1, SUPPORT_UID, 1))
    assert caught.value.reason == "map_not_loaded"
    assert gate.deny_reason == "map_not_loaded"


def test_tenant_mismatch_refuses_startup(world: World) -> None:
    gate = IdentityGate(tenant_id="other", map_path=world.map_path, audit=InMemoryAuditStore())
    with pytest.raises(IdentityMapError, match="tenant"):
        gate.start()


# --- unix binding (US-2) -------------------------------------------------


def test_mapped_uid_resolves_to_its_agent(world: World) -> None:
    verified = world.gate.authenticate_unix(PeerIdentity(pid=7, uid=SUPPORT_UID, gid=1))
    assert verified.agent_id == "support-bot"
    assert verified.identity == f"uid:{SUPPORT_UID}"


def test_unmapped_uid_is_denied_and_audited(world: World) -> None:
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_unix(PeerIdentity(pid=7, uid=UNKNOWN_UID, gid=1))
    assert caught.value.reason == "uid_unmapped"
    denied = _events(world.audit, "identity.denied")[-1]
    assert denied.detail["reason"] == "uid_unmapped"
    assert denied.detail["transport"] == "unix"


def test_unix_connection_without_peer_credentials_is_denied(world: World) -> None:
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_unix(None)
    assert caught.value.reason == "no_peer_credentials"


def test_declared_agent_must_match_the_verified_agent(world: World) -> None:
    verified = world.gate.authenticate_unix(PeerIdentity(pid=7, uid=SUPPORT_UID, gid=1))
    world.gate.check_declared(verified, declared=None, transport="unix")
    world.gate.check_declared(verified, declared="support-bot", transport="unix")
    with pytest.raises(IdentityDenied) as caught:
        world.gate.check_declared(verified, declared="billing-bot", transport="unix")
    assert caught.value.reason == "body_agent_mismatch"
    assert caught.value.http_status == 403
    denied = _events(world.audit, "identity.denied")[-1]
    assert denied.detail["declared_agent_id"] == "billing-bot"
    assert denied.detail["identity"] == f"uid:{SUPPORT_UID}"


def test_non_string_declared_agent_is_a_mismatch(world: World) -> None:
    verified = world.gate.authenticate_unix(PeerIdentity(pid=7, uid=SUPPORT_UID, gid=1))
    with pytest.raises(IdentityDenied) as caught:
        world.gate.check_declared(verified, declared=["support-bot"], transport="unix")
    assert caught.value.reason == "body_agent_mismatch"
    denied = _events(world.audit, "identity.denied")[-1]
    assert denied.detail["declared_agent_id"] is None


# --- bearer and certificate credentials (US-1, US-4) --------------------


def test_verified_bearer_maps_to_agent_and_never_reaches_audit(world: World) -> None:
    token = sign(world.private, base_claims(oid="oid-support"))
    verified = world.gate.authenticate_http(bearer=token, peer_cert=None)
    assert verified.agent_id == "support-bot"
    assert verified.identity.startswith(f"jwt:{ISSUER}|sub=")
    for event in world.audit.events:
        assert token not in repr(event.detail)


def test_bearer_for_unmapped_identity_is_forbidden(world: World) -> None:
    token = sign(world.private, base_claims(oid="oid-nobody"))
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_http(bearer=token, peer_cert=None)
    assert caught.value.reason == "unmapped"
    assert caught.value.http_status == 403


def test_bearer_from_unconfigured_issuer_is_denied(world: World) -> None:
    token = sign(world.private, base_claims(iss="https://other.example", oid="oid-support"))
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_http(bearer=token, peer_cert=None)
    assert caught.value.reason == "unknown_issuer"


def test_bearer_signed_by_another_key_is_denied(world: World) -> None:
    attacker, _ = make_rsa_key()
    token = sign(attacker, base_claims(oid="oid-support"))
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_http(bearer=token, peer_cert=None)
    assert caught.value.reason == "bad_signature"


def test_unverified_claims_never_reach_the_audit_trail(world: World) -> None:
    """A forged sub on an unverified token must not be written into audit detail."""
    forged_sub = "svc-evil\nidentity.map_loaded forged"
    attacker, _ = make_rsa_key()
    token = sign(attacker, base_claims(sub=forged_sub, oid="oid-support"))
    with pytest.raises(IdentityDenied):
        world.gate.authenticate_http(bearer=token, peer_cert=None)
    unknown = sign(world.private, base_claims(iss="https://other.example", sub=forged_sub))
    with pytest.raises(IdentityDenied):
        world.gate.authenticate_http(bearer=unknown, peer_cert=None)
    denials = _events(world.audit, "identity.denied")
    assert [event.detail["identity"] for event in denials[-2:]] == [None, None]
    for event in world.audit.events:
        assert forged_sub not in repr(event.detail)


def test_bearer_without_pyjwt_is_denied_not_crashed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spiffe-only map on a host without PyJWT must deny bearer tokens cleanly."""
    map_path = tmp_path / "spiffe-only.yaml"
    map_path.write_text(
        """
tenant_id: acme
verifiers:
  spiffe:
    trust_domain: acme.example
agents:
  support-bot:
    identities:
      - type: spiffe
        match: "spiffe://acme.example/ns/prod/sa/support-bot-*"
""",
        encoding="utf-8",
    )
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=InMemoryAuditStore())
    gate.start()
    try:
        monkeypatch.setattr(identity_gate_module, "jwt", None)
        with pytest.raises(IdentityDenied) as caught:
            gate.authenticate_http(bearer="a.b.c", peer_cert=None)
        assert caught.value.reason == "jwt_unavailable"
    finally:
        gate.close()


def test_malformed_bearer_is_bad_token(world: World) -> None:
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_http(bearer="definitely.not.jwt", peer_cert=None)
    assert caught.value.reason == "bad_token"


def test_bearer_and_certificate_together_are_ambiguous(world: World) -> None:
    token = sign(world.private, base_claims(oid="oid-support"))
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_http(bearer=token, peer_cert=peer_cert(SUPPORT_SPIFFE))
    assert caught.value.reason == "ambiguous_credential"


def test_spiffe_certificate_maps_to_agent(world: World) -> None:
    verified = world.gate.authenticate_http(bearer=None, peer_cert=peer_cert(SUPPORT_SPIFFE))
    assert verified.agent_id == "support-bot"
    assert verified.identity == SUPPORT_SPIFFE


def test_unmapped_spiffe_identity_is_forbidden(world: World) -> None:
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_http(
            bearer=None,
            peer_cert=peer_cert("spiffe://acme.example/ns/prod/sa/other-1"),
        )
    assert caught.value.reason == "unmapped"


def test_spiffe_certificate_errors_are_reported(world: World) -> None:
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_http(
            bearer=None,
            peer_cert=peer_cert("spiffe://evil.example/ns/prod/sa/support-bot-1"),
        )
    assert caught.value.reason == "trust_domain_mismatch"


def test_no_credential_is_unauthenticated(world: World) -> None:
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_http(bearer=None, peer_cert=None)
    assert caught.value.reason == "no_credential"
    assert caught.value.http_status == 401


def test_claims_mapping_to_two_agents_are_ambiguous(
    tmp_path: Path, world: World
) -> None:
    """Overlap checks run per claim; one token carrying two matching claims is denied."""
    map_path = tmp_path / "ambiguous.yaml"
    map_path.write_text(
        f"""
tenant_id: acme
verifiers:
  jwt:
    - issuer: {ISSUER}
      audience: {AUDIENCE}
      jwks_file: "{world.jwks_path}"
      algorithms: [RS256]
agents:
  support-bot:
    identities:
      - type: jwt
        issuer: {ISSUER}
        claim: oid
        match: shared-value
  billing-bot:
    identities:
      - type: jwt
        issuer: {ISSUER}
        claim: sub
        match: shared-value
""",
        encoding="utf-8",
    )
    gate = IdentityGate(tenant_id="acme", map_path=map_path, audit=InMemoryAuditStore())
    gate.start()
    try:
        token = sign(world.private, base_claims(oid="shared-value", sub="shared-value"))
        with pytest.raises(IdentityDenied) as caught:
            gate.authenticate_http(bearer=token, peer_cert=None)
        assert caught.value.reason == "ambiguous"
    finally:
        gate.close()


# --- reload semantics (US-3) --------------------------------------------


def test_removing_an_identity_denies_its_next_request_without_restart(world: World) -> None:
    token = sign(world.private, base_claims(oid="oid-support"))
    assert world.gate.authenticate_http(bearer=token, peer_cert=None).agent_id == "support-bot"
    assert world.gate.authenticate_unix(PeerIdentity(1, SUPPORT_UID, 1)).agent_id == "support-bot"

    world.map_path.write_text(
        _map_with(world.jwks_path, support_body="    {}"), encoding="utf-8"
    )
    world.gate.reload()

    with pytest.raises(IdentityDenied) as http_denied:
        world.gate.authenticate_http(bearer=token, peer_cert=None)
    assert http_denied.value.reason == "unmapped"
    with pytest.raises(IdentityDenied) as unix_denied:
        world.gate.authenticate_unix(PeerIdentity(1, SUPPORT_UID, 1))
    assert unix_denied.value.reason == "uid_unmapped"
    assert len(_events(world.audit, "identity.map_loaded")) == 2


def test_failed_reload_denies_everything_until_a_valid_map_loads(world: World) -> None:
    world.map_path.write_text("tenant_id: acme\nagents:\n  a: {}\n  a: {}\n", encoding="utf-8")
    world.gate.reload()

    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_unix(PeerIdentity(1, SUPPORT_UID, 1))
    assert caught.value.reason == "map_rejected"
    assert world.gate.deny_reason == "map_rejected"
    rejected = _events(world.audit, "identity.map_rejected")
    assert rejected and "duplicate key" in rejected[-1].detail["reason"]

    world.map_path.write_text(
        standard_map_yaml(world.jwks_path, support_uid=SUPPORT_UID), encoding="utf-8"
    )
    world.gate.reload()
    assert world.gate.deny_reason is None
    assert world.gate.authenticate_unix(PeerIdentity(1, SUPPORT_UID, 1)).agent_id == "support-bot"


def test_reload_to_unfetchable_jwks_denies(world: World) -> None:
    world.map_path.write_text(
        standard_map_yaml(world.jwks_path.parent / "gone.json", support_uid=SUPPORT_UID),
        encoding="utf-8",
    )
    world.gate.reload()
    with pytest.raises(IdentityDenied) as caught:
        world.gate.authenticate_unix(PeerIdentity(1, SUPPORT_UID, 1))
    assert caught.value.reason == "map_rejected"


def test_reload_with_changed_issuer_settings_rebuilds_the_key_cache(world: World) -> None:
    token = sign(world.private, base_claims(oid="oid-support"))
    world.map_path.write_text(
        standard_map_yaml(world.jwks_path, support_uid=SUPPORT_UID).replace(
            "max_age_seconds: 3600", "max_age_seconds: 120"
        ),
        encoding="utf-8",
    )
    world.gate.reload()
    assert world.gate.authenticate_http(bearer=token, peer_cert=None).agent_id == "support-bot"


def test_reload_restores_identity_when_map_is_reinstated(world: World) -> None:
    world.map_path.write_text(
        _map_with(world.jwks_path, support_body="    {}"), encoding="utf-8"
    )
    world.gate.reload()
    world.map_path.write_text(
        standard_map_yaml(world.jwks_path, support_uid=SUPPORT_UID), encoding="utf-8"
    )
    world.gate.reload()
    assert world.gate.authenticate_unix(PeerIdentity(1, SUPPORT_UID, 1)).agent_id == "support-bot"


def test_close_is_idempotent(world: World) -> None:
    world.gate.close()
    world.gate.close()


def test_billing_spiffe_identity_maps_to_billing(world: World) -> None:
    verified = world.gate.authenticate_http(bearer=None, peer_cert=peer_cert(BILLING_SPIFFE))
    assert verified.agent_id == "billing-bot"
