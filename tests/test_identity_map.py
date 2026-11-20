"""Identity map validation and resolution (spec 003 US-3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hyperbus_runtime.identity_map import (
    IdentityMapError,
    IdentityRule,
    load_identity_map,
    parse_identity_map,
)
from identity_helpers import ISSUER, standard_map_yaml

SPIFFE_BASE = """
tenant_id: acme
verifiers:
  spiffe:
    trust_domain: acme.example
agents:
"""


def _parse(text: str, **kwargs: object):
    return parse_identity_map(text.encode("utf-8"), **kwargs)  # type: ignore[arg-type]


def test_valid_map_loads_with_digest_blocked_agent_and_summary(tmp_path: Path) -> None:
    jwks = tmp_path / "jwks.json"
    jwks.write_text("{}", encoding="utf-8")
    path = tmp_path / "map.yaml"
    path.write_text(standard_map_yaml(jwks), encoding="utf-8")

    identity_map = load_identity_map(path, expected_tenant_id="acme")

    assert identity_map.tenant_id == "acme"
    assert identity_map.change_ref == "CHG-TEST"
    assert len(identity_map.digest) == 64
    assert identity_map.agents["retired-bot"].blocked is True
    assert identity_map.agents["support-bot"].blocked is False
    summary = identity_map.summary()
    assert summary["support-bot"] == {"identities": 2, "unix_uids": 1, "blocked": False}
    assert summary["retired-bot"]["blocked"] is True


def test_digest_covers_exact_bytes(tmp_path: Path) -> None:
    jwks = tmp_path / "jwks.json"
    jwks.write_text("{}", encoding="utf-8")
    first = _parse(standard_map_yaml(jwks))
    second = _parse(standard_map_yaml(jwks) + "\n# edited\n")
    assert first.digest != second.digest


def test_tenant_mismatch_refused() -> None:
    with pytest.raises(IdentityMapError, match="tenant"):
        _parse(SPIFFE_BASE.replace("acme", "other", 1) + "  a: {}\n", expected_tenant_id="acme")


def test_duplicate_agent_key_refused_instead_of_silently_overwriting() -> None:
    text = SPIFFE_BASE + """
  support-bot:
    unix_uids: [1]
  support-bot:
    unix_uids: [2]
"""
    with pytest.raises(IdentityMapError, match="duplicate key"):
        _parse(text)


def test_unknown_top_level_and_agent_keys_refused() -> None:
    with pytest.raises(IdentityMapError, match="unknown key"):
        _parse("tenant_id: acme\nagnets: {}\n")
    with pytest.raises(IdentityMapError, match="unknown key"):
        _parse(SPIFFE_BASE + "  a:\n    unix_uid: [1]\n")


def test_non_mapping_document_refused() -> None:
    with pytest.raises(IdentityMapError, match="must be a mapping"):
        _parse("- just\n- a list\n")


def test_invalid_yaml_refused() -> None:
    with pytest.raises(IdentityMapError, match="not valid YAML"):
        _parse("tenant_id: [unclosed\n")


def test_unreadable_file_refused(tmp_path: Path) -> None:
    with pytest.raises(IdentityMapError, match="unreadable"):
        load_identity_map(tmp_path / "missing.yaml")


@pytest.mark.parametrize(
    "match",
    [
        "*",  # bare wildcard: would match every SPIFFE ID
        "spiffe://acme.example/*",  # whole trust domain
        "spiffe://acme.example/ns/*/sa/x",  # wildcard not trailing
        "spiffe://acme.example/ns/a**",  # more than one wildcard
    ],
)
def test_unsafe_wildcards_refused(match: str) -> None:
    text = SPIFFE_BASE + f"""
  support-bot:
    identities:
      - type: spiffe
        match: "{match}"
"""
    with pytest.raises(IdentityMapError):
        _parse(text)


def test_spiffe_identity_outside_trust_domain_refused() -> None:
    text = SPIFFE_BASE + """
  support-bot:
    identities:
      - type: spiffe
        match: "spiffe://evil.example/ns/prod/sa/support-bot-1"
"""
    with pytest.raises(IdentityMapError, match="outside trust domain"):
        _parse(text)


def test_spiffe_identity_without_verifier_refused() -> None:
    text = """
tenant_id: acme
agents:
  support-bot:
    identities:
      - type: spiffe
        match: "spiffe://acme.example/ns/prod/sa/support-bot-1"
"""
    with pytest.raises(IdentityMapError, match="requires verifiers.spiffe"):
        _parse(text)


def test_cross_agent_overlap_refused() -> None:
    text = SPIFFE_BASE + """
  support-bot:
    identities:
      - type: spiffe
        match: "spiffe://acme.example/ns/prod/sa/support-*"
  billing-bot:
    identities:
      - type: spiffe
        match: "spiffe://acme.example/ns/prod/sa/support-bot-1"
"""
    with pytest.raises(IdentityMapError, match="overlaps"):
        _parse(text)


def test_same_agent_may_hold_overlapping_identities() -> None:
    text = SPIFFE_BASE + """
  support-bot:
    identities:
      - type: spiffe
        match: "spiffe://acme.example/ns/prod/sa/support-*"
      - type: spiffe
        match: "spiffe://acme.example/ns/prod/sa/support-bot-1"
"""
    identity_map = _parse(text)
    assert identity_map.agents_for_spiffe("spiffe://acme.example/ns/prod/sa/support-bot-1") == {
        "support-bot"
    }


def test_uid_mapped_to_two_agents_refused() -> None:
    text = SPIFFE_BASE + """
  support-bot:
    unix_uids: [1103]
  billing-bot:
    unix_uids: [1103]
"""
    with pytest.raises(IdentityMapError, match="map to both"):
        _parse(text)


@pytest.mark.parametrize("uids", ["[-1]", "[true]", "[1.5]", "1103"])
def test_bad_uid_values_refused(uids: str) -> None:
    text = SPIFFE_BASE + f"  support-bot:\n    unix_uids: {uids}\n"
    with pytest.raises(IdentityMapError, match="unix_uids"):
        _parse(text)


def test_jwt_identity_requires_configured_issuer() -> None:
    text = """
tenant_id: acme
agents:
  support-bot:
    identities:
      - type: jwt
        issuer: https://other.example
        claim: oid
        match: oid-1
"""
    with pytest.raises(IdentityMapError, match="not configured"):
        _parse(text)


@pytest.mark.parametrize(
    "source",
    [
        "jwks_url: https://idp.example/jwks\n      jwks_file: /tmp/j.json",
        "",
    ],
)
def test_verifier_needs_exactly_one_jwks_source(source: str) -> None:
    text = f"""
tenant_id: acme
verifiers:
  jwt:
    - issuer: {ISSUER}
      audience: hyperbus
      {source}
"""
    with pytest.raises(IdentityMapError, match="exactly one of jwks_url or jwks_file"):
        _parse(text)


def test_jwks_url_must_use_https() -> None:
    text = f"""
tenant_id: acme
verifiers:
  jwt:
    - issuer: {ISSUER}
      audience: hyperbus
      jwks_url: http://idp.example/jwks
"""
    with pytest.raises(IdentityMapError, match="must use https"):
        _parse(text)


@pytest.mark.parametrize("algorithms", ["[none]", "[HS256]", "[RS256, none]", "[]", "RS256"])
def test_only_asymmetric_algorithms_allowed(algorithms: str) -> None:
    text = f"""
tenant_id: acme
verifiers:
  jwt:
    - issuer: {ISSUER}
      audience: hyperbus
      jwks_file: /tmp/j.json
      algorithms: {algorithms}
"""
    with pytest.raises(IdentityMapError, match="algorithm|non-empty list"):
        _parse(text)


def test_default_algorithms_and_bounds_applied() -> None:
    text = f"""
tenant_id: acme
verifiers:
  jwt:
    - issuer: {ISSUER}
      audience: hyperbus
      jwks_file: /tmp/j.json
"""
    issuer = _parse(text).jwt_issuers[ISSUER]
    assert issuer.algorithms == ("ES256", "RS256")
    assert issuer.leeway_seconds == 60
    assert issuer.max_age_seconds == 3600


@pytest.mark.parametrize(
    "field,value",
    [("leeway_seconds", "61"), ("leeway_seconds", "-1"), ("max_age_seconds", "10")],
)
def test_out_of_range_verifier_bounds_refused(field: str, value: str) -> None:
    text = f"""
tenant_id: acme
verifiers:
  jwt:
    - issuer: {ISSUER}
      audience: hyperbus
      jwks_file: /tmp/j.json
      {field}: {value}
"""
    with pytest.raises(IdentityMapError, match=field):
        _parse(text)


def test_duplicate_verifier_issuer_refused() -> None:
    entry = f"""
    - issuer: {ISSUER}
      audience: hyperbus
      jwks_file: /tmp/j.json
"""
    text = f"tenant_id: acme\nverifiers:\n  jwt:{entry}{entry}"
    with pytest.raises(IdentityMapError, match="twice"):
        _parse(text)


def test_blank_agent_id_refused() -> None:
    with pytest.raises(IdentityMapError, match="agent_id keys"):
        _parse('tenant_id: acme\nagents:\n  "  ":\n    unix_uids: [1]\n')


def test_identity_type_must_be_known() -> None:
    text = SPIFFE_BASE + """
  support-bot:
    identities:
      - type: password
        match: hunter2
"""
    with pytest.raises(IdentityMapError, match="identity type"):
        _parse(text)


def test_identity_rule_overlap_and_match_semantics() -> None:
    exact = IdentityRule(type="spiffe", match="spiffe://d/ns/a")
    prefix = IdentityRule(type="spiffe", match="spiffe://d/ns/*")
    other_prefix = IdentityRule(type="spiffe", match="spiffe://d/other/*")
    jwt_a = IdentityRule(type="jwt", match="x", issuer=ISSUER, claim="oid")
    jwt_b = IdentityRule(type="jwt", match="x", issuer=ISSUER, claim="sub")

    assert exact.overlaps(prefix) and prefix.overlaps(exact)
    assert prefix.overlaps(IdentityRule(type="spiffe", match="spiffe://d/ns/a/b*"))
    assert not other_prefix.overlaps(prefix)
    assert not exact.overlaps(IdentityRule(type="spiffe", match="spiffe://d/ns/b"))
    assert not jwt_a.overlaps(jwt_b)
    assert jwt_a.overlaps(IdentityRule(type="jwt", match="x", issuer=ISSUER, claim="oid"))
    assert not exact.overlaps(jwt_a)
    assert prefix.matches("spiffe://d/ns/anything")
    assert exact.matches("spiffe://d/ns/a") and not exact.matches("spiffe://d/ns/ab")


def test_resolve_jwt_by_claim_and_issuer() -> None:
    text = f"""
tenant_id: acme
verifiers:
  jwt:
    - issuer: {ISSUER}
      audience: hyperbus
      jwks_file: /tmp/j.json
agents:
  support-bot:
    identities:
      - type: jwt
        issuer: {ISSUER}
        claim: oid
        match: oid-support*
"""
    identity_map = _parse(text)
    assert identity_map.agents_for_jwt(ISSUER, {"oid": "oid-support-7"}) == {"support-bot"}
    assert identity_map.agents_for_jwt(ISSUER, {"oid": "oid-other"}) == set()
    assert identity_map.agents_for_jwt(ISSUER, {"sub": "oid-support-7"}) == set()
    assert identity_map.agents_for_jwt(ISSUER, {"oid": 42}) == set()
    assert identity_map.agents_for_jwt("https://other.example", {"oid": "oid-support-7"}) == set()


def test_agent_for_uid_and_blank_entry_is_blocked() -> None:
    text = SPIFFE_BASE + """
  support-bot:
    unix_uids: [1103]
  billing-bot:
"""
    identity_map = _parse(text)
    assert identity_map.agent_for_uid(1103) == "support-bot"
    assert identity_map.agent_for_uid(9999) is None
    assert identity_map.agents["billing-bot"].blocked is True
