"""Shared builders for verified-identity tests: keys, signed tokens, maps, certs."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://idp.example"
AUDIENCE = "hyperbus"
KID = "k1"
TRUST_DOMAIN = "acme.example"
SUPPORT_SPIFFE = "spiffe://acme.example/ns/prod/sa/support-bot-1"
BILLING_SPIFFE = "spiffe://acme.example/ns/prod/sa/billing-bot-1"


def make_rsa_key(kid: str = KID) -> tuple[Any, dict[str, Any]]:
    """Return (private key, JWKS document holding its public half)."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return private, {"keys": [jwk]}


def sign(private: Any, claims: dict[str, Any], *, kid: str = KID, alg: str = "RS256") -> str:
    return jwt.encode(claims, private, algorithm=alg, headers={"kid": kid})


def base_claims(**extra: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "svc-1",
        "iat": now,
        "exp": now + 300,
    }
    claims.update(extra)
    return claims


def write_json(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def standard_map_yaml(
    jwks_path: Path,
    *,
    tenant: str = "acme",
    support_uid: int = 4242,
    billing_uid: int | None = None,
) -> str:
    """A map with two agents, one retired agent, one JWT issuer, and SPIFFE."""
    billing_uids = f"unix_uids: [{billing_uid}]" if billing_uid is not None else "unix_uids: []"
    return f"""
tenant_id: {tenant}
change_ref: CHG-TEST
verifiers:
  jwt:
    - issuer: {ISSUER}
      audience: {AUDIENCE}
      jwks_file: "{jwks_path}"
      algorithms: [RS256]
      leeway_seconds: 0
      max_age_seconds: 3600
  spiffe:
    trust_domain: {TRUST_DOMAIN}
agents:
  support-bot:
    unix_uids: [{support_uid}]
    identities:
      - type: spiffe
        match: "spiffe://acme.example/ns/prod/sa/support-bot-*"
      - type: jwt
        issuer: {ISSUER}
        claim: oid
        match: oid-support
  billing-bot:
    {billing_uids}
    identities:
      - type: spiffe
        match: "spiffe://acme.example/ns/prod/sa/billing-bot-*"
      - type: jwt
        issuer: {ISSUER}
        claim: oid
        match: oid-billing
  retired-bot: {{}}
"""


def peer_cert(
    spiffe_id: str,
    *,
    not_before: str = "Jan  1 00:00:00 2000 GMT",
    not_after: str = "Jan  1 00:00:00 2100 GMT",
) -> dict[str, Any]:
    """Shape of ``ssl.SSLSocket.getpeercert()`` for a chain-verified SVID."""
    return {
        "subjectAltName": (("URI", spiffe_id),),
        "notBefore": not_before,
        "notAfter": not_after,
    }


def current_uid() -> int:
    return os.getuid()
