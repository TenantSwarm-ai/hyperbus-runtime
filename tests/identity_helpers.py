"""Shared builders for verified-identity tests: keys, signed tokens, maps, certs."""

from __future__ import annotations

import ipaddress
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
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


def make_tls_pair(directory: Path) -> tuple[Path, Path]:
    """Self-signed listener certificate for localhost and 127.0.0.1.

    The certificate is its own trust anchor, so the same PEM file serves as the
    server chain and as the client's CA bundle.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hyperbus-test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / "tls-cert.pem"
    key_path = directory / "tls-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def make_client_ca(directory: Path) -> tuple[Path, Path]:
    """A self-signed CA that issues client certificates for mTLS (spec 003 AC-1.5)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hyperbus-client-ca")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "client-ca.pem"
    key_path = directory / "client-ca-key.pem"
    directory.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def make_client_cert(
    directory: Path,
    ca_cert: Path,
    ca_key: Path,
    spiffe_id: str,
) -> tuple[Path, Path]:
    """A client certificate for ``spiffe_id``, signed by the given CA."""
    issuer = x509.load_pem_x509_certificate(ca_cert.read_bytes())
    signer = serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
    if not isinstance(signer, ec.EllipticCurvePrivateKey):
        msg = "client CA key must be an EC key"
        raise TypeError(msg)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "worker")]))
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(signer, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / "worker-cert.pem"
    key_path = directory / "worker-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def current_uid() -> int:
    return os.getuid()
