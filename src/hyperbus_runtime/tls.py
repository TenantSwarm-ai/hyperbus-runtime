"""TLS for the engine's HTTP listener and the worker's HTTPS client (spec 003 AC-1.4).

Client certificates (mTLS, spec 003 AC-1.5) are not handled here. The server
requests none, so the bearer credential is the only identity on this path.
"""

from __future__ import annotations

import ssl
from pathlib import Path

_MIN_VERSION = ssl.TLSVersion.TLSv1_2


def load_server_ssl_context(*, cert_path: str | Path, key_path: str | Path) -> ssl.SSLContext:
    """Build the listener's TLS context from a PEM certificate chain and key."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _MIN_VERSION
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


def load_client_ssl_context(*, ca_path: str | Path) -> ssl.SSLContext:
    """Build a client context that trusts only ``ca_path`` and checks the server name.

    Hostname checking stays on. The system trust store is not consulted, so an
    engine cannot be impersonated by any certificate a public CA issued.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
    ctx.minimum_version = _MIN_VERSION
    return ctx
