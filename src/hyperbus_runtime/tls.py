"""TLS for the engine's HTTP listener and the worker's HTTPS client (spec 003 AC-1.4/1.5).

With a client CA the listener requires a client certificate that chains to it
(mTLS, 001 AC-7.1). The identity gate then maps the certificate's SPIFFE ID to an
agent. A request carries one credential: a client certificate or a bearer token.
The gate denies a request that carries both.
"""

from __future__ import annotations

import ssl
from pathlib import Path

_MIN_VERSION = ssl.TLSVersion.TLSv1_2


def load_server_ssl_context(
    *,
    cert_path: str | Path,
    key_path: str | Path,
    client_ca_path: str | Path | None = None,
) -> ssl.SSLContext:
    """Build the listener's TLS context.

    With ``client_ca_path`` the server requires a client certificate that chains
    to that CA. Without it the server requests none.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _MIN_VERSION
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    if client_ca_path is not None:
        ctx.load_verify_locations(cafile=str(client_ca_path))
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def load_client_ssl_context(
    *,
    ca_path: str | Path,
    cert_path: str | Path | None = None,
    key_path: str | Path | None = None,
) -> ssl.SSLContext:
    """Build a client context that trusts only ``ca_path`` and checks the server name.

    Hostname checking stays on. The system trust store is not consulted, so an
    engine cannot be impersonated by any certificate a public CA issued. With
    ``cert_path`` and ``key_path`` the client presents that certificate when the
    engine asks for one.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
    ctx.minimum_version = _MIN_VERSION
    if cert_path is not None and key_path is not None:
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx
