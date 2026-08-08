"""HyperBus engine sidecar — RPC gateway to HyperBusEngine."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from pathlib import Path

from hyperbus_core import HyperBusEngine, InMemoryBackend, InMemoryAuditStore

from hyperbus_runtime.grants import load_grants_yaml
from hyperbus_runtime.rpc_server import HttpRpcServer, UnixRpcServer

try:
    from hyperbus_core import PostgresBackend
except ImportError:  # pragma: no cover - optional extra
    PostgresBackend = None  # type: ignore[misc, assignment]


def _build_backend(database_url: str | None):
    if database_url:
        if PostgresBackend is None:
            msg = "Postgres backend requested but hyperbus-core[postgres] is not installed"
            raise RuntimeError(msg)
        return PostgresBackend(database_url)
    return InMemoryBackend()


def _parse_listen(value: str) -> tuple[str, int]:
    host, _, port_text = value.rpartition(":")
    if not host or not port_text.isdigit():
        msg = f"Invalid --listen address {value!r}; expected host:port"
        raise ValueError(msg)
    return host, int(port_text)


def create_engine(
    *,
    tenant_id: str,
    grants_path: Path,
    database_url: str | None,
) -> HyperBusEngine:
    audit = InMemoryAuditStore()
    registry = load_grants_yaml(grants_path, tenant_id=tenant_id, audit=audit)
    backend = _build_backend(database_url)
    return HyperBusEngine(tenant_id, backend, registry, audit=audit)


def serve_engine(
    engine: HyperBusEngine,
    *,
    tenant_id: str,
    socket_path: str | None,
    listen: str | None,
) -> None:
    servers: list[HttpRpcServer | UnixRpcServer] = []
    if listen:
        host, port = _parse_listen(listen)
        http = HttpRpcServer(host, port, engine=engine, tenant_id=tenant_id)
        http.start()
        servers.append(http)
        bound_host, bound_port = http.address
        print(
            f"hyperbus-engine listening on http://{bound_host}:{bound_port}/rpc",
            file=sys.stderr,
        )
    if socket_path:
        unix = UnixRpcServer(socket_path, engine=engine, tenant_id=tenant_id)
        unix.start()
        servers.append(unix)
        print(
            f"hyperbus-engine listening on unix://{socket_path}",
            file=sys.stderr,
        )
    if not servers:
        msg = "At least one of --listen or --socket must be configured"
        raise RuntimeError(msg)

    stop = threading.Event()

    def _shutdown(_signum: int, _frame: object | None) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    stop.wait()
    for server in servers:
        server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="HyperBus engine sidecar")
    parser.add_argument("--tenant", required=True, help="Tenant id for this engine")
    parser.add_argument(
        "--grants",
        required=True,
        type=Path,
        help="YAML grant file (tenant_id + agent grants)",
    )
    parser.add_argument(
        "--socket",
        default=None,
        help="Unix domain socket path (Linux)",
    )
    parser.add_argument(
        "--listen",
        default="127.0.0.1:8080",
        help="HTTP listen address host:port (fallback / Docker)",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="Postgres URL (or set DATABASE_URL)",
    )
    args = parser.parse_args()
    database_url = args.database_url or os.environ.get("DATABASE_URL")
    engine = create_engine(
        tenant_id=args.tenant,
        grants_path=args.grants,
        database_url=database_url,
    )
    serve_engine(
        engine,
        tenant_id=args.tenant,
        socket_path=args.socket,
        listen=args.listen,
    )


if __name__ == "__main__":
    main()
