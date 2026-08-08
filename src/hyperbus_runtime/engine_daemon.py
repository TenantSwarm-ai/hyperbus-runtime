"""HyperBus engine sidecar — RPC gateway to HyperBusEngine."""

from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import threading
from pathlib import Path

from hyperbus_core import HyperBusEngine, InMemoryAuditStore, InMemoryBackend

from hyperbus_runtime.grants import load_grants_yaml
from hyperbus_runtime.peer_cred import load_peer_agent_map
from hyperbus_runtime.rpc_server import HttpRpcServer, UnixRpcServer

try:
    from hyperbus_core import PostgresBackend
except ImportError:  # pragma: no cover - optional extra
    PostgresBackend = None  # type: ignore[misc, assignment]

_DEFAULT_UNIX_SOCKET = "/run/hyperbus/engine.sock"


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


def default_socket_path() -> str | None:
    if hasattr(socket, "AF_UNIX"):
        return os.environ.get("HYPERBUS_SOCKET", _DEFAULT_UNIX_SOCKET)
    return None


def create_engine(
    *,
    tenant_id: str,
    grants_path: Path,
    database_url: str | None,
) -> tuple[HyperBusEngine, InMemoryAuditStore]:
    audit = InMemoryAuditStore()
    registry = load_grants_yaml(grants_path, tenant_id=tenant_id, audit=audit)
    backend = _build_backend(database_url)
    engine = HyperBusEngine(tenant_id, backend, registry, audit=audit)
    return engine, audit


def serve_engine(
    engine: HyperBusEngine,
    audit: InMemoryAuditStore,
    *,
    tenant_id: str,
    socket_path: str | None,
    listen: str | None,
    peer_agent_map_path: Path | None,
    rpc_token: str | None = None,
    socket_group: str | None = None,
) -> None:
    peer_agent_map = load_peer_agent_map(peer_agent_map_path)
    if listen and not rpc_token:
        msg = (
            "HTTP RPC requires HYPERBUS_RPC_TOKEN (or --rpc-token) when --listen is set"
        )
        raise RuntimeError(msg)
    servers: list[HttpRpcServer | UnixRpcServer] = []
    if listen:
        host, port = _parse_listen(listen)
        http = HttpRpcServer(
            host,
            port,
            engine=engine,
            tenant_id=tenant_id,
            audit=audit,
            rpc_token=rpc_token,
        )
        http.start()
        servers.append(http)
        bound_host, bound_port = http.address
        print(
            f"hyperbus-engine listening on http://{bound_host}:{bound_port}/rpc",
            file=sys.stderr,
        )
    if socket_path:
        unix = UnixRpcServer(
            socket_path,
            engine=engine,
            tenant_id=tenant_id,
            audit=audit,
            peer_agent_map=peer_agent_map,
            socket_group=socket_group,
        )
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
        default=default_socket_path(),
        help="Unix domain socket path (default on Linux/macOS)",
    )
    parser.add_argument(
        "--listen",
        default=os.environ.get("HYPERBUS_ENGINE_LISTEN"),
        help="Optional HTTP listen address host:port (Docker fallback)",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="Postgres URL (or set DATABASE_URL)",
    )
    parser.add_argument(
        "--peer-agent-map",
        type=Path,
        default=os.environ.get("HYPERBUS_PEER_AGENT_MAP"),
        help="Optional uid→agent_id YAML for SO_PEERCRED binding",
    )
    parser.add_argument(
        "--rpc-token",
        default=os.environ.get("HYPERBUS_RPC_TOKEN"),
        help="Shared secret required for HTTP RPC (HYPERBUS_RPC_TOKEN)",
    )
    parser.add_argument(
        "--socket-group",
        default=os.environ.get("HYPERBUS_SOCKET_GROUP", "hb-agents"),
        help="Group ownership for Unix socket (default hb-agents)",
    )
    args = parser.parse_args()
    database_url = args.database_url or os.environ.get("DATABASE_URL")
    engine, audit = create_engine(
        tenant_id=args.tenant,
        grants_path=args.grants,
        database_url=database_url,
    )
    serve_engine(
        engine,
        audit,
        tenant_id=args.tenant,
        socket_path=args.socket or None,
        listen=args.listen,
        peer_agent_map_path=args.peer_agent_map,
        rpc_token=args.rpc_token,
        socket_group=args.socket_group,
    )


if __name__ == "__main__":
    main()
