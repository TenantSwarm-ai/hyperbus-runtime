"""HyperBus engine sidecar — RPC gateway to HyperBusEngine."""

from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import threading
from pathlib import Path

from hyperbus_core import (
    AuditConflictError,
    AuditDurabilityError,
    AuditIntegrityError,
    CapabilityError,
    HyperBusEngine,
    InMemoryAuditStore,
    InMemoryBackend,
    PostgresAuditStore,
    rebuild_registry,
)

from hyperbus_runtime.audit_checkpoint import load_audit_checkpoint
from hyperbus_runtime.grants import load_grants_seed
from hyperbus_runtime.identity_gate import IdentityConfigError, IdentityGate
from hyperbus_runtime.identity_map import IdentityMapError
from hyperbus_runtime.identity_verify import JwksError
from hyperbus_runtime.peer_cred import load_peer_agent_map
from hyperbus_runtime.rpc_server import HttpRpcServer, UnixRpcServer

try:
    from hyperbus_core import PostgresBackend
except ImportError:  # pragma: no cover - optional extra
    PostgresBackend = None  # type: ignore[misc, assignment]

_DEFAULT_UNIX_SOCKET = "/run/hyperbus/engine.sock"

AuditStore = InMemoryAuditStore | PostgresAuditStore
_SEED_SOURCE = "grants-yaml"


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


def _build_audit_store(database_url: str | None) -> AuditStore:
    """Durable grant audit when a database is configured, volatile otherwise (AC-6.1, AC-6.3)."""
    if database_url:
        return PostgresAuditStore(database_url)
    return InMemoryAuditStore()


def create_engine(
    *,
    tenant_id: str,
    grants_path: Path,
    database_url: str | None,
    audit_checkpoint: tuple[int, str] | None = None,
) -> tuple[HyperBusEngine, AuditStore]:
    """Rebuild the tenant's grants from its audit log, then build the engine.

    The YAML seed fills only regions the log has never decided (AC-6.2). A
    revoked grant therefore stays revoked after restart. Any integrity failure
    raises before an engine exists, so the process does not start (spec 014 AC-14.6).
    """
    audit = _build_audit_store(database_url)
    _, seed = load_grants_seed(grants_path, tenant_id=tenant_id)
    rebuilt = rebuild_registry(
        audit,
        tenant_id,
        seed=seed,
        seed_source=_SEED_SOURCE,
        checkpoint=audit_checkpoint,
    )
    backend = _build_backend(database_url)
    engine = HyperBusEngine(tenant_id, backend, rebuilt.registry, audit=audit)
    return engine, audit


def validate_identity_startup(
    *,
    mode: str,
    listen: str | None,
    peer_agent_map_path: Path | None,
    identity_map_path: Path | None,
    durable_audit: bool,
    allow_volatile_grants: bool,
    audit_checkpoint_given: bool,
) -> None:
    """Refuse verified-mode configurations this build cannot enforce (spec 003)."""
    if mode == "declared":
        return
    if listen:
        msg = (
            "verified identity over HTTP requires TLS (001 AC-7.1), which this build "
            "does not provide; serve verified mode on --socket only"
        )
        raise IdentityConfigError(msg)
    if peer_agent_map_path is not None:
        msg = "verified mode reads uids from --identity-map; remove --peer-agent-map"
        raise IdentityConfigError(msg)
    if identity_map_path is None:
        msg = "verified mode requires --identity-map"
        raise IdentityConfigError(msg)
    if not durable_audit and not allow_volatile_grants:
        msg = (
            "verified mode requires durable grant audit (spec 003 AC-6.3); "
            "pass --allow-volatile-grants only for local development"
        )
        raise IdentityConfigError(msg)
    if durable_audit and not audit_checkpoint_given:
        msg = (
            "verified mode with durable grant audit requires --audit-checkpoint "
            "(spec 003 AC-6.6); create one with `python -m hyperbus_runtime.audit_checkpoint`"
        )
        raise IdentityConfigError(msg)


def _reload_on_signal(
    gate: IdentityGate,
    requested: threading.Event,
    stop: threading.Event,
) -> None:
    """Run reloads off the signal handler so the handler never takes a lock."""
    while not stop.is_set():
        if not requested.wait(timeout=0.5):
            continue
        requested.clear()
        gate.reload()


def serve_engine(
    engine: HyperBusEngine,
    audit: AuditStore,
    *,
    tenant_id: str,
    socket_path: str | None,
    listen: str | None,
    peer_agent_map_path: Path | None,
    rpc_token: str | None = None,
    socket_group: str | None = None,
    gate: IdentityGate | None = None,
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
            gate=gate,
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
            gate=gate,
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
    reload_requested = threading.Event()

    def _shutdown(_signum: int, _frame: object | None) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    if gate is not None and hasattr(signal, "SIGHUP"):
        def _request_reload(_signum: int, _frame: object | None) -> None:
            reload_requested.set()

        signal.signal(signal.SIGHUP, _request_reload)
        threading.Thread(
            target=_reload_on_signal,
            args=(gate, reload_requested, stop),
            name="hyperbus-identity-reload",
            daemon=True,
        ).start()
    stop.wait()
    for server in servers:
        server.stop()
    if gate is not None:
        gate.close()


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
    parser.add_argument(
        "--identity-mode",
        choices=["declared", "verified"],
        default=os.environ.get("HYPERBUS_IDENTITY_MODE", "declared"),
        help="declared trusts the caller's agent_id (not an identity boundary); "
        "verified binds agent_id to a verified credential",
    )
    parser.add_argument(
        "--identity-map",
        type=Path,
        default=os.environ.get("HYPERBUS_IDENTITY_MAP"),
        help="Identity map YAML (required in verified mode)",
    )
    parser.add_argument(
        "--allow-volatile-grants",
        action="store_true",
        help="Dev only: allow verified mode without durable grant audit",
    )
    parser.add_argument(
        "--audit-checkpoint",
        type=Path,
        default=os.environ.get("HYPERBUS_AUDIT_CHECKPOINT"),
        help="Operator-held audit tip; required in verified mode with a durable log",
    )
    args = parser.parse_args()
    database_url = args.database_url or os.environ.get("DATABASE_URL")
    try:
        validate_identity_startup(
            mode=args.identity_mode,
            listen=args.listen,
            peer_agent_map_path=args.peer_agent_map,
            identity_map_path=args.identity_map,
            durable_audit=bool(database_url),
            allow_volatile_grants=args.allow_volatile_grants,
            audit_checkpoint_given=args.audit_checkpoint is not None,
        )
        checkpoint = (
            load_audit_checkpoint(args.audit_checkpoint, tenant_id=args.tenant)
            if args.audit_checkpoint is not None
            else None
        )
        engine, audit = create_engine(
            tenant_id=args.tenant,
            grants_path=args.grants,
            database_url=database_url,
            audit_checkpoint=checkpoint,
        )
        gate = None
        if args.identity_mode == "verified":
            gate = IdentityGate(
                tenant_id=args.tenant,
                map_path=args.identity_map,
                audit=audit,
            )
            gate.start()
    except (
        IdentityConfigError,
        IdentityMapError,
        JwksError,
        AuditIntegrityError,
        AuditConflictError,
        AuditDurabilityError,
        CapabilityError,
        ValueError,
    ) as exc:
        sys.exit(f"hyperbus-engine: {exc}")
    serve_engine(
        engine,
        audit,
        tenant_id=args.tenant,
        socket_path=args.socket or None,
        listen=args.listen,
        peer_agent_map_path=args.peer_agent_map,
        rpc_token=args.rpc_token,
        socket_group=args.socket_group,
        gate=gate,
    )


if __name__ == "__main__":
    main()
