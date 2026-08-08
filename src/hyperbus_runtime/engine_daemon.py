"""HyperBus engine sidecar — RPC gateway to HyperBusEngine."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


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
        default="/run/hyperbus/engine.sock",
        help="Unix domain socket path (Linux)",
    )
    parser.add_argument(
        "--listen",
        default="127.0.0.1:8080",
        help="HTTP listen address (fallback when socket unavailable)",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="Postgres URL (or set DATABASE_URL)",
    )
    args = parser.parse_args()
    msg = (
        "Engine daemon RPC server is not implemented yet. "
        f"Would start tenant={args.tenant!r} grants={args.grants} "
        f"socket={args.socket!r} listen={args.listen!r}"
    )
    print(msg, file=sys.stderr)
    sys.exit(1)
