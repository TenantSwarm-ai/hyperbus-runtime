"""Operator-held audit checkpoints for verified boot (spec 003 AC-6.6, core 014 AC-14.24).

A checkpoint is the chain tip the operator recorded from a verified replay. Boot
replays the log against it, so events removed from the end of the log are
detected. The engine never fetches a checkpoint from the network (AC-7.1).

File format (YAML)::

    tenant_id: acme
    sequence: 42
    event_hash: "<64 lowercase hex characters>"
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from hyperbus_core import (
    GrantReplayStore,
    PostgresAuditStore,
    checkpoint_of,
    replay_tenant_grants,
)

_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")


def load_audit_checkpoint(path: str | Path, *, tenant_id: str) -> tuple[int, str]:
    """Read and validate a checkpoint file for ``tenant_id``."""
    raw: Any = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        msg = "audit checkpoint must be a YAML mapping"
        raise ValueError(msg)
    if raw.get("tenant_id") != tenant_id:
        msg = f"audit checkpoint is for tenant {raw.get('tenant_id')!r}, not {tenant_id!r}"
        raise ValueError(msg)
    sequence = raw.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        msg = "audit checkpoint sequence must be a non-negative integer"
        raise ValueError(msg)
    digest = raw.get("event_hash")
    if not isinstance(digest, str) or not _HASH_PATTERN.fullmatch(digest):
        msg = "audit checkpoint event_hash must be 64 lowercase hex characters"
        raise ValueError(msg)
    return (sequence, digest)


def write_audit_checkpoint(
    path: str | Path,
    store: GrantReplayStore,
    *,
    tenant_id: str,
) -> tuple[int, str]:
    """Record the verified tip of ``tenant_id``'s log in a new checkpoint file.

    Refuses to overwrite an existing file, because an anchor is replaced only by
    an explicit operator action. The replay verifies the chain first, so a
    damaged log cannot be checkpointed.
    """
    target = Path(path)
    if target.exists():
        msg = f"audit checkpoint {str(target)!r} already exists; move it aside to replace it"
        raise FileExistsError(msg)
    sequence, digest = checkpoint_of(replay_tenant_grants(store, tenant_id))
    document = {"tenant_id": tenant_id, "sequence": sequence, "event_hash": digest}
    target.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return (sequence, digest)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Write a verified audit checkpoint for one tenant (run once, keep offline)",
    )
    parser.add_argument("--tenant", required=True, help="Tenant id to checkpoint")
    parser.add_argument("--out", required=True, type=Path, help="New checkpoint file")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL holding the audit log (or set DATABASE_URL)",
    )
    args = parser.parse_args(argv)
    if not args.database_url:
        sys.exit("audit-checkpoint: a Postgres URL is required (--database-url or DATABASE_URL)")
    with PostgresAuditStore(args.database_url) as store:
        sequence, digest = write_audit_checkpoint(args.out, store, tenant_id=args.tenant)
    print(
        f"wrote {args.out} at sequence {sequence} ({digest[:12]}...)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
