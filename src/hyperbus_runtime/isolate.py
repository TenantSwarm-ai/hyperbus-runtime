"""Process-level guard for the isolate isolation profile."""

from __future__ import annotations

import os
import threading

_BOUND_AGENT_ID: str | None = None
_isolate_lock = threading.Lock()


def register_isolate_agent(agent_id: str, *, profile: str) -> None:
    """Ensure one agent role per process under the isolate profile."""
    if profile != "isolate":
        return
    global _BOUND_AGENT_ID
    with _isolate_lock:
        if _BOUND_AGENT_ID is None:
            _BOUND_AGENT_ID = agent_id
            return
        if _BOUND_AGENT_ID != agent_id:
            msg = (
                f"isolate profile allows one agent_id per process; "
                f"already bound {_BOUND_AGENT_ID!r}, got {agent_id!r}"
            )
            raise RuntimeError(msg)


def reset_for_tests() -> None:
    global _BOUND_AGENT_ID
    with _isolate_lock:
        _BOUND_AGENT_ID = None


def bound_agent_id() -> str | None:
    return _BOUND_AGENT_ID


def pid_file_guard(agent_id: str, *, profile: str, tenant_id: str) -> None:
    """Optional on-disk guard for cohost/inline multi-import scenarios."""
    if profile not in ("cohost", "inline"):
        return
    path = os.environ.get("HB_ISOLATE_GUARD_FILE")
    if not path:
        return
    marker = f"{tenant_id}:{agent_id}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        existing = open(path, encoding="utf-8").read().strip()
        if existing and existing != marker:
            msg = (
                f"isolate guard file {path!r} binds {existing!r}; "
                f"refusing {marker!r}"
            )
            raise RuntimeError(msg)
        return
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(marker)
