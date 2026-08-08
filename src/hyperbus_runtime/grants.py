"""Load capability grants from YAML for the engine sidecar."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from hyperbus_core import AuditSink, CapabilityRegistry, Permission

_PERMISSIONS = {
    "NONE": Permission.NONE,
    "READ": Permission.READ,
    "WRITE": Permission.WRITE,
    "READ_WRITE": Permission.READ_WRITE,
}


def _parse_permission(raw: str) -> Permission:
    try:
        return _PERMISSIONS[raw.upper()]
    except KeyError as exc:
        msg = f"Unknown permission {raw!r}; expected one of {sorted(_PERMISSIONS)}"
        raise ValueError(msg) from exc


def load_grants_yaml(
    path: str | Path,
    *,
    tenant_id: str | None = None,
    audit: AuditSink | None = None,
) -> CapabilityRegistry:
    """Build a tenant-scoped registry from a grants YAML file."""
    raw: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    file_tenant = raw.get("tenant_id")
    resolved_tenant = tenant_id or file_tenant
    if not resolved_tenant:
        msg = "grants YAML must include tenant_id or pass --tenant"
        raise ValueError(msg)
    if file_tenant and tenant_id and file_tenant != tenant_id:
        msg = f"grants tenant {file_tenant!r} != engine tenant {tenant_id!r}"
        raise ValueError(msg)

    registry = CapabilityRegistry(tenant_id=resolved_tenant, audit=audit)
    grants = raw.get("grants") or {}
    for agent_id, regions in grants.items():
        if not isinstance(regions, dict):
            msg = f"grants for {agent_id!r} must be a region map"
            raise ValueError(msg)
        for region, permission_name in regions.items():
            registry.grant(agent_id, region, _parse_permission(str(permission_name)))
    return registry
