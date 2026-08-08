"""Runtime configuration: worker identity and colocation policy."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_REQUIRED_ENV = ("HB_TENANT_ID", "HB_AGENT_ID")


@dataclass(frozen=True)
class WorkerContext:
    """Immutable identity bound at worker startup (not from LLM config)."""

    tenant_id: str
    agent_id: str
    default_region: str = "hyperbus-meta"
    colocate_group: str | None = None
    profile: str = "isolate"

    @classmethod
    def from_env(cls) -> WorkerContext:
        missing = [key for key in _REQUIRED_ENV if not os.environ.get(key)]
        if missing:
            msg = f"Worker identity env required: {', '.join(missing)}"
            raise RuntimeError(msg)
        return cls(
            tenant_id=os.environ["HB_TENANT_ID"],
            agent_id=os.environ["HB_AGENT_ID"],
            default_region=os.environ.get("HB_DEFAULT_REGION", "hyperbus-meta"),
            colocate_group=os.environ.get("HB_COLOCATE_GROUP"),
            profile=os.environ.get("HB_ISOLATION_PROFILE", "isolate"),
        )

    def langgraph_configurable(self) -> dict[str, str]:
        """Inject into LangGraph config; overrides caller-supplied hyperbus keys."""
        return {
            "hyperbus_tenant_id": self.tenant_id,
            "hyperbus_agent_id": self.agent_id,
            "hyperbus_region": self.default_region,
        }

    def validate_profile(self) -> None:
        if self.profile == "isolate" and self.colocate_group:
            msg = (
                "isolate profile must not set HB_COLOCATE_GROUP; "
                "use pool/cohost/inline for shared RAM"
            )
            raise RuntimeError(msg)
        if self.profile in ("pool", "cohost", "inline") and not self.colocate_group:
            msg = f"{self.profile} profile requires HB_COLOCATE_GROUP"
            raise RuntimeError(msg)


@dataclass
class ColocationGroup:
    name: str
    max_workers: int = 1
    shared_ram: bool = False
    trust: str = "same_agent_id"
    allow_ram_share_with: list[str] = field(default_factory=list)


@dataclass
class ColocationPolicy:
    tenant_id: str
    default_profile: str = "isolate"
    workers: list[dict[str, Any]] = field(default_factory=list)
    groups: dict[str, ColocationGroup] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ColocationPolicy:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        groups = {
            name: ColocationGroup(name=name, **spec)
            for name, spec in (raw.get("groups") or {}).items()
        }
        policy = raw.get("colocation_policy") or {}
        return cls(
            tenant_id=raw["tenant_id"],
            default_profile=policy.get("default_profile", "isolate"),
            workers=list(raw.get("workers") or []),
            groups=groups,
        )

    def worker_spec(self, worker_id: str) -> dict[str, Any] | None:
        for entry in self.workers:
            if entry.get("id") == worker_id:
                return entry
        return None

