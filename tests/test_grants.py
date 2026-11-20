"""Tests for grants YAML loading."""

from __future__ import annotations

import pytest
from hyperbus_core import Permission

from hyperbus_runtime.grants import load_grants_seed, load_grants_yaml


def test_load_grants_yaml(tmp_path) -> None:
    path = tmp_path / "grants.yaml"
    path.write_text(
        """
tenant_id: acme
grants:
  support-bot:
    support: READ_WRITE
""",
        encoding="utf-8",
    )
    registry = load_grants_yaml(path)
    assert registry.grants_for("support-bot")["support"] == Permission.READ_WRITE


def test_load_grants_yaml_tenant_mismatch(tmp_path) -> None:
    path = tmp_path / "grants.yaml"
    path.write_text("tenant_id: other\ngrants: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="tenant"):
        load_grants_yaml(path, tenant_id="acme")


def test_load_grants_seed_rejects_a_non_mapping_agent(tmp_path) -> None:
    path = tmp_path / "grants.yaml"
    path.write_text("tenant_id: acme\ngrants:\n  bot: READ\n", encoding="utf-8")
    with pytest.raises(ValueError, match="region map"):
        load_grants_seed(path)


def test_load_grants_seed_returns_permissions_without_applying(tmp_path) -> None:
    path = tmp_path / "grants.yaml"
    path.write_text(
        "tenant_id: acme\ngrants:\n  support-bot:\n    support: READ_WRITE\n",
        encoding="utf-8",
    )
    tenant, seed = load_grants_seed(path)
    assert tenant == "acme"
    assert seed == {"support-bot": {"support": Permission.READ_WRITE}}


def test_load_grants_yaml_unknown_permission(tmp_path) -> None:
    path = tmp_path / "grants.yaml"
    path.write_text(
        "tenant_id: acme\ngrants:\n  bot:\n    support: SUPER\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Unknown permission"):
        load_grants_yaml(path)
