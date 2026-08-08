"""Tests for engine daemon helpers."""

from __future__ import annotations

import pytest

from hyperbus_runtime.engine_daemon import _parse_listen, create_engine


def test_parse_listen() -> None:
    assert _parse_listen("127.0.0.1:8080") == ("127.0.0.1", 8080)


def test_parse_listen_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid"):
        _parse_listen("8080")


def test_create_engine_uses_in_memory_backend(grants_file) -> None:
    engine = create_engine(
        tenant_id="acme",
        grants_path=grants_file,
        database_url=None,
    )
    assert engine.tenant_id == "acme"
    assert engine.enforces_capabilities is True
