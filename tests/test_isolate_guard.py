"""Tests for isolate profile process guard."""

from __future__ import annotations

import pytest

from hyperbus_runtime.isolate import register_isolate_agent, reset_for_tests


def setup_function() -> None:
    reset_for_tests()


def test_isolate_allows_single_agent_id() -> None:
    register_isolate_agent("support-bot", profile="isolate")
    register_isolate_agent("support-bot", profile="isolate")


def test_isolate_rejects_second_agent_id() -> None:
    register_isolate_agent("support-bot", profile="isolate")
    with pytest.raises(RuntimeError, match="one agent_id per process"):
        register_isolate_agent("billing-bot", profile="isolate")


def test_pool_profile_skips_guard() -> None:
    register_isolate_agent("support-bot", profile="pool")
    register_isolate_agent("billing-bot", profile="pool")
