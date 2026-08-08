"""Adversarial penetration tests — spec §7 verification."""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest
from hyperbus_core import CapabilityError
from langgraph.checkpoint.base import Checkpoint, CheckpointMetadata

from hyperbus_runtime import shared
from hyperbus_runtime.client import _RpcTransportClient
from hyperbus_runtime.config import WorkerContext
from hyperbus_runtime.rpc_dispatch import dispatch_request
from hyperbus_runtime.worker import bind_from_env, checkpointer, inject_langgraph_config

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestIdentitySpoofing:
    """AC-2.3 / US-2: prompt injection cannot elevate grants via graph config."""

    def test_graph_config_agent_spoof_still_writes_support_region(
        self,
        engine_server,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        url, _engine = engine_server
        monkeypatch.setenv("HB_TENANT_ID", "acme")
        monkeypatch.setenv("HB_AGENT_ID", "support-bot")
        monkeypatch.setenv("HB_DEFAULT_REGION", "support")
        monkeypatch.setenv("HYPERBUS_ENGINE_URL", url)
        saver = checkpointer()
        config = inject_langgraph_config(
            {
                "configurable": {
                    "thread_id": "ticket-spoof",
                    "hyperbus_agent_id": "billing-bot",
                    "hyperbus_region": "billing",
                }
            }
        )
        checkpoint: Checkpoint = {
            "v": 1,
            "id": "c-spoof",
            "ts": "2026-01-01T00:00:00Z",
            "channel_values": {"secret": "support-data"},
            "channel_versions": {"secret": 1},
            "versions_seen": {},
            "updated_channels": {"secret"},
        }
        metadata: CheckpointMetadata = {"source": "pentest", "step": 1, "writes": {}}
        saver.put(config, checkpoint, metadata, {"secret": 1})

        client = _RpcTransportClient(http_url=url)
        with pytest.raises(CapabilityError):
            client.call(
                "get",
                tenant_id="acme",
                agent_id="billing-bot",
                args=["ticket-spoof", "c-spoof"],
                kwargs={"region": "support"},
            )
        record = client.call(
            "get",
            tenant_id="acme",
            agent_id="support-bot",
            args=["ticket-spoof", "c-spoof"],
            kwargs={"region": "support"},
        )
        assert record is not None

    def test_billing_agent_cannot_read_support_checkpoint(
        self,
        engine_server,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        url, _engine = engine_server
        client = _RpcTransportClient(http_url=url)
        client.call(
            "put",
            tenant_id="acme",
            agent_id="support-bot",
            args=["ticket-8812", "c1"],
            kwargs={
                "state": {"pii": "customer@example.com"},
                "metadata": {},
                "region": "support",
            },
        )
        with pytest.raises(CapabilityError):
            client.call(
                "get",
                tenant_id="acme",
                agent_id="billing-bot",
                args=["ticket-8812", "c1"],
                kwargs={"region": "support"},
            )


class TestRpcAuthentication:
    """AC-1.3: every RPC must carry agent_id; engine rejects malformed calls."""

    def test_rpc_without_agent_id_rejected(self, engine_server) -> None:
        _, engine = engine_server
        response = dispatch_request(
            engine,
            {"op": "runtime.ping", "tenant_id": "acme"},
            expected_tenant_id="acme",
        )
        assert response["ok"] is False
        assert response["error"]["type"] == "RpcValidationError"

    def test_rpc_without_tenant_id_rejected(self, engine_server) -> None:
        _, engine = engine_server
        response = dispatch_request(
            engine,
            {"op": "runtime.ping", "agent_id": "support-bot"},
            expected_tenant_id="acme",
        )
        assert response["ok"] is False
        assert response["error"]["type"] == "RpcValidationError"

    def test_rpc_wrong_tenant_rejected(self, engine_server) -> None:
        _, engine = engine_server
        response = dispatch_request(
            engine,
            {
                "op": "runtime.ping",
                "tenant_id": "evil-corp",
                "agent_id": "support-bot",
            },
            expected_tenant_id="acme",
        )
        assert response["ok"] is False
        assert "tenant" in response["error"]["message"].lower()

    def test_rpc_kwargs_agent_id_spoof_rejected(self, engine_server) -> None:
        _, engine = engine_server
        response = dispatch_request(
            engine,
            {
                "op": "put",
                "tenant_id": "acme",
                "agent_id": "support-bot",
                "args": ["t1", "c1"],
                "kwargs": {
                    "state": {},
                    "metadata": {},
                    "region": "billing",
                    "agent_id": "billing-bot",
                },
            },
            expected_tenant_id="acme",
        )
        assert response["ok"] is False
        assert response["error"]["type"] == "RpcValidationError"

    def test_unsupported_op_rejected(self, engine_server) -> None:
        _, engine = engine_server
        response = dispatch_request(
            engine,
            {
                "op": "_authorize",
                "tenant_id": "acme",
                "agent_id": "support-bot",
            },
            expected_tenant_id="acme",
        )
        assert response["ok"] is False
        assert response["error"]["type"] == "RpcValidationError"


class TestWorkerContainment:
    """AC-3.1 / AC-3.2: workers must not hold direct backend access."""

    def test_worker_dockerfile_excludes_postgres_extra(self) -> None:
        dockerfile = (REPO_ROOT / "Dockerfile.worker").read_text(encoding="utf-8")
        assert "[postgres]" not in dockerfile
        assert "DATABASE_URL" not in dockerfile

    def test_worker_package_has_no_postgres_optional_in_install(self) -> None:
        dockerfile = (REPO_ROOT / "Dockerfile.worker").read_text(encoding="utf-8")
        assert re.search(r"pip install[^\n]*\.", dockerfile)
        assert "postgres" not in dockerfile.lower().split("pip install")[-1]

    def test_worker_modules_avoid_postgres_backend_import(self) -> None:
        worker_sources = (REPO_ROOT / "src" / "hyperbus_runtime").glob("*.py")
        forbidden = ("PostgresBackend", "postgres", "psycopg")
        for path in worker_sources:
            if path.name == "engine_daemon.py":
                continue
            text = path.read_text(encoding="utf-8")
            for token in forbidden:
                assert token not in text, f"{path.name} references forbidden {token!r}"

    def test_worker_runtime_has_no_storage_backend_import(self) -> None:
        import ast

        worker_modules = (
            "hyperbus_runtime.client",
            "hyperbus_runtime.worker",
            "hyperbus_runtime.checkpointer",
        )
        for module_name in worker_modules:
            module = importlib.import_module(module_name)
            source = Path(module.__file__).read_text(encoding="utf-8")
            tree = ast.parse(source)
            imported = {
                alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imported.update(
                node.module
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            )
            assert "hyperbus_core.backend" not in imported
            assert "PostgresBackend" not in imported


class TestColocationBoundaries:
    """AC-5.2: colocation groups must not leak RAM by default namespace binding."""

    def test_different_groups_use_isolated_default_namespaces(self) -> None:
        shared._group_stores.clear()
        shared.bind_context(
            WorkerContext(
                tenant_id="acme",
                agent_id="support-bot",
                profile="pool",
                colocate_group="support-pool",
            )
        )
        shared.namespace()["secret"] = "support-cache"

        shared.bind_context(
            WorkerContext(
                tenant_id="acme",
                agent_id="billing-bot",
                profile="pool",
                colocate_group="billing-solo",
            )
        )
        assert "secret" not in shared.namespace()

    def test_isolate_profile_blocks_shared_ram(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HB_TENANT_ID", "acme")
        monkeypatch.setenv("HB_AGENT_ID", "support-bot")
        monkeypatch.setenv("HB_ISOLATION_PROFILE", "isolate")
        monkeypatch.setenv("HYPERBUS_ENGINE_URL", "http://127.0.0.1:1")
        bind_from_env()
        with pytest.raises(RuntimeError, match="isolate profile"):
            shared.namespace()


class TestTenantIsolation:
    """Structural attacks on tenant/thread identifiers."""

    def test_malicious_thread_id_rejected(self, engine_server) -> None:
        _, engine = engine_server
        response = dispatch_request(
            engine,
            {
                "op": "put",
                "tenant_id": "acme",
                "agent_id": "support-bot",
                "args": ["../other-tenant/thread", "c1"],
                "kwargs": {"state": {}, "metadata": {}, "region": "support"},
            },
            expected_tenant_id="acme",
        )
        assert response["ok"] is False
        assert response["error"]["type"] == "TenantIsolationError"

    def test_support_cannot_list_billing_region_checkpoints(
        self,
        engine_server,
    ) -> None:
        url, _engine = engine_server
        client = _RpcTransportClient(http_url=url)
        client.call(
            "put",
            tenant_id="acme",
            agent_id="billing-bot",
            args=["invoice-thread", "c1"],
            kwargs={"state": {"total": 999}, "metadata": {}, "region": "billing"},
        )
        with pytest.raises(CapabilityError):
            client.call(
                "list_checkpoint_refs",
                tenant_id="acme",
                agent_id="support-bot",
                args=["invoice-thread"],
                kwargs={"region": "billing"},
            )
