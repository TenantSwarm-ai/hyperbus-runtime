"""Explicit allowlist of engine operations exposed over RPC."""

from __future__ import annotations

ALLOWED_ENGINE_OPS = frozenset(
    {
        "put",
        "get",
        "delete",
        "put_checkpoint_bundle",
        "load_checkpoint_bundle",
        "prime_latest_bundle",
        "clear_latest_bundle_cache",
        "put_writes_batch",
        "put_write",
        "list_writes",
        "has_write",
        "get_channel_values",
        "put_channel_value",
        "list_checkpoint_refs",
        "list_checkpoint_ids",
        "latest_checkpoint_id",
        "delete_thread",
        "delete_for_runs",
        "copy_thread",
        "list_run_checkpoint_refs",
        "prune_thread",
        "reclaim_blob_garbage",
        "aput",
        "aget",
        "adelete",
        "aput_checkpoint_bundle",
        "aload_checkpoint_bundle",
        "aput_writes_batch",
        "aput_write",
        "alist_writes",
        "ahas_write",
        "aget_channel_values",
        "aput_channel_value",
        "alist_checkpoint_refs",
        "alist_checkpoint_ids",
        "alatest_checkpoint_id",
        "adelete_thread",
        "adelete_for_runs",
        "acopy_thread",
        "alist_run_checkpoint_refs",
        "aprune_thread",
    }
)

ALLOWED_RUNTIME_AUDIT_EVENTS = frozenset(
    {
        "colocation.group.join",
        "colocation.ram.shared",
        "colocation.policy.override",
    }
)
