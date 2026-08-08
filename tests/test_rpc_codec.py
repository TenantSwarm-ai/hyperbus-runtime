"""Tests for RPC codec roundtrips."""

from __future__ import annotations

from hyperbus_core import (
    ChannelValueRecord,
    CheckpointBundle,
    CheckpointRecord,
    CheckpointRef,
    RunCheckpointRef,
    WriteRecord,
)

from hyperbus_runtime.rpc_codec import decode, encode


def test_encode_decode_primitives() -> None:
    payload = {"count": 1, "ok": True, "name": "acme", "missing": None}
    assert decode(encode(payload)) == payload


def test_encode_decode_bytes() -> None:
    raw = b"\x00\xffcheckpoint"
    assert decode(encode(raw)) == raw


def test_encode_decode_checkpoint_record() -> None:
    record = CheckpointRecord(
        thread_id="t1",
        checkpoint_id="c1",
        state={"messages": []},
        metadata={"source": "test"},
        region="support",
    )
    restored = decode(encode(record))
    assert restored == record


def test_encode_decode_checkpoint_bundle() -> None:
    record = CheckpointRecord("t1", "c1", {"x": 1}, {})
    bundle = CheckpointBundle(
        record=record,
        channel_values={"messages": (["hi"], {})},
        pending_writes=[
            WriteRecord(task_id="t", write_idx=0, channel="messages", value="hi")
        ],
        indexed_channel_versions={"messages": "1"},
    )
    restored = decode(encode(bundle))
    assert restored == bundle


def test_encode_decode_refs() -> None:
    ref = CheckpointRef(checkpoint_ns="", checkpoint_id="c1")
    run_ref = RunCheckpointRef(thread_id="t1", checkpoint_ns="", checkpoint_id="c1")
    channel = ChannelValueRecord(channel="messages", version="1", value={"a": 1})
    assert decode(encode(ref)) == ref
    assert decode(encode(run_ref)) == run_ref
    assert decode(encode(channel)) == channel
