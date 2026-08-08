"""JSON codec for engine RPC payloads."""

from __future__ import annotations

import base64
from dataclasses import asdict, fields, is_dataclass
from typing import Any

from hyperbus_core import (
    ChannelValueRecord,
    CheckpointBundle,
    CheckpointRecord,
    CheckpointRef,
    RunCheckpointRef,
    WriteRecord,
)

_DATACLASS_TYPES: dict[str, type[Any]] = {
    "CheckpointRecord": CheckpointRecord,
    "CheckpointRef": CheckpointRef,
    "RunCheckpointRef": RunCheckpointRef,
    "WriteRecord": WriteRecord,
    "ChannelValueRecord": ChannelValueRecord,
    "CheckpointBundle": CheckpointBundle,
}


def encode(value: Any) -> Any:
    """Convert Python values to JSON-serializable structures."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"__type__": "bytes", "data": base64.b64encode(value).decode("ascii")}
    if isinstance(value, tuple):
        return {"__type__": "tuple", "items": [encode(item) for item in value]}
    if isinstance(value, list):
        return [encode(item) for item in value]
    if isinstance(value, dict):
        return {str(key): encode(item) for key, item in value.items()}
    if is_dataclass(value):
        payload = {field.name: encode(getattr(value, field.name)) for field in fields(value)}
        payload["__type__"] = type(value).__name__
        return payload
    msg = f"RPC codec cannot encode {type(value)!r}"
    raise TypeError(msg)


def decode(value: Any) -> Any:
    """Restore Python values from JSON structures."""
    if not isinstance(value, dict):
        if isinstance(value, list):
            return [decode(item) for item in value]
        return value
    type_name = value.get("__type__")
    if type_name == "bytes":
        return base64.b64decode(value["data"])
    if type_name == "tuple":
        return tuple(decode(item) for item in value["items"])
    if type_name in _DATACLASS_TYPES:
        cls = _DATACLASS_TYPES[type_name]
        kwargs = {
            field.name: decode(value[field.name])
            for field in fields(cls)
            if field.name in value
        }
        return cls(**kwargs)
    return {key: decode(item) for key, item in value.items()}
