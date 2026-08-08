"""Background asyncio loop for threaded RPC servers."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

_T = TypeVar("_T")

_loop: asyncio.AbstractEventLoop | None = None
_loop_thread: threading.Thread | None = None
_loop_lock = threading.Lock()


def run_async(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run a coroutine on a dedicated background event loop."""
    loop = _ensure_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result()


def _ensure_loop() -> asyncio.AbstractEventLoop:
    global _loop, _loop_thread
    with _loop_lock:
        if _loop is None:
            loop = asyncio.new_event_loop()
            thread = threading.Thread(
                target=loop.run_forever,
                name="hyperbus-async-rpc",
                daemon=True,
            )
            thread.start()
            _loop = loop
            _loop_thread = thread
        return _loop


def reset_for_tests() -> None:
    global _loop, _loop_thread
    with _loop_lock:
        if _loop is not None:
            _loop.call_soon_threadsafe(_loop.stop)
            if _loop_thread is not None:
                _loop_thread.join(timeout=2)
        _loop = None
        _loop_thread = None
