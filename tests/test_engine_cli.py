"""Tests for engine daemon CLI entrypoint."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from hyperbus_runtime import engine_daemon


def test_main_starts_and_stops(grants_file: Path, tmp_path: Path) -> None:
    sock = __import__("socket").socket()
    sock.bind(("127.0.0.1", 0))
    _, port = sock.getsockname()
    sock.close()

    argv = [
        "hyperbus-engine",
        "--tenant",
        "acme",
        "--grants",
        str(grants_file),
        "--listen",
        f"127.0.0.1:{port}",
    ]

    def stop_soon(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    with patch.object(engine_daemon, "serve_engine", side_effect=stop_soon):
        with patch("sys.argv", argv):
            with pytest.raises(KeyboardInterrupt):
                engine_daemon.main()
