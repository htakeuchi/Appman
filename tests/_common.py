"""Shared helpers for the AppMan test suite."""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile

_FIXTURE: str | None = None


def sample_appimage() -> str | None:
    """Return an AppImage fixture for the heavier tests.

    ``APPMAN_TEST_APPIMAGE`` takes precedence when it points at a file.
    Otherwise a tiny, valid type 2 AppImage is generated in pure Python so
    the SquashFS reader, installer and doctor tests always run instead of
    being skipped.

    Returns ``None`` only if the fixture cannot be built.
    """
    provided = os.environ.get("APPMAN_TEST_APPIMAGE")
    if provided and os.path.isfile(provided):
        return provided

    global _FIXTURE
    if _FIXTURE is not None:
        return _FIXTURE
    try:
        from _fixture import build_appimage

        directory = tempfile.mkdtemp(prefix="appman-fixture-")
        atexit.register(shutil.rmtree, directory, ignore_errors=True)
        _FIXTURE = build_appimage(
            os.path.join(directory, "Sample-1.0.AppImage")
        )
    except Exception:  # noqa: BLE001 - fall back to skipping the tests
        return None
    return _FIXTURE
