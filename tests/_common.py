"""Shared helpers for the AppMan test suite."""

from __future__ import annotations

import os


def sample_appimage() -> str | None:
    """Return the AppImage fixture, if one was provided.

    The heavier tests (SquashFS reader, installer lifecycle) need a real
    AppImage. Point ``APPMAN_TEST_APPIMAGE`` at one to enable them; they are
    skipped otherwise so the suite works on any machine.
    """
    candidate = os.environ.get("APPMAN_TEST_APPIMAGE")
    if candidate and os.path.isfile(candidate):
        return candidate
    return None
