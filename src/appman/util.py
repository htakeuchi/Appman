"""Assorted helpers shared by the AppMan commands."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


def human_size(num: int) -> str:
    value = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def atomic_write(path: str, data: bytes, mode: int = 0o644) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".appman-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def atomic_copy(src: str, dst: str, mode: int = 0o755) -> None:
    directory = os.path.dirname(dst) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".appman-", dir=directory)
    try:
        os.close(fd)
        shutil.copyfile(src, tmp)
        os.chmod(tmp, mode)
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def is_within(path: str, directory: str) -> bool:
    """Return True when *path* is contained in *directory*.

    Symlinks are resolved on both sides so a link inside the managed directory
    cannot point at a path outside of it.
    """
    path = os.path.realpath(os.path.abspath(path))
    directory = os.path.realpath(os.path.abspath(directory))
    return path == directory or path.startswith(directory + os.sep)


def confirm(prompt: str, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print(f"{prompt} [y/N] (non-interactive: pass --yes to confirm)",
              file=sys.stderr)
        return False
    try:
        answer = input(f"{prompt} [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def run_quiet(cmd: list[str]) -> bool:
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=30)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def which(program: str) -> str | None:
    return shutil.which(program)


def fuse_available() -> tuple[bool, str]:
    """Return ``(available, reason)`` for FUSE based AppImage mounting."""
    if not os.path.exists("/dev/fuse"):
        return False, "/dev/fuse does not exist"
    if which("fusermount3") is None and which("fusermount") is None:
        return False, "fusermount3/fusermount is not installed"
    return True, "ok"


def update_desktop_database(directory: str | None = None) -> None:
    if which("update-desktop-database"):
        run_quiet(["update-desktop-database", directory or ""])


def update_icon_cache(directory: str | None = None) -> None:
    if which("gtk-update-icon-cache") and directory and os.path.isdir(directory):
        run_quiet(["gtk-update-icon-cache", "-q", "-t", "-f", directory])
