"""Diagnostics for installed AppImages."""

from __future__ import annotations

import os
import platform
import subprocess
import tempfile
from dataclasses import dataclass

from . import paths, registry
from .appimage import AppImageError, inspect
from .desktop import parse_desktop
from .squashfs import SquashFS
from .util import fuse_available, human_size, which

OK = "OK"
WARN = "WARN"
ERROR = "ERROR"
INFO = "INFO"

_STATUS_ORDER = {ERROR: 0, WARN: 1, INFO: 2, OK: 3}


@dataclass
class Check:
    status: str
    title: str
    detail: str = ""
    hint: str = ""

    def render(self) -> str:
        line = f"[{self.status:5}] {self.title}"
        if self.detail:
            line += f": {self.detail}"
        return line


def _system_arch() -> str:
    machine = platform.machine()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)


def global_checks() -> list[Check]:
    checks: list[Check] = []
    home = paths.home()
    if os.path.isdir(home):
        if os.access(home, os.W_OK):
            checks.append(Check(OK, "AppMan data directory", home))
        else:
            checks.append(Check(ERROR, "AppMan data directory not writable", home,
                                "Check permissions on the directory."))
    else:
        checks.append(Check(INFO, "AppMan data directory", f"{home} (not created yet)"))

    available, reason = fuse_available()
    if available:
        checks.append(Check(OK, "FUSE", "available (AppImages mount normally)"))
    else:
        checks.append(Check(WARN, "FUSE unavailable", reason,
                            "AppMan will fall back to APPIMAGE_EXTRACT_AND_RUN=1."))

    if which("update-desktop-database"):
        checks.append(Check(OK, "update-desktop-database", "found"))
    else:
        checks.append(Check(WARN, "update-desktop-database", "not found",
                            "Install desktop-file-utils for reliable launcher updates."))
    return checks


def app_checks(app: registry.InstalledApp, deep: bool = False) -> list[Check]:
    checks: list[Check] = []
    path = app.appimage_path

    if not os.path.exists(path):
        checks.append(Check(ERROR, "AppImage file", f"missing: {path}",
                            "Reinstall the application."))
        return checks

    if not os.path.isfile(path):
        checks.append(Check(ERROR, "AppImage file", f"not a regular file: {path}"))
        return checks

    if os.access(path, os.R_OK):
        checks.append(Check(OK, "AppImage file", f"{human_size(os.path.getsize(path))}"))
    else:
        checks.append(Check(ERROR, "AppImage file", "not readable",
                            f"chmod +r {path}"))

    if os.access(path, os.X_OK):
        checks.append(Check(OK, "Executable bit", "set"))
    else:
        checks.append(Check(ERROR, "Executable bit", "missing",
                            f"chmod +x {path}"))

    try:
        meta = inspect(path)
        checks.append(Check(OK, "AppImage format", f"type {meta.appimage_type}"))
        if meta.sha256 and app.sha256:
            if meta.sha256 == app.sha256:
                checks.append(Check(OK, "SHA-256", "matches installed record"))
            else:
                checks.append(Check(ERROR, "SHA-256", "does not match installed record",
                                    "The file changed. Reinstall if this is unexpected."))
        if meta.arch and app.arch and meta.arch != app.arch:
            checks.append(Check(ERROR, "Architecture",
                                f"AppImage is {meta.arch}, recorded {app.arch}"))
        elif meta.arch:
            checks.append(Check(INFO, "Architecture", meta.arch))
    except AppImageError as exc:
        checks.append(Check(ERROR, "AppImage format", str(exc),
                            "Re-download the AppImage (the file is corrupt)."))
        return checks

    system_arch = _system_arch()
    if app.arch and app.arch not in (system_arch, "unknown"):
        checks.append(Check(ERROR, "Architecture match",
                            f"{app.arch} != host {system_arch}",
                            "Install the build matching your CPU architecture."))
    elif app.arch:
        checks.append(Check(OK, "Architecture match", system_arch))

    checks.extend(_launcher_checks(app))
    checks.extend(_icon_checks(app))

    try:
        with open(path, "rb") as fileobj:
            elf_info = _payload_offset(path)
            squash = SquashFS(fileobj, elf_info)
            entries = squash.readdir(squash.root_inode_ref)
        checks.append(Check(OK, "SquashFS payload",
                            f"{len(entries)} entries at root"))
        have_apprun = any(name == "AppRun" for name, _r, _i in entries)
        if have_apprun:
            checks.append(Check(OK, "AppRun", "present"))
        else:
            checks.append(Check(WARN, "AppRun", "not found at image root",
                                "AppImages normally ship an AppRun entry point."))
    except Exception as exc:  # noqa: BLE001
        checks.append(Check(ERROR, "SquashFS payload", str(exc),
                            "The embedded filesystem cannot be read."))

    checks.extend(_runtime_checks(path, deep))
    return checks


def _payload_offset(path: str) -> int:
    from .appimage import read_elf_info

    with open(path, "rb") as fileobj:
        info = read_elf_info(fileobj)
    if info.payload_offset is None:
        raise AppImageError("payload offset not found")
    return info.payload_offset


def _launcher_checks(app: registry.InstalledApp) -> list[Check]:
    checks: list[Check] = []
    launcher = app.launcher_path or paths.launcher_path(app.id)
    if not os.path.exists(launcher):
        checks.append(Check(ERROR, "Launcher entry", f"missing: {launcher}",
                            "Reinstall to recreate the desktop entry."))
        return checks
    checks.append(Check(OK, "Launcher entry", launcher))
    try:
        with open(launcher, encoding="utf-8") as handle:
            entry = parse_desktop(handle.read())
    except OSError as exc:
        checks.append(Check(ERROR, "Launcher entry", str(exc)))
        return checks
    exec_line = entry.get("Exec", "")
    if app.appimage_path in exec_line:
        checks.append(Check(OK, "Launcher Exec", "points at installed AppImage"))
    else:
        checks.append(Check(WARN, "Launcher Exec",
                            f"does not reference {app.appimage_path}",
                            "Reinstall to refresh the launcher entry."))
    if entry.get("Icon"):
        checks.append(Check(OK, "Launcher Icon", entry["Icon"]))
    else:
        checks.append(Check(INFO, "Launcher Icon", "not set"))
    return checks


def _icon_checks(app: registry.InstalledApp) -> list[Check]:
    checks: list[Check] = []
    if not app.icon_path:
        checks.append(Check(INFO, "Icon", "not recorded (application ships none)"))
        return checks
    if os.path.exists(app.icon_path):
        checks.append(Check(OK, "Icon", app.icon_path))
    else:
        checks.append(Check(WARN, "Icon", f"missing: {app.icon_path}",
                            "Reinstall to extract the icon again."))
    return checks


def _runtime_checks(path: str, deep: bool) -> list[Check]:
    if not deep:
        return [Check(
            INFO, "Runtime execution",
            "skipped; use 'doctor --deep' to execute the AppImage runtime "
            "(runs untrusted code)",
        )]
    checks: list[Check] = []
    env = dict(os.environ)
    available, _reason = fuse_available()
    if not available:
        env["APPIMAGE_EXTRACT_AND_RUN"] = "1"

    for flag in ("--appimage-version", "--appimage-offset"):
        try:
            result = subprocess.run(
                [path, flag], capture_output=True, text=True, timeout=15,
                env=env, cwd=tempfile.gettempdir(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            checks.append(Check(WARN, f"Runtime probe {flag}", str(exc)))
            continue
        output = (result.stdout or result.stderr).strip().splitlines()
        summary = output[-1] if output else ""
        if result.returncode == 0 and summary:
            checks.append(Check(OK, f"Runtime probe {flag}", summary))
        else:
            checks.append(Check(WARN, f"Runtime probe {flag}",
                                summary or f"exit {result.returncode}"))

    if deep:
        checks.extend(_deep_extract_check(path))
    return checks


def _deep_extract_check(path: str) -> list[Check]:
    with tempfile.TemporaryDirectory(prefix="appman-doctor-") as workdir:
        env = dict(os.environ)
        available, _reason = fuse_available()
        if not available:
            env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
        try:
            result = subprocess.run(
                [path, "--appimage-extract", "*.desktop"],
                capture_output=True, text=True, timeout=180, env=env, cwd=workdir,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [Check(WARN, "Payload extraction", str(exc))]
        extracted = os.path.join(workdir, "squashfs-root")
        if result.returncode == 0 and os.path.isdir(extracted):
            names = os.listdir(extracted)
            return [Check(OK, "Payload extraction", f"ok ({len(names)} top level items)")]
        return [Check(ERROR, "Payload extraction",
                      (result.stderr or result.stdout).strip()[:200],
                      "The AppImage payload cannot be extracted.")]


def summarize(checks: list[Check]) -> tuple[int, int, int]:
    errors = sum(1 for c in checks if c.status == ERROR)
    warnings = sum(1 for c in checks if c.status == WARN)
    return errors, warnings, len(checks)
