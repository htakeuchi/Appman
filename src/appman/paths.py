"""XDG based directory layout used by AppMan.

The layout can be redirected for testing by setting ``APPMAN_HOME`` (the tool's
private data directory) and the usual ``XDG_*`` variables.
"""

from __future__ import annotations

import os


def _xdg(env: str, default: str) -> str:
    value = os.environ.get(env)
    if value and os.path.isabs(value):
        return value
    return os.path.join(os.path.expanduser("~"), default)


def home() -> str:
    override = os.environ.get("APPMAN_HOME")
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(_xdg("XDG_DATA_HOME", ".local/share"), "appman")


def apps_dir() -> str:
    return os.path.join(home(), "apps")


def db_dir() -> str:
    return os.path.join(home(), "db")


def backups_dir() -> str:
    return os.path.join(home(), "backups")


def logs_dir() -> str:
    return os.path.join(home(), "logs")


def applications_dir() -> str:
    return _xdg("XDG_DATA_HOME", ".local/share") + "/applications"


def icons_theme_dir() -> str:
    return _xdg("XDG_DATA_HOME", ".local/share") + "/icons"


def config_dir() -> str:
    return _xdg("XDG_CONFIG_HOME", ".config")


def bin_dir() -> str:
    return os.path.expanduser("~/.local/bin")


def appimage_path(app_id: str) -> str:
    return os.path.join(apps_dir(), f"{app_id}.AppImage")


def launcher_path(app_id: str) -> str:
    return os.path.join(applications_dir(), f"appman-{app_id}.desktop")


def db_path(app_id: str) -> str:
    return os.path.join(db_dir(), f"{app_id}.json")


def ensure_dirs() -> None:
    for directory in (home(), apps_dir(), db_dir(), backups_dir(), applications_dir()):
        os.makedirs(directory, exist_ok=True)


def icon_theme_name(app_id: str) -> str:
    return f"appman-{app_id}"


def icon_install_path(app_id: str, ext: str, size: str = "512x512") -> str:
    sub = "scalable" if ext in (".svg", ".svgz") else size
    return os.path.join(icons_theme_dir(), "hicolor", sub, "apps",
                        icon_theme_name(app_id) + ext)
