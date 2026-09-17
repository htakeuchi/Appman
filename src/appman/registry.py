"""Persistent registry of installed AppImages (one JSON file per app)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field

from . import paths
from .util import atomic_write


@dataclass
class InstalledApp:
    id: str
    name: str
    version: str | None
    installed_at: str
    sha256: str | None
    size: int
    appimage_path: str
    original_filename: str
    source: str | None = None
    comment: str | None = None
    categories: str = "Utility;"
    wm_class: str | None = None
    exec_args: list[str] = field(default_factory=list)
    icon_path: str | None = None
    icon_theme_name: str | None = None
    launcher_path: str | None = None
    arch: str = "unknown"
    appimage_type: int | None = None
    appimage_schema_version: int = 1

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False) + "\n"

    @classmethod
    def from_dict(cls, data: dict) -> "InstalledApp":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


class RegistryError(Exception):
    pass


def load_all() -> list[InstalledApp]:
    result = []
    directory = paths.db_dir()
    if not os.path.isdir(directory):
        return result
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("id"):
            result.append(InstalledApp.from_dict(data))
    return result


def load(app_id: str) -> InstalledApp | None:
    path = paths.db_path(app_id)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"cannot read registry entry {path}: {exc}") from exc
    if not isinstance(data, dict) or not data.get("id"):
        raise RegistryError(f"invalid registry entry: {path}")
    return InstalledApp.from_dict(data)


def save(app: InstalledApp) -> None:
    paths.ensure_dirs()
    atomic_write(paths.db_path(app.id), app.to_json().encode("utf-8"))


def delete(app_id: str) -> None:
    try:
        os.unlink(paths.db_path(app_id))
    except FileNotFoundError:
        pass


def _aliases(app: InstalledApp) -> list[str]:
    values = [app.id, app.name]
    if app.original_filename:
        stem = app.original_filename
        for suffix in (".AppImage", ".appimage"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        values.append(stem)
    return [v.lower() for v in values if v]


def match(query: str, apps: list[InstalledApp] | None = None) -> InstalledApp | None:
    """Resolve *query* to a single installed app.

    Raises ``RegistryError`` when the query is ambiguous.
    """
    if apps is None:
        apps = load_all()
    q = query.strip().lower()
    if not q:
        return None
    for app in apps:
        if app.id.lower() == q:
            return app
    exact_name = [a for a in apps if a.name.lower() == q]
    if len(exact_name) == 1:
        return exact_name[0]
    candidates = [a for a in apps if any(q in alias for alias in _aliases(a))]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    ids = ", ".join(a.id for a in candidates)
    raise RegistryError(f"'{query}' is ambiguous; matches: {ids}")
