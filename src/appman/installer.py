"""Install / remove AppImages as desktop applications."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field

from . import paths, registry
from .appimage import (AppImageError, AppImageMetadata, icon_size_dir, inspect,
                       read_elf_info, sha256_file)
from .desktop import build_exec, escape_value
from .util import (atomic_copy, atomic_write, confirm, is_within, timestamp,
                   update_desktop_database, update_icon_cache, utc_now_iso)


class InstallError(Exception):
    pass


@dataclass
class InstallOutcome:
    app: registry.InstalledApp
    replaced: bool = False
    already_installed: bool = False
    backup_path: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class RemoveOutcome:
    removed: list[str] = field(default_factory=list)
    backed_up: str | None = None


# ----------------------------------------------------------------------
# install
# ----------------------------------------------------------------------
def _fallback_metadata(source: str, reason: str) -> AppImageMetadata:
    with open(source, "rb") as fileobj:
        elf = read_elf_info(fileobj)
    meta = AppImageMetadata(
        path=os.path.abspath(source),
        size=os.path.getsize(source),
        appimage_type=elf.appimage_type,
        arch=elf.machine,
        payload_offset=elf.payload_offset,
        sha256=sha256_file(source),
    )
    from .appimage import _app_id_from_filename, _version_from_filename

    meta.app_id = _app_id_from_filename(source)
    meta.name = meta.app_id.replace("-", " ").title()
    meta.version = _version_from_filename(source)
    meta.warnings.append(reason)
    return meta


def _build_desktop(app: registry.InstalledApp) -> str:
    lines = ["[Desktop Entry]", "Type=Application",
             f"Name={escape_value(app.name)}"]
    if app.comment:
        lines.append(f"Comment={escape_value(app.comment)}")
    lines.append("Exec=" + build_exec(app.appimage_path, list(app.exec_args)))
    if app.icon_theme_name:
        lines.append(f"Icon={escape_value(app.icon_theme_name)}")
    if app.wm_class:
        lines.append(f"StartupWMClass={escape_value(app.wm_class)}")
    lines.append("Terminal=false")
    lines.append(f"Categories={escape_value(app.categories or 'Utility;')}")
    lines.append(f"X-AppMan-Id={escape_value(app.id)}")
    if app.version:
        lines.append(f"X-AppMan-Version={escape_value(app.version)}")
    if app.original_filename:
        lines.append(f"X-AppMan-Original={escape_value(app.original_filename)}")
    return "\n".join(lines) + "\n"


def _stage_appimage(source: str, dest: str) -> None:
    atomic_copy(source, dest, mode=0o755)


def install(source: str, *, force: bool = False, yes: bool = False,
            dry_run: bool = False) -> InstallOutcome:
    source = os.path.abspath(os.path.expanduser(source))
    if not os.path.isfile(source):
        raise InstallError(f"file not found: {source}")

    try:
        meta = inspect(source)
    except AppImageError as exc:
        try:
            with open(source, "rb") as fileobj:
                elf = read_elf_info(fileobj)
        except AppImageError:
            raise InstallError(str(exc)) from exc
        if elf.appimage_type != 2:
            raise InstallError(str(exc)) from exc
        if not force:
            raise InstallError(
                f"{exc}\nUse --force to install it anyway (metadata will be "
                f"derived from the filename)."
            ) from exc
        meta = _fallback_metadata(source, f"metadata unavailable: {exc}")

    app_id = meta.app_id
    if not app_id:
        raise InstallError("could not determine an application id")

    try:
        existing = registry.load(app_id)
    except registry.RegistryError as exc:
        if not force:
            raise InstallError(
                f"existing registry entry for '{app_id}' is unreadable: {exc}\n"
                f"Use --force to overwrite it."
            ) from exc
        existing = None
    orphan_appimage = os.path.exists(paths.appimage_path(app_id)) and existing is None

    if existing is not None:
        same = bool(existing.sha256 and meta.sha256 and existing.sha256 == meta.sha256)
        if same and not force:
            return InstallOutcome(app=existing, already_installed=True,
                                  warnings=meta.warnings)
        if not dry_run and not force:
            if not confirm(
                f"'{existing.id}' is already installed"
                + (f" (version {existing.version})" if existing.version else "")
                + f". Replace it with '{os.path.basename(source)}'?",
                assume_yes=yes,
            ):
                raise InstallError("aborted: existing installation left untouched")
    elif orphan_appimage and not force:
        raise InstallError(
            f"{paths.appimage_path(app_id)} already exists but is not registered "
            f"(orphan). Re-run with --force to overwrite it."
        )

    app = registry.InstalledApp(
        id=app_id,
        name=meta.name or app_id,
        version=meta.version,
        installed_at=utc_now_iso(),
        sha256=meta.sha256,
        size=meta.size,
        appimage_path=paths.appimage_path(app_id),
        original_filename=os.path.basename(source),
        source=source,
        comment=meta.comment,
        categories=meta.categories or "Utility;",
        wm_class=meta.wm_class,
        exec_args=[a for a in meta.exec_args if not a.startswith("--appimage")],
        arch=meta.arch,
        appimage_type=meta.appimage_type,
    )
    if meta.icon_bytes:
        ext = meta.icon_ext or ".png"
        size = icon_size_dir(ext, meta.icon_bytes)
        app.icon_path = paths.icon_install_path(app_id, ext, size)
        app.icon_theme_name = paths.icon_theme_name(app_id)
    app.launcher_path = paths.launcher_path(app_id)

    if dry_run:
        print(f"[dry-run] would install '{app.id}'")
        print(f"  appimage : {app.appimage_path}")
        if app.icon_path:
            print(f"  icon     : {app.icon_path}")
        print(f"  launcher : {app.launcher_path}")
        return InstallOutcome(app=app, replaced=existing is not None,
                              warnings=meta.warnings)

    paths.ensure_dirs()
    backup_path = None
    created: list[str] = []
    stashed: list[tuple[str, str]] = []
    stash_targets = {app.launcher_path, paths.db_path(app.id)}
    if app.icon_path:
        stash_targets.add(app.icon_path)
    if existing is not None and existing.icon_path:
        stash_targets.add(existing.icon_path)

    try:
        if os.path.lexists(app.appimage_path):
            backup_path = _backup_file(app.appimage_path, app.id, "AppImage")
        for path in stash_targets:
            if os.path.lexists(path):
                stashed.append((path, _stash(path)))

        _stage_appimage(source, app.appimage_path)
        created.append(app.appimage_path)

        # Recompute integrity data from the installed copy to avoid a
        # time-of-check/time-of-use gap between hashing and copying.
        app.sha256 = sha256_file(app.appimage_path)
        app.size = os.path.getsize(app.appimage_path)

        if app.icon_path and meta.icon_bytes:
            atomic_write(app.icon_path, meta.icon_bytes, mode=0o644)
            created.append(app.icon_path)

        atomic_write(app.launcher_path, _build_desktop(app).encode("utf-8"), mode=0o644)
        created.append(app.launcher_path)

        registry.save(app)
        created.append(paths.db_path(app.id))
    except BaseException:
        for path in reversed(created):
            _safe_unlink(path)
        for original, saved in reversed(stashed):
            try:
                os.replace(saved, original)
            except OSError:
                pass
        if backup_path and os.path.exists(backup_path):
            os.makedirs(os.path.dirname(app.appimage_path), exist_ok=True)
            os.replace(backup_path, app.appimage_path)
        raise
    else:
        for _original, saved in stashed:
            _safe_unlink(saved)

    update_desktop_database(paths.applications_dir())
    if app.icon_path:
        update_icon_cache(os.path.join(paths.icons_theme_dir(), 'hicolor'))

    return InstallOutcome(app=app, replaced=existing is not None,
                          backup_path=backup_path, warnings=meta.warnings)


def _backup_file(path: str, app_id: str, kind: str) -> str:
    os.makedirs(paths.backups_dir(), exist_ok=True)
    target = os.path.join(paths.backups_dir(), f"{app_id}-{timestamp()}.{kind}")
    suffix = 1
    while os.path.exists(target):
        target = os.path.join(
            paths.backups_dir(), f"{app_id}-{timestamp()}-{suffix}.{kind}"
        )
        suffix += 1
    os.replace(path, target)
    return target


def _safe_unlink(path: str) -> None:
    try:
        if os.path.islink(path) or os.path.exists(path):
            os.unlink(path)
    except OSError:
        pass


def _stash(path: str) -> str:
    """Move *path* to a hidden sibling file and return its temporary name."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".appman-rollback-", dir=directory)
    os.close(fd)
    os.unlink(tmp)
    os.replace(path, tmp)
    return tmp


# ----------------------------------------------------------------------
# remove
# ----------------------------------------------------------------------
def _managed_paths(app: registry.InstalledApp) -> list[str]:
    candidates = []
    mapping = [
        (app.appimage_path, paths.apps_dir()),
        (app.icon_path, paths.icons_theme_dir()),
        (app.launcher_path, paths.applications_dir()),
        (paths.db_path(app.id), paths.db_dir()),
    ]
    for path, managed_dir in mapping:
        if not path or not is_within(path, managed_dir):
            continue
        if managed_dir == paths.applications_dir():
            if not os.path.basename(path).startswith("appman-"):
                continue
        candidates.append(path)
    return candidates


def remove(app: registry.InstalledApp, *, yes: bool = False, dry_run: bool = False,
           backup: bool = False) -> RemoveOutcome:
    outcome = RemoveOutcome()
    targets = _managed_paths(app)
    existing = [p for p in targets if os.path.lexists(p)]

    if dry_run:
        print(f"[dry-run] would remove '{app.id}':")
        for path in existing:
            print(f"  {path}")
        if backup and os.path.lexists(app.appimage_path):
            print(f"  (appimage backed up under {paths.backups_dir()})")
        return outcome

    if not confirm(f"Remove '{app.id}' and its launcher/icon?", assume_yes=yes):
        raise InstallError("aborted: nothing was removed")

    errors: list[str] = []
    for path in existing:
        if backup and path == app.appimage_path:
            outcome.backed_up = _backup_file(path, app.id, "AppImage")
            continue
        try:
            os.unlink(path)
            outcome.removed.append(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"{path}: {exc}")

    if outcome.backed_up:
        outcome.removed.append(f"backed up -> {outcome.backed_up}")

    try:
        registry.delete(app.id)
    except OSError as exc:
        errors.append(f"{paths.db_path(app.id)}: {exc}")

    update_desktop_database(paths.applications_dir())
    if app.icon_path:
        update_icon_cache(os.path.join(paths.icons_theme_dir(), 'hicolor'))

    if errors:
        raise InstallError(
            "some files could not be removed:\n  " + "\n  ".join(errors)
        )
    return outcome
