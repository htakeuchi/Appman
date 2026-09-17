"""Command line interface for AppMan."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from . import __version__, doctor, installer, paths, registry
from .appimage import AppImageError
from .installer import InstallError
from .registry import RegistryError
from .util import fuse_available, human_size


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appman",
        description="Install and manage AppImages like regular applications "
                    "(designed for Omarchy / Arch Linux).",
    )
    parser.add_argument("--version", action="version",
                        version=f"appman {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_install = sub.add_parser("install", help="install an AppImage")
    p_install.add_argument("file", help="path to the .AppImage file")
    p_install.add_argument("--force", action="store_true",
                           help="overwrite an existing install, even if broken")
    p_install.add_argument("--yes", action="store_true",
                           help="assume yes for confirmation prompts")
    p_install.add_argument("--dry-run", action="store_true",
                           help="show what would happen without changing anything")

    p_list = sub.add_parser("list", help="list installed AppImages")
    p_list.add_argument("--json", action="store_true", help="output JSON")

    p_info = sub.add_parser("info", help="show information about an app")
    p_info.add_argument("app")
    p_info.add_argument("--json", action="store_true", help="output JSON")

    p_run = sub.add_parser("run", help="run an installed app")
    p_run.add_argument("--extract-and-run", action="store_true",
                       help="force extraction instead of FUSE mounting")
    p_run.add_argument("app")
    p_run.add_argument("rest", nargs=argparse.REMAINDER,
                       help="arguments passed to the application")

    p_remove = sub.add_parser("remove", help="remove an installed app")
    p_remove.add_argument("app")
    p_remove.add_argument("--yes", action="store_true",
                          help="do not ask for confirmation")
    p_remove.add_argument("--dry-run", action="store_true",
                          help="show what would be removed")
    p_remove.add_argument("--backup", action="store_true",
                          help="move the AppImage to the backup directory")

    p_doctor = sub.add_parser("doctor", help="diagnose problems")
    p_doctor.add_argument("app", nargs="?", help="app id (all apps if omitted)")
    p_doctor.add_argument("--deep", action="store_true",
                          help="execute the AppImage runtime and extract the "
                               "payload to verify it (runs untrusted code)")
    p_doctor.add_argument("--json", action="store_true", help="output JSON")

    return parser


# ----------------------------------------------------------------------
# commands
# ----------------------------------------------------------------------
def cmd_install(args) -> int:
    try:
        outcome = installer.install(args.file, force=args.force, yes=args.yes,
                                    dry_run=args.dry_run)
    except (InstallError, AppImageError, RegistryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    app = outcome.app
    for warning in outcome.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if outcome.already_installed:
        print(f"'{app.id}' is already installed (same file); nothing to do.")
        return 0
    if args.dry_run:
        return 0
    verb = "Replaced" if outcome.replaced else "Installed"
    print(f"{verb} '{app.id}' ({app.name}"
          + (f" {app.version}" if app.version else "") + ")")
    print(f"  appimage : {app.appimage_path}")
    if app.icon_path:
        print(f"  icon     : {app.icon_path}")
    print(f"  launcher : {app.launcher_path}")
    if outcome.backup_path:
        print(f"  backup   : {outcome.backup_path}")
    print(f"Run it with: appman run {app.id}")
    return 0


def cmd_list(args) -> int:
    apps = registry.load_all()
    if args.json:
        print(json.dumps([asdict(a) for a in apps], indent=2, ensure_ascii=False))
        return 0
    if not apps:
        print("No AppImages installed. Use 'appman install <file>'.")
        return 0
    rows = [("ID", "NAME", "VERSION", "SIZE", "INSTALLED")]
    for app in apps:
        rows.append((app.id, app.name, app.version or "-",
                     human_size(app.size), (app.installed_at or "")[:10]))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for index, row in enumerate(rows):
        line = "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        print(line.rstrip())
        if index == 0:
            print("  ".join("-" * w for w in widths))
    return 0


def _resolve(query: str) -> registry.InstalledApp | None:
    return registry.match(query)


def cmd_info(args) -> int:
    try:
        app = _resolve(args.app)
    except RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if app is None:
        print(f"error: no installed app matches '{args.app}'", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(asdict(app), indent=2, ensure_ascii=False))
        return 0
    fields = [
        ("ID", app.id),
        ("Name", app.name),
        ("Version", app.version),
        ("Comment", app.comment),
        ("Categories", app.categories),
        ("Architecture", app.arch),
        ("Size", human_size(app.size)),
        ("Installed at", app.installed_at),
        ("Source", app.source),
        ("Original filename", app.original_filename),
        ("AppImage", app.appimage_path),
        ("Launcher", app.launcher_path),
        ("Icon", app.icon_path),
        ("Exec args", " ".join(app.exec_args) if app.exec_args else None),
        ("SHA-256", app.sha256),
    ]
    width = max(len(name) for name, _ in fields)
    for name, value in fields:
        if value is None:
            continue
        print(f"{name.ljust(width)} : {value}")
    return 0


def cmd_run(args) -> int:
    try:
        app = _resolve(args.app)
    except RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if app is None:
        print(f"error: no installed app matches '{args.app}'", file=sys.stderr)
        return 1
    path = app.appimage_path
    if not os.path.isfile(path):
        print(f"error: AppImage is missing: {path}", file=sys.stderr)
        print("Reinstall it with 'appman install <file>'.", file=sys.stderr)
        return 1
    if not os.access(path, os.X_OK):
        try:
            os.chmod(path, os.stat(path).st_mode | 0o111)
        except OSError as exc:
            print(f"error: cannot make AppImage executable: {exc}", file=sys.stderr)
            return 1

    env = dict(os.environ)
    available, reason = fuse_available()
    if args.extract_and_run or not available:
        env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
        if not available and not args.extract_and_run:
            print(f"note: FUSE unavailable ({reason}); extracting instead.",
                  file=sys.stderr)
    stored_args = [a for a in app.exec_args if "%" not in a and a != "--"]
    user_args = list(args.rest)
    if any(a.startswith("--appimage-") for a in user_args):
        argv = [path] + user_args
    else:
        argv = [path] + stored_args + user_args
    try:
        os.execve(path, argv, env)
    except OSError as exc:
        print(f"error: failed to execute AppImage: {exc}", file=sys.stderr)
        return 1
    return 0  # not reached


def cmd_remove(args) -> int:
    try:
        app = _resolve(args.app)
    except RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if app is None:
        print(f"error: no installed app matches '{args.app}'", file=sys.stderr)
        return 1
    try:
        outcome = installer.remove(app, yes=args.yes, dry_run=args.dry_run,
                                   backup=args.backup)
    except InstallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.dry_run:
        return 0
    print(f"Removed '{app.id}'.")
    for path in outcome.removed:
        print(f"  removed: {path}")
    if outcome.backed_up:
        print(f"  backup : {outcome.backed_up}")
    return 0


def _print_checks(checks, indent: str = "") -> None:
    for check in checks:
        print(indent + check.render())
        if check.hint and check.status in (doctor.ERROR, doctor.WARN):
            print(indent + "  -> " + check.hint)


def cmd_doctor(args) -> int:
    environment = doctor.global_checks()
    checks = list(environment)
    sections: list[tuple[str, list]] = [("environment", environment)]

    if args.app:
        try:
            app = _resolve(args.app)
        except RegistryError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if app is None:
            print(f"error: no installed app matches '{args.app}'", file=sys.stderr)
            return 1
        app_result = doctor.app_checks(app, deep=args.deep)
        checks += app_result
        sections.insert(0, (app.id, app_result))
    else:
        apps = registry.load_all()
        for app in apps:
            app_result = doctor.app_checks(app, deep=args.deep)
            checks += app_result
            sections.append((app.id, app_result))

    if args.json:
        print(json.dumps([asdict(c) for c in checks], indent=2, ensure_ascii=False))
        _errors, _warnings, _total = doctor.summarize(checks)
        return 1 if any(c.status == doctor.ERROR for c in checks) else 0

    for title, section_checks in sections:
        print(f"== {title} ==")
        _print_checks(section_checks, indent="  ")
        print()

    errors, warnings, total = doctor.summarize(checks)
    print(f"{total} checks: {errors} error(s), {warnings} warning(s)")
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "install": cmd_install,
        "list": cmd_list,
        "info": cmd_info,
        "run": cmd_run,
        "remove": cmd_remove,
        "doctor": cmd_doctor,
    }
    handler = handlers[args.command]
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
