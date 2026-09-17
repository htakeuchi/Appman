"""Small helpers for freedesktop.org Desktop Entry files."""

from __future__ import annotations

import re

_ESCAPE_RE = re.compile(r'([\\`$"])')


class DesktopEntry(dict):
    """A parsed ``[Desktop Entry]`` group, preserving the first value of a key."""

    def get(self, key, default=None):  # noqa: D102 - dict semantics
        return super().get(key, default)

    def localized(self, key: str, langs: list[str] | None = None) -> str | None:
        if langs:
            for lang in langs:
                value = self.get(f"{key}[{lang}]")
                if value:
                    return value
        return self.get(key)


def parse_desktop(text: str) -> DesktopEntry:
    """Parse a desktop file, returning the ``[Desktop Entry]`` group."""
    entry = DesktopEntry()
    in_group = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_group = line[1:-1].strip() == "Desktop Entry"
            continue
        if not in_group or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = _unescape(value.strip())
        if key not in entry:
            entry[key] = value
    return entry


def _unescape(value: str) -> str:
    out = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            mapping = {"s": " ", "n": "\n", "t": "\t", "r": "\r", "\\": "\\"}
            out.append(mapping.get(nxt, nxt))
            i += 2
        else:
            out.append(char)
            i += 1
    return "".join(out)


def escape_exec_arg(arg: str) -> str:
    """Quote a single ``Exec=`` argument per the desktop entry specification."""
    if arg and not re.search(r'[\s"\'\\`$<>|&;*?#()]', arg):
        return arg
    escaped = _ESCAPE_RE.sub(r"\\\1", arg)
    return f'"{escaped}"'


def build_exec(program: str, args: list[str] | None = None) -> str:
    parts = [escape_exec_arg(program)]
    parts.extend(escape_exec_arg(a) for a in (args or []))
    return " ".join(parts)
