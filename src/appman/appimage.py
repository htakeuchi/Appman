"""AppImage inspection: validation, payload detection and metadata extraction."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field

from .desktop import DesktopEntry, parse_desktop
from .squashfs import SquashFS, SquashFSError
from .util import which

UNSQUASHFS_TIMEOUT = 600
MAX_DESKTOP_BYTES = 1 << 20
MAX_ICON_BYTES = 16 << 20
MAX_ICON_CANDIDATES = 256

ELF_MAGIC = b"\x7fELF"
APPIMAGE_MAGIC = b"AI"
SQUASHFS_MAGIC = b"hsqs"
ISO9660_MAGIC = b"CD001"
SQUASHFS_SCAN_LIMIT = 64 * 1024 * 1024

ELF_MACHINES = {
    0x03: "i386",
    0x3E: "x86_64",
    0x28: "arm",
    0xB7: "aarch64",
    0x08: "mips",
    0x14: "ppc",
    0x15: "ppc64",
    0x16: "ppc64le",
    0x2B: "sparc",
    0xF3: "riscv32",
    0xEB: "riscv64",
    0x102: "loongarch64",
}

_ICON_EXTS = {".png", ".svg", ".svgz", ".xpm"}
_HICOLOR_SIZES = (16, 22, 24, 32, 36, 48, 64, 72, 96, 128, 256, 512)
_VERSION_RE = re.compile(r"(?<![0-9])(\d+(?:\.\d+)+(?:[-.][0-9A-Za-z]+)?)")


def icon_size_dir(ext: str | None, data: bytes | None) -> str:
    """Pick the hicolor icon directory that matches an icon's real size."""
    if ext in (".svg", ".svgz"):
        return "scalable"
    dimensions = _png_dimensions(data) if data else None
    if dimensions and dimensions[0] == dimensions[1] and dimensions[0] > 0:
        size = dimensions[0]
        if size in _HICOLOR_SIZES:
            return f"{size}x{size}"
        for candidate in _HICOLOR_SIZES:
            if candidate >= size:
                return f"{candidate}x{candidate}"
        return f"{_HICOLOR_SIZES[-1]}x{_HICOLOR_SIZES[-1]}"
    return "512x512"


def _png_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n":
        width, height = struct.unpack(">II", data[16:24])
        return width, height
    return None


def _sniff_icon_ext(data: bytes) -> str | None:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    head = data[:256].lstrip()
    if head.startswith(b"<?xml") or head.startswith(b"<svg") or b"<svg" in head:
        return ".svg"
    return None


class AppImageError(Exception):
    """Raised for files that cannot be treated as AppImages."""


@dataclass
class ElfInfo:
    bits: int
    endian: str
    machine: str
    appimage_type: int | None
    payload_offset: int | None
    sha256: str | None = None


@dataclass
class AppImageMetadata:
    path: str
    size: int
    appimage_type: int | None = None
    arch: str = "unknown"
    payload_offset: int | None = None
    sha256: str | None = None
    app_id: str = ""
    name: str = ""
    version: str | None = None
    comment: str | None = None
    categories: str = "Utility;"
    wm_class: str | None = None
    exec_args: list[str] = field(default_factory=list)
    desktop_filename: str | None = None
    desktop_entry: DesktopEntry | None = None
    icon_bytes: bytes | None = None
    icon_ext: str | None = None
    icon_source: str | None = None
    embedded_metadata: bool = False
    warnings: list[str] = field(default_factory=list)


# ----------------------------------------------------------------------
# validation helpers
# ----------------------------------------------------------------------
def read_elf_info(fileobj) -> ElfInfo:
    fileobj.seek(0)
    ident = fileobj.read(16)
    if len(ident) < 16 or ident[:4] != ELF_MAGIC:
        raise AppImageError("not an ELF file")
    bits = 64 if ident[4] == 2 else 32 if ident[4] == 1 else 0
    if not bits:
        raise AppImageError("unknown ELF class")
    endian = "<" if ident[5] == 1 else ">" if ident[5] == 2 else None
    if endian is None:
        raise AppImageError("unknown ELF endianness")

    fileobj.seek(8)
    magic = fileobj.read(4)
    appimage_type = None
    if magic[:2] == APPIMAGE_MAGIC:
        appimage_type = magic[2] if magic[2] in (1, 2) else None

    fileobj.seek(0, os.SEEK_END)
    file_size = fileobj.tell()
    fileobj.seek(0)
    header = fileobj.read(64 if bits == 64 else 52)
    machine_raw = struct.unpack_from(endian + "H", header, 18)[0]
    if bits == 64:
        shoff = struct.unpack_from(endian + "Q", header, 40)[0]
        shentsize = struct.unpack_from(endian + "H", header, 58)[0]
        shnum = struct.unpack_from(endian + "H", header, 60)[0]
    else:
        shoff = struct.unpack_from(endian + "I", header, 32)[0]
        shentsize = struct.unpack_from(endian + "H", header, 46)[0]
        shnum = struct.unpack_from(endian + "H", header, 48)[0]

    payload_offset = None
    if 0 < shentsize < 4096 and 0 < shnum < 65536:
        candidate = shoff + shentsize * shnum
        if candidate < file_size and _is_squashfs(fileobj, candidate):
            payload_offset = candidate

    return ElfInfo(
        bits=bits,
        endian=endian,
        machine=ELF_MACHINES.get(machine_raw, f"unknown(0x{machine_raw:x})"),
        appimage_type=appimage_type,
        payload_offset=payload_offset,
    )


def _is_squashfs(fileobj, offset: int) -> bool:
    fileobj.seek(offset)
    raw = fileobj.read(96)
    if len(raw) < 96 or raw[:4] != SQUASHFS_MAGIC:
        return False
    (inode_count, _mkfs, block_size, _fragments, compression, _block_log,
     _flags, _ids, major, _minor) = struct.unpack_from("<IIIIHHHHHH", raw, 4)
    if block_size < 4096 or block_size > 1 << 24 or (block_size & (block_size - 1)):
        return False
    if major not in (3, 4):
        return False
    if compression not in (1, 2, 3, 4, 5, 6):
        return False
    if inode_count == 0:
        return False
    return True


def _scan_for_squashfs(fileobj, limit: int = SQUASHFS_SCAN_LIMIT) -> int | None:
    fileobj.seek(0, os.SEEK_END)
    size = fileobj.tell()
    end = min(size, limit)
    fileobj.seek(0)
    data = fileobj.read(end)
    index = data.find(SQUASHFS_MAGIC)
    while index != -1:
        if _is_squashfs(fileobj, index):
            return index
        index = data.find(SQUASHFS_MAGIC, index + 1)
    return None


def _detect_payload(fileobj, elf: ElfInfo) -> int | None:
    if elf.payload_offset is not None:
        return elf.payload_offset
    if elf.appimage_type == 2:
        found = _scan_for_squashfs(fileobj)
        if found is not None:
            return found
    return None


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def validate(path: str) -> ElfInfo:
    """Validate that *path* is a usable AppImage and return basic info."""
    if not os.path.exists(path):
        raise AppImageError(f"file not found: {path}")
    if not os.path.isfile(path):
        raise AppImageError(f"not a regular file: {path}")
    if os.path.getsize(path) == 0:
        raise AppImageError("file is empty")
    if not os.access(path, os.R_OK):
        raise AppImageError(f"file is not readable: {path}")
    with open(path, "rb") as fileobj:
        elf = read_elf_info(fileobj)
        if elf.appimage_type is None:
            raise AppImageError(
                "not an AppImage: missing AppImage magic bytes at offset 8"
            )
        if elf.appimage_type == 1:
            raise AppImageError(
                "AppImage type 1 (ISO 9660) is obsolete and not supported"
            )
        payload = _detect_payload(fileobj, elf)
        elf.payload_offset = payload
        if payload is None:
            raise AppImageError(
                "corrupt AppImage: embedded SquashFS payload could not be located"
            )
    return elf


# ----------------------------------------------------------------------
# metadata extraction
# ----------------------------------------------------------------------
def _app_id_from_filename(path: str) -> str:
    stem = os.path.basename(path)
    for suffix in (".AppImage", ".appimage", ".appimage"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    else:
        stem = os.path.splitext(stem)[0]
    stem = _VERSION_RE.sub("", stem).strip("-_ .")
    return sanitize_id(stem or "appimage")


def sanitize_id(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value or "appimage"


def _version_from_filename(path: str) -> str | None:
    stem = os.path.basename(path)
    for suffix in (".AppImage", ".appimage"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    match = _VERSION_RE.search(stem)
    return match.group(1) if match else None


def _score_desktop(name: str, stem: str) -> tuple:
    base = name[: -len(".desktop")].lower()
    return (0 if base == stem.lower() else 1, len(name), name)


def _choose_desktop(entries: list[tuple[str, int, object]], stem: str):
    candidates = [(name, ref) for name, ref, inode in entries
                  if name.lower().endswith(".desktop") and inode.is_file]
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: _score_desktop(item[0], stem))[0]


def _contained_realpath(root: str, path: str) -> str | None:
    """Resolve *path* and return it only if it stays inside *root*.

    Protects against symlinks in an extracted tree that point at host files
    (e.g. ``evil.png -> /home/user/.ssh/id_rsa``).
    """
    root_real = os.path.realpath(root)
    real = os.path.realpath(path)
    if real == root_real or real.startswith(root_real + os.sep):
        return real
    return None


def _read_tree_file(root: str, path: str) -> bytes | None:
    """Read *path* if it resolves to a regular file inside *root*."""
    real = _contained_realpath(root, path)
    if real is None or not os.path.isfile(real):
        return None
    try:
        with open(real, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def _choose_desktop_name(root: str, names: list[str], stem: str) -> str | None:
    candidates = []
    for name in names:
        if not name.lower().endswith(".desktop"):
            continue
        real = _contained_realpath(root, os.path.join(root, name))
        if real is not None and os.path.isfile(real):
            candidates.append(name)
    if not candidates:
        return None
    return sorted(candidates, key=lambda name: _score_desktop(name, stem))[0]


def _icon_candidates(sfs: SquashFS, icon_field: str | None):
    """Return ``(image_path, inode, ext)`` candidates without reading data."""
    found: list[tuple[str, object, str]] = []

    def consider(image_path: str, inode):
        ext = os.path.splitext(image_path)[1].lower()
        if ext in _ICON_EXTS:
            found.append((image_path, inode, ext))

    diricon = sfs.lookup(".DirIcon")
    if diricon is not None and diricon.is_file:
        try:
            data = sfs.read(diricon)
        except SquashFSError:
            data = b""
        ext = _sniff_icon_ext(data)
        if ext in _ICON_EXTS:
            found.append((".DirIcon", diricon, ext))

    names = set()
    if icon_field:
        names.add(icon_field.lower())
        names.add(os.path.splitext(icon_field)[0].lower())

    for name, _ref, inode in sfs.readdir(sfs.root_inode_ref):
        if inode.is_file and os.path.splitext(name)[0].lower() in names:
            consider(name, inode)

    if names:
        for directory in ("usr/share/pixmaps", "usr/share/icons", "usr/share/icons/hicolor"):
            try:
                base_inode = sfs.lookup(directory)
            except SquashFSError:
                base_inode = None
            if base_inode is not None and base_inode.is_dir:
                _search_icons(sfs, base_inode, names, consider)
    return found


def _search_icons(sfs: SquashFS, inode, names: set[str], consider, _depth: int = 0):
    if _depth > 4:
        return
    try:
        children = sfs.readdir(inode.ref)
    except SquashFSError:
        return
    for name, _ref, child in children:
        if child.is_dir:
            _search_icons(sfs, child, names, consider, _depth + 1)
        elif child.is_file:
            base_name = os.path.splitext(name)[0].lower()
            if base_name in names:
                consider(name, child)


def _icon_rank(ext: str, size: int) -> tuple:
    if ext == ".svg":
        return (0, -size)
    if ext == ".svgz":
        return (1, -size)
    if ext == ".png":
        return (2, -size)
    return (3, -size)


def _pick_icon(icons):
    if not icons:
        return None
    return sorted(icons, key=lambda item: _icon_rank(item[2], item[1].size))[0]


def _decode_text(raw: bytes, meta: AppImageMetadata) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        meta.warnings.append("desktop file is not valid UTF-8")
        return raw.decode("latin-1", "replace")


def _apply_desktop(meta: AppImageMetadata, desktop_name: str, text: str,
                   stem: str) -> DesktopEntry:
    desktop = parse_desktop(text)
    meta.desktop_filename = desktop_name
    meta.desktop_entry = desktop
    meta.embedded_metadata = True
    meta.name = desktop.get("Name") or stem
    meta.comment = desktop.get("Comment")
    meta.categories = desktop.get("Categories") or "Utility;"
    meta.wm_class = desktop.get("StartupWMClass")
    meta.version = desktop.get("X-AppImage-Version")
    if desktop.get("NoDisplay", "").lower() == "true":
        meta.warnings.append("embedded desktop entry sets NoDisplay=true")
    meta.exec_args = _parse_exec(desktop.get("Exec"), stem)
    meta.app_id = sanitize_id(os.path.splitext(desktop_name)[0] or stem)
    return desktop


def _inspect_squashfs(sfs: SquashFS, meta: AppImageMetadata, stem: str) -> None:
    root = sfs.readdir(sfs.root_inode_ref)
    chosen = _choose_desktop(root, stem)
    desktop = None
    if chosen is not None:
        desktop_name, desktop_ref = chosen
        text = _decode_text(sfs.read(sfs.inode(desktop_ref)), meta)
        desktop = _apply_desktop(meta, desktop_name, text, stem)
    else:
        meta.warnings.append(
            "no embedded .desktop file found; using filename for metadata"
        )

    icons = _icon_candidates(sfs, desktop.get("Icon") if desktop else None)
    picked = _pick_icon(icons)
    if picked is not None:
        image_path, inode, ext = picked
        meta.icon_source = image_path
        meta.icon_ext = ext
        try:
            meta.icon_bytes = sfs.read(inode)
        except SquashFSError as exc:
            meta.warnings.append(f"could not read icon {image_path}: {exc}")


def inspect(path: str, compute_hash: bool = True) -> AppImageMetadata:
    """Return metadata for a valid AppImage. Raises AppImageError."""
    elf = validate(path)
    meta = AppImageMetadata(
        path=os.path.abspath(path),
        size=os.path.getsize(path),
        appimage_type=elf.appimage_type,
        arch=elf.machine,
        payload_offset=elf.payload_offset,
    )
    if compute_hash:
        meta.sha256 = sha256_file(path)

    if elf.payload_offset is None:
        meta.warnings.append("SquashFS payload not found; metadata unavailable")
        _apply_filename_fallback(meta)
        return meta

    stem = _app_id_from_filename(path)
    try:
        with open(path, "rb") as fileobj:
            _inspect_squashfs(SquashFS(fileobj, elf.payload_offset), meta, stem)
    except SquashFSError as exc:
        if _is_unsupported_compression(exc):
            if not _inspect_unsquashfs(path, elf.payload_offset, meta, stem):
                raise AppImageError(
                    f"unsupported SquashFS compression ({exc}); install "
                    f"squashfs-tools to enable the extraction fallback"
                ) from exc
        else:
            raise AppImageError(f"corrupt AppImage payload: {exc}") from exc
    except (struct.error, IndexError, ValueError) as exc:
        raise AppImageError(f"corrupt AppImage payload: {exc}") from exc

    if not meta.app_id:
        meta.app_id = _app_id_from_filename(path)
    if not meta.name:
        meta.name = _app_id_from_filename(path)
    if not meta.version:
        meta.version = _version_from_filename(path)
    return meta


def _is_unsupported_compression(exc: Exception) -> bool:
    message = str(exc)
    return ("unsupported SquashFS compression" in message
            or "zstd compressed SquashFS needs Python 3.14" in message)


@dataclass
class _TreeEntry:
    path: str
    is_dir: bool
    is_link: bool
    size: int
    target: str | None = None


def _inspect_unsquashfs(path: str, offset: int, meta: AppImageMetadata,
                        stem: str) -> bool:
    """Fallback for compression the built-in reader cannot handle.

    The filesystem is listed first and only the ``.desktop`` entry and the
    icon candidates are extracted, so a hostile image cannot make us unpack a
    multi-gigabyte payload into the temporary directory (a /tmp exhaustion
    DoS).
    """
    exe = which("unsquashfs")
    if exe is None:
        return False
    entries = _unsquashfs_list(exe, path, offset)
    if entries is None:
        return False
    by_path = {entry.path: entry for entry in entries}
    desktop_path = _choose_desktop_entry(by_path, stem)

    with tempfile.TemporaryDirectory(prefix="appman-unpack-") as dest:
        if desktop_path is not None:
            wanted = _expand_tree_paths(by_path, [desktop_path])
            if not _unsquashfs_extract(exe, path, offset, dest, wanted):
                return False

        icon_field = _desktop_icon_field(dest, desktop_path)
        icon_paths = _select_icon_entries(by_path, icon_field)
        if icon_paths:
            wanted = _expand_tree_paths(by_path, icon_paths)
            if not _unsquashfs_extract(exe, path, offset, dest, wanted):
                return False

        _metadata_from_tree(dest, meta, stem)
    return True


def _unsquashfs_list(exe: str, image_path: str, offset: int):
    command = [exe, "-o", str(offset), "-ll", "-no-progress", image_path]
    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=UNSQUASHFS_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return _parse_unsquashfs_listing(result.stdout)


def _parse_unsquashfs_listing(text: str) -> list[_TreeEntry]:
    """Parse the ``unsquashfs -ll`` output.

    Lines look like ``PERMS USER/GROUP SIZE DATE TIME PATH[ -> TARGET]``.
    """
    entries: list[_TreeEntry] = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        perms, _owner, size_raw, _date, _time, rest = parts
        if not perms:
            continue
        is_dir = perms[0] == "d"
        is_link = perms[0] == "l"
        target = None
        path = rest
        if is_link and " -> " in rest:
            path, target = rest.split(" -> ", 1)
        if "/" not in path:
            continue
        path = path.split("/", 1)[1]
        if not path:
            continue
        try:
            size = int(size_raw)
        except ValueError:
            size = 0
        entries.append(_TreeEntry(path, is_dir, is_link, size, target))
    return entries


def _resolve_target_path(path: str, target: str) -> str | None:
    if not target or target.startswith("/"):
        return None
    parent = os.path.dirname(path)
    resolved = os.path.normpath(os.path.join(parent, target) if parent else target)
    if resolved in (".", "..") or resolved.startswith("../") or resolved.startswith("/"):
        return None
    return resolved


def _resolve_entry(by_path: dict[str, _TreeEntry], entry: _TreeEntry | None,
                   _depth: int = 0) -> _TreeEntry | None:
    """Follow symlinks to the regular file they point at inside the tree."""
    if entry is None or entry.is_dir or _depth > 8:
        return None
    if not entry.is_link:
        return entry
    target = _resolve_target_path(entry.path, entry.target or "")
    if target is None:
        return None
    return _resolve_entry(by_path, by_path.get(target), _depth + 1)


def _expand_tree_paths(by_path: dict[str, _TreeEntry],
                       paths: list[str]) -> list[str]:
    """Add the in-tree targets of any symlinks in *paths*."""
    selected: list[str] = []
    seen: set[str] = set()
    pending = list(paths)
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        selected.append(path)
        entry = by_path.get(path)
        if entry is None or not entry.is_link:
            continue
        target = _resolve_target_path(path, entry.target or "")
        if target is not None:
            pending.append(target)
    return selected


def _choose_desktop_entry(by_path: dict[str, _TreeEntry], stem: str) -> str | None:
    candidates = []
    for path, entry in by_path.items():
        if entry.is_dir or path.startswith("-") or "/" in path:
            continue
        if not path.lower().endswith(".desktop"):
            continue
        resolved = _resolve_entry(by_path, entry)
        if resolved is None or resolved.size > MAX_DESKTOP_BYTES:
            continue
        candidates.append(path)
    if not candidates:
        return None
    return sorted(candidates, key=lambda name: _score_desktop(name, stem))[0]


def _desktop_icon_field(dest: str, desktop_path: str | None) -> str | None:
    if desktop_path is None:
        return None
    raw = _read_tree_file(dest, os.path.join(dest, desktop_path))
    if raw is None:
        return None
    return parse_desktop(raw.decode("utf-8", "replace")).get("Icon")


def _select_icon_entries(by_path: dict[str, _TreeEntry],
                         icon_field: str | None) -> list[str]:
    candidates: list[tuple[str, _TreeEntry]] = []

    diricon = by_path.get(".DirIcon")
    if diricon is not None and not diricon.is_dir:
        resolved = _resolve_entry(by_path, diricon)
        if resolved is not None and resolved.size <= MAX_ICON_BYTES:
            candidates.append((".DirIcon", resolved))

    names: set[str] = set()
    if icon_field:
        names.add(icon_field.lower())
        names.add(os.path.splitext(icon_field)[0].lower())
    if names:
        for path, entry in by_path.items():
            if entry.is_dir or path == ".DirIcon" or path.startswith("-"):
                continue
            if os.path.splitext(path)[1].lower() not in _ICON_EXTS:
                continue
            if os.path.splitext(os.path.basename(path))[0].lower() not in names:
                continue
            if "/" in path and not (path.startswith("usr/share/pixmaps/")
                                    or path.startswith("usr/share/icons/")):
                continue
            resolved = _resolve_entry(by_path, entry)
            if resolved is None or resolved.size > MAX_ICON_BYTES:
                continue
            candidates.append((path, resolved))

    candidates.sort(key=lambda item: _icon_rank(
        os.path.splitext(item[1].path)[1].lower(), item[1].size))
    return [path for path, _entry in candidates[:MAX_ICON_CANDIDATES]]


def _unsquashfs_extract(exe: str, image_path: str, offset: int, dest: str,
                        paths: list[str]) -> bool:
    if not paths:
        return True
    command = [exe, "-o", str(offset), "-d", dest, "-no-progress", "-f",
               image_path, *paths]
    try:
        result = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=UNSQUASHFS_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _metadata_from_tree(root: str, meta: AppImageMetadata, stem: str) -> None:
    names = os.listdir(root)
    desktop_name = _choose_desktop_name(root, names, stem)
    desktop = None
    raw = _read_tree_file(root, os.path.join(root, desktop_name)) if desktop_name else None
    if raw is not None:
        text = _decode_text(raw, meta)
        desktop = _apply_desktop(meta, desktop_name, text, stem)
    else:
        meta.warnings.append(
            "no embedded .desktop file found; using filename for metadata"
        )

    icon_field = desktop.get("Icon") if desktop else None
    picked = _pick_tree_icon(root, icon_field)
    if picked is not None:
        source, data, ext = picked
        meta.icon_source = source
        meta.icon_bytes = data
        meta.icon_ext = ext


def _pick_tree_icon(root: str, icon_field: str | None):
    candidates: list[tuple[str, int, str, bytes]] = []

    def consider(image_path: str, data: bytes):
        ext = os.path.splitext(image_path)[1].lower()
        if ext in _ICON_EXTS:
            candidates.append((image_path, len(data), ext, data))

    diricon = os.path.join(root, ".DirIcon")
    if os.path.lexists(diricon):
        data = _read_tree_file(root, diricon)
        if data is not None:
            real = _contained_realpath(root, diricon)
            ext = os.path.splitext(real)[1].lower()
            if ext not in _ICON_EXTS:
                ext = _sniff_icon_ext(data)
            if ext in _ICON_EXTS:
                candidates.append((".DirIcon", len(data), ext, data))

    names = set()
    if icon_field:
        names.add(icon_field.lower())
        names.add(os.path.splitext(icon_field)[0].lower())
    if names:
        for name in os.listdir(root):
            if os.path.splitext(name)[0].lower() not in names:
                continue
            data = _read_tree_file(root, os.path.join(root, name))
            if data is not None:
                consider(name, data)
        for base in ("usr/share/pixmaps", "usr/share/icons"):
            _search_icon_tree(root, os.path.join(root, base), names, consider)

    if not candidates:
        return None
    best = sorted(candidates, key=lambda item: _icon_rank(item[2], item[1]))[0]
    return best[0], best[3], best[2]


def _search_icon_tree(root: str, base: str, names: set[str], consider,
                      _depth: int = 0):
    if _depth > 4:
        return
    real_base = _contained_realpath(root, base)
    if real_base is None or not os.path.isdir(real_base):
        return
    try:
        entries = os.listdir(real_base)
    except OSError:
        return
    for name in entries:
        real = _contained_realpath(root, os.path.join(real_base, name))
        if real is None:
            continue
        if os.path.isdir(real):
            _search_icon_tree(root, real, names, consider, _depth + 1)
        elif os.path.isfile(real) and os.path.splitext(name)[0].lower() in names:
            data = _read_tree_file(root, real)
            if data is not None:
                consider(name, data)


def _parse_exec(exec_line: str | None, stem: str) -> list[str]:
    if not exec_line:
        return []
    try:
        tokens = shlex.split(exec_line)
    except ValueError:
        tokens = exec_line.split()
    if not tokens:
        return []
    first = os.path.basename(tokens[0]).lower()
    if first in {"apprun", "apprun.wrapper"} or first == stem.lower():
        tokens = tokens[1:]
    elif first.endswith(".appimage"):
        tokens = tokens[1:]
    return tokens


def _apply_filename_fallback(meta: AppImageMetadata) -> None:
    meta.app_id = _app_id_from_filename(meta.path)
    meta.name = meta.app_id.replace("-", " ").title()
    meta.version = _version_from_filename(meta.path)
