"""Minimal read-only SquashFS v4 reader.

It only implements the subset of the format that is needed to inspect the
contents of an AppImage (type 2) payload: the super block, metadata blocks,
inode table, directory table, file data blocks and the fragment table.

Compression backends available in the Python standard library are supported
(gzip/zlib, xz and lzma).  zstd is supported on Python 3.14+ via the
``compression.zstd`` module.  lzo/lz4 are not supported; ``SquashFSError`` is
raised with a clear message in that case.
"""

from __future__ import annotations

import io
import lzma
import posixpath
import struct
import zlib
from dataclasses import dataclass, field

try:  # Python 3.14+
    from compression import zstd as _zstd  # type: ignore
except Exception:  # pragma: no cover - depends on interpreter version
    _zstd = None

SUPERBLOCK_SIZE = 96

COMPRESSION_NAMES = {
    1: "gzip",
    2: "lzma",
    3: "lzo",
    4: "xz",
    5: "lz4",
    6: "zstd",
}

# inode types
DIR_TYPE = 1
FILE_TYPE = 2
SYMLINK_TYPE = 3
BLKDEV_TYPE = 4
CHRDEV_TYPE = 5
FIFO_TYPE = 6
SOCKET_TYPE = 7
EXT_DIR_TYPE = 8
EXT_FILE_TYPE = 9
EXT_SYMLINK_TYPE = 10
EXT_BLKDEV_TYPE = 11
EXT_CHRDEV_TYPE = 12
EXT_FIFO_TYPE = 13
EXT_SOCKET_TYPE = 14

SYMLINK_TYPES = (SYMLINK_TYPE, EXT_SYMLINK_TYPE)
DIR_TYPES = (DIR_TYPE, EXT_DIR_TYPE)
FILE_TYPES = (FILE_TYPE, EXT_FILE_TYPE)


class SquashFSError(Exception):
    """Raised when the SquashFS image cannot be read."""


@dataclass
class Inode:
    type: int
    mode: int
    uid: int
    guid: int
    mtime: int
    inode_number: int
    ref: int
    size: int = 0
    target: str | None = None
    start_block: int = 0
    block_sizes: list = field(default_factory=list)
    fragment: int = 0xFFFFFFFF
    frag_offset: int = 0
    dir_start: int = 0
    dir_offset: int = 0

    @property
    def is_dir(self) -> bool:
        return self.type in DIR_TYPES

    @property
    def is_file(self) -> bool:
        return self.type in FILE_TYPES

    @property
    def is_symlink(self) -> bool:
        return self.type in SYMLINK_TYPES

    @property
    def is_executable(self) -> bool:
        return bool(self.mode & 0o111)


class SquashFS:
    """Read-only access to a SquashFS v4 image inside ``fileobj``."""

    _FIXED_INODE_SIZE = {
        DIR_TYPE: 32,
        EXT_DIR_TYPE: 40,
        FILE_TYPE: 32,
        EXT_FILE_TYPE: 56,
        SYMLINK_TYPE: 24,
        EXT_SYMLINK_TYPE: 28,
        BLKDEV_TYPE: 32,
        CHRDEV_TYPE: 32,
        FIFO_TYPE: 32,
        SOCKET_TYPE: 32,
        EXT_BLKDEV_TYPE: 40,
        EXT_CHRDEV_TYPE: 40,
        EXT_FIFO_TYPE: 40,
        EXT_SOCKET_TYPE: 40,
    }

    def __init__(self, fileobj: io.BufferedIOBase, base: int = 0):
        self.f = fileobj
        self.base = base
        self._meta_cache: dict[int, bytes] = {}
        self._parse_superblock()

    # ------------------------------------------------------------------
    # low level helpers
    # ------------------------------------------------------------------
    def _seek(self, offset: int) -> None:
        self.f.seek(self.base + offset)

    def _read_at(self, offset: int, length: int) -> bytes:
        self._seek(offset)
        data = self.f.read(length)
        if len(data) != length:
            raise SquashFSError("unexpected end of SquashFS image")
        return data

    def _parse_superblock(self) -> None:
        raw = self._read_at(0, SUPERBLOCK_SIZE)
        self.magic = raw[0:4]
        if self.magic != b"hsqs":
            raise SquashFSError("not a SquashFS image (bad magic)")
        (self.inode_count, self.mkfs_time, self.block_size, self.fragment_count,
         self.compression, self.block_log, self.flags, self.id_count,
         self.major, self.minor) = struct.unpack_from("<IIIIHHHHHH", raw, 4)
        (self.root_inode_ref, self.bytes_used, self.id_table_start,
         self.xattr_id_table_start, self.inode_table_start,
         self.directory_table_start, self.fragment_table_start,
         self.export_table_start) = struct.unpack_from("<QQQQQQQQ", raw, 32)
        if self.major != 4:
            raise SquashFSError(f"unsupported SquashFS version {self.major}.{self.minor}")
        if self.compression not in COMPRESSION_NAMES:
            raise SquashFSError(f"unknown SquashFS compression id {self.compression}")

    def _decompress(self, data: bytes) -> bytes:
        c = self.compression
        try:
            if c == 1:
                return zlib.decompress(data)
            if c == 4:
                return lzma.decompress(data)
            if c == 2:
                return lzma.decompress(data, format=lzma.FORMAT_ALONE)
            if c == 6:
                if _zstd is None:
                    raise SquashFSError(
                        "zstd compressed SquashFS needs Python 3.14+ (compression.zstd)"
                    )
                return _zstd.decompress(data)
        except SquashFSError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SquashFSError(f"failed to decompress SquashFS block: {exc}") from exc
        name = COMPRESSION_NAMES.get(c, str(c))
        raise SquashFSError(f"unsupported SquashFS compression: {name}")

    def _metadata_block(self, offset: int) -> bytes:
        cached = self._meta_cache.get(offset)
        if cached is not None:
            return cached
        header = struct.unpack("<H", self._read_at(offset, 2))[0]
        size = header & 0x7FFF
        compressed = not (header & 0x8000)
        payload = self._read_at(offset + 2, size)
        data = self._decompress(payload) if compressed else payload
        self._meta_cache[offset] = data
        return data

    def _read_metadata(self, offset: int, length: int) -> bytes:
        out = bytearray()
        pos = offset
        while len(out) < length:
            block = self._metadata_block(pos)
            out += block
            header = struct.unpack("<H", self._read_at(pos, 2))[0]
            pos += 2 + (header & 0x7FFF)
        return bytes(out[:length])

    # ------------------------------------------------------------------
    # inodes and directories
    # ------------------------------------------------------------------
    def _inode_at(self, ref: int, light: bool = False) -> Inode:
        offset = self.inode_table_start + (ref >> 16)
        within = ref & 0xFFFF
        head = self._read_metadata(offset, within + 16)[within:]
        (itype, mode, uid, guid, mtime, inode_number) = struct.unpack("<HHHHII", head)
        ino = Inode(type=itype, mode=mode, uid=uid, guid=guid, mtime=mtime,
                    inode_number=inode_number, ref=ref)
        fixed = self._FIXED_INODE_SIZE.get(itype)
        if fixed is None:
            return ino
        raw = self._read_metadata(offset, within + fixed)[within:]
        p = 16
        if itype == DIR_TYPE:
            start, nlink, size, off, _parent = struct.unpack_from("<IIHHI", raw, p)
            ino.dir_start, ino.dir_offset, ino.size = start, off, size
        elif itype == EXT_DIR_TYPE:
            _nlink, size, start, _parent = struct.unpack_from("<IIII", raw, p)
            _icount, off, _xattr = struct.unpack_from("<HHI", raw, p + 16)
            ino.dir_start, ino.dir_offset, ino.size = start, off, size
        elif itype == FILE_TYPE:
            start, fragment, frag_off, size = struct.unpack_from("<IIII", raw, p)
            ino.start_block, ino.fragment, ino.frag_offset, ino.size = start, fragment, frag_off, size
            nblocks = self._data_block_count(size, fragment)
            if nblocks and not light:
                raw = self._read_metadata(offset, within + p + 16 + 4 * nblocks)[within:]
                ino.block_sizes = list(struct.unpack_from(f"<{nblocks}I", raw, p + 16))
        elif itype == EXT_FILE_TYPE:
            start, size, _sparse, _nlink, fragment, frag_off, _xattr = struct.unpack_from("<QQQIIII", raw, p)
            ino.start_block, ino.fragment, ino.frag_offset, ino.size = start, fragment, frag_off, size
            nblocks = self._data_block_count(size, fragment)
            if nblocks and not light:
                raw = self._read_metadata(offset, within + p + 40 + 4 * nblocks)[within:]
                ino.block_sizes = list(struct.unpack_from(f"<{nblocks}I", raw, p + 40))
        elif itype == SYMLINK_TYPE:
            _nlink, target_size = struct.unpack_from("<II", raw, p)
            raw = self._read_metadata(offset, within + p + 8 + target_size)[within:]
            ino.target = raw[p + 8:p + 8 + target_size].decode("utf-8", "replace")
            ino.size = target_size
        elif itype == EXT_SYMLINK_TYPE:
            _nlink, target_size, _xattr = struct.unpack_from("<III", raw, p)
            raw = self._read_metadata(offset, within + p + 12 + target_size)[within:]
            ino.target = raw[p + 12:p + 12 + target_size].decode("utf-8", "replace")
            ino.size = target_size
        return ino

    def _data_block_count(self, size: int, fragment: int) -> int:
        if fragment != 0xFFFFFFFF:
            return size // self.block_size
        return (size + self.block_size - 1) // self.block_size

    def inode(self, ref: int) -> Inode:
        return self._inode_at(ref)

    def readdir(self, ref: int) -> list[tuple[str, int, Inode]]:
        """Return ``(name, ref, inode)`` tuples for a directory inode."""
        directory = self._inode_at(ref, light=True)
        if not directory.is_dir:
            raise SquashFSError("not a directory")
        block = self.directory_table_start + directory.dir_start
        within = directory.dir_offset
        size = directory.size
        data = self._read_metadata(block, within + size)[within:]
        entries: list[tuple[str, int, Inode]] = []
        p = 0
        while p + 12 <= size:
            count, start_block, _inode_number = struct.unpack_from("<III", data, p)
            p += 12
            for _ in range(count + 1):
                if p + 8 > size:
                    return entries
                entry_offset, _delta, _etype, name_size = struct.unpack_from("<HhHH", data, p)
                p += 8
                name_len = name_size + 1
                name = data[p:p + name_len].decode("utf-8", "replace")
                p += name_len
                child_ref = (start_block << 16) | entry_offset
                entries.append((name, child_ref, self._inode_at(child_ref, light=True)))
        return entries

    def lookup(self, path: str, _depth: int = 0) -> Inode | None:
        """Resolve ``path`` (absolute or relative, ``/`` separated).

        Symlinks encountered along the way are followed, matching POSIX
        semantics.  Returns ``None`` when the path does not exist.
        """
        if _depth > 40:
            raise SquashFSError("too many levels of symbolic links")
        ref = self.root_inode_ref
        prefix: list[str] = []
        parts = [p for p in path.split("/") if p and p != "."]
        index = 0
        while index < len(parts):
            part = parts[index]
            match = None
            for name, child_ref, child in self.readdir(ref):
                if name == part:
                    match = (child_ref, child)
                    break
            if match is None:
                return None
            child_ref, child = match
            if child.is_symlink:
                target = child.target or ""
                base = target if target.startswith("/") else "/".join(prefix + [target])
                rest = "/".join(parts[index + 1:])
                combined = posixpath.normpath(posixpath.join("/", base, rest))
                return self.lookup(combined.lstrip("/"), _depth + 1)
            prefix.append(part)
            ref = child_ref
            index += 1
        return self._inode_at(ref)

    # ------------------------------------------------------------------
    # file data
    # ------------------------------------------------------------------
    def read(self, inode: Inode) -> bytes:
        if inode.is_symlink:
            return (inode.target or "").encode("utf-8")
        if not inode.is_file:
            raise SquashFSError("not a regular file")
        inode = self._inode_at(inode.ref)
        out = bytearray()
        pos = inode.start_block
        last = len(inode.block_sizes) - 1
        for index, raw_size in enumerate(inode.block_sizes):
            size = raw_size & 0xFFFFFF
            if size == 0:
                # Sparse hole: zero filled, no data stored in the image.
                expected = self.block_size
                if inode.fragment == 0xFFFFFFFF and index == last:
                    expected = inode.size - index * self.block_size
                out += b"\x00" * expected
                continue
            compressed = not (raw_size & 0x1000000)
            payload = self._read_at(pos, size)
            pos += size
            out += self._decompress(payload) if compressed else payload
        if inode.fragment != 0xFFFFFFFF:
            tail = inode.size % self.block_size
            if tail:
                out += self._read_fragment(inode.fragment, inode.frag_offset, tail)
        return bytes(out[:inode.size])

    def _read_fragment(self, index: int, offset: int, size: int) -> bytes:
        per_block = self.block_size // 16
        table_entry = index // per_block
        metadata_offset = self._read_at(self.fragment_table_start + table_entry * 8, 8)
        block_location = struct.unpack("<Q", metadata_offset)[0]
        entry = self._read_metadata(block_location + (index % per_block) * 16, 16)
        fragment_start, fragment_size, _unused = struct.unpack("<QII", entry)
        compressed = not (fragment_size & 0x1000000)
        fragment_size &= 0xFFFFFF
        payload = self._read_at(fragment_start, fragment_size)
        block = self._decompress(payload) if compressed else payload
        return block[offset:offset + size]

    def read_path(self, path: str) -> bytes | None:
        inode = self.lookup(path)
        if inode is None:
            return None
        return self.read(inode)

    def walk(self, path: str = "/"):
        """Yield ``(path, inode)`` for every entry below ``path``."""
        root = self.lookup(path)
        if root is None:
            return
        base = "/" + path.strip("/") if path.strip("/") else ""
        stack = [(base or "", root)]
        while stack:
            current_path, inode = stack.pop()
            yield current_path or "/", inode
            if inode.is_dir:
                for name, child_ref, _child in self.readdir(inode.ref):
                    child = self._inode_at(child_ref)
                    stack.append((f"{current_path}/{name}", child))
