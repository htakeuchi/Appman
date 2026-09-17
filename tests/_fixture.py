"""Build a tiny, valid AppImage (type 2) fixture at runtime.

The image is intentionally minimal but exercises the real code paths: an
ELF header with the AppImage magic, a SquashFS v4 superblock, a root
directory, an executable ``AppRun``, a ``.desktop`` entry, a ``.DirIcon``
symlink and PNG icons (including a nested hicolor entry).

It is generated in pure Python so the test suite does not depend on
external tools such as ``mksquashfs`` or on a checked-in binary blob.
"""

from __future__ import annotations

import os
import struct

BLOCK_SIZE = 4096
BLOCK_LOG = 12
MAGIC = b"hsqs"
COMPRESSION_GZIP = 1

DIR_TYPE = 1
FILE_TYPE = 2
SYMLINK_TYPE = 3

_UNCOMPRESSED_META = 0x8000
_UNCOMPRESSED_DATA = 0x1000000
_NO_FRAGMENT = 0xFFFFFFFF

DESKTOP = (
    "[Desktop Entry]\n"
    "Type=Application\n"
    "Name=Sample App\n"
    "Comment=A tiny test AppImage\n"
    "Exec=AppRun %U\n"
    "Icon=sample\n"
    "Categories=Utility;\n"
    "X-AppImage-Version=1.0\n"
)


def _png() -> bytes:
    return (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"
            + struct.pack(">II", 64, 64) + b"\x00" * 4)


def _sample_tree() -> dict:
    png = _png()
    return {"kind": "dir", "children": {
        "AppRun": {"kind": "file", "data": b"#!/bin/sh\necho sample\n"},
        "sample.desktop": {"kind": "file", "data": DESKTOP.encode("utf-8")},
        "data.bin": {"kind": "file", "data": bytes(range(256)) * 36},
        ".DirIcon": {"kind": "symlink", "target": "sample.png"},
        "sample.png": {"kind": "file", "data": png},
        "usr": {"kind": "dir", "children": {
            "share": {"kind": "dir", "children": {
                "icons": {"kind": "dir", "children": {
                    "hicolor": {"kind": "dir", "children": {
                        "48x48": {"kind": "dir", "children": {
                            "apps": {"kind": "dir", "children": {
                                "sample.png": {"kind": "file", "data": png},
                            }},
                        }},
                    }},
                }},
            }},
        }},
    }}


def _base_inode(itype: int, mode: int, number: int) -> bytes:
    return struct.pack("<HHHHII", itype, mode, 0, 0, 0, number)


def _inode_payload(node: dict) -> bytes:
    number = node["inode"]
    kind = node["kind"]
    if kind == "dir":
        size = len(node["dir_data"])
        return (_base_inode(DIR_TYPE, 0o40755, number)
                + struct.pack("<IIHHI", 0, 2, size, node["dir_offset"], 1))
    if kind == "file":
        size = len(node["data"])
        payload = (_base_inode(FILE_TYPE, 0o100755, number)
                   + struct.pack("<IIII", node["start_block"], _NO_FRAGMENT,
                                 0, size))
        remaining = size
        while remaining > 0:
            chunk = min(BLOCK_SIZE, remaining)
            payload += struct.pack("<I", chunk | _UNCOMPRESSED_DATA)
            remaining -= chunk
        return payload
    target = node["target"].encode("utf-8")
    return (_base_inode(SYMLINK_TYPE, 0o120777, number)
            + struct.pack("<II", 1, len(target)) + target)


def _metadata_block(payload: bytes) -> bytes:
    if len(payload) >= 0x8000:
        raise ValueError("fixture metadata block too large")
    return struct.pack("<H", _UNCOMPRESSED_META | len(payload)) + payload


def _flatten(root: dict) -> list[dict]:
    nodes: list[dict] = []

    def visit(name: str, node: dict) -> None:
        node["name"] = name
        nodes.append(node)
        if node["kind"] == "dir":
            for child_name, child in node["children"].items():
                visit(child_name, child)

    visit("", root)
    return nodes


def _build_squashfs() -> bytes:
    nodes = _flatten(_sample_tree())

    offset = 0
    for number, node in enumerate(nodes, start=1):
        node["inode"] = number
        node["offset"] = offset
        if node["kind"] == "file":
            size = len(node["data"])
            node["nblocks"] = 0 if size == 0 else (size + BLOCK_SIZE - 1) // BLOCK_SIZE
            offset += 32 + 4 * node["nblocks"]
        elif node["kind"] == "symlink":
            offset += 24 + len(node["target"].encode("utf-8"))
        else:
            offset += 32

    data_offset = 96
    file_data = bytearray()
    for node in nodes:
        if node["kind"] == "file":
            node["start_block"] = data_offset + len(file_data)
            file_data += node["data"]

    for node in nodes:
        if node["kind"] != "dir":
            continue
        out = bytearray()
        children = list(node["children"].values())
        out += struct.pack("<III", max(len(children) - 1, 0), 0, node["inode"])
        for child in children:
            raw = child["name"].encode("utf-8")
            itype = {"dir": DIR_TYPE, "file": FILE_TYPE,
                     "symlink": SYMLINK_TYPE}[child["kind"]]
            out += struct.pack("<HhHH", child["offset"], 0, itype, len(raw) - 1)
            out += raw
        node["dir_data"] = bytes(out)

    dir_payload = bytearray()
    for node in nodes:
        if node["kind"] == "dir":
            node["dir_offset"] = len(dir_payload)
            dir_payload += node["dir_data"]

    inode_payload = bytearray()
    for node in nodes:
        inode_payload += _inode_payload(node)

    inode_meta = _metadata_block(bytes(inode_payload))
    dir_meta = _metadata_block(bytes(dir_payload))

    inode_table_start = 96 + len(file_data)
    directory_table_start = inode_table_start + len(inode_meta)
    id_table_start = directory_table_start + len(dir_meta)
    total = id_table_start + 4

    superblock = bytearray(96)
    superblock[0:4] = MAGIC
    struct.pack_into("<IIIIHHHHHH", superblock, 4,
                     len(nodes), 0, BLOCK_SIZE, 0, COMPRESSION_GZIP, BLOCK_LOG,
                     0, 1, 4, 0)
    struct.pack_into("<QQQQQQQQ", superblock, 32,
                     nodes[0]["offset"], total, id_table_start,
                     0xFFFFFFFFFFFFFFFF, inode_table_start,
                     directory_table_start, 0, 0)

    return bytes(superblock) + bytes(file_data) + inode_meta + dir_meta + b"\x00" * 4


def _elf_wrapper() -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little-endian
    header[6] = 1  # ELF version
    header[8:11] = b"AI\x02"  # AppImage type 2
    struct.pack_into("<H", header, 16, 2)      # ET_EXEC
    struct.pack_into("<H", header, 18, 0x3E)   # x86-64
    struct.pack_into("<I", header, 20, 1)
    struct.pack_into("<Q", header, 40, 64)     # section header offset
    struct.pack_into("<H", header, 58, 64)     # section header entry size
    struct.pack_into("<H", header, 60, 1)      # section header count
    return bytes(header) + bytes(64)


def build_appimage(path: str) -> str:
    """Write a minimal type 2 AppImage to *path* and return it."""
    data = _elf_wrapper() + _build_squashfs()
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o755)
    return path
