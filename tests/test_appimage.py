import io
import os
import struct
import tempfile
import unittest
from unittest import mock

from appman.appimage import (AppImageError, AppImageMetadata,
                             _app_id_from_filename, _choose_desktop_name,
                             _inspect_unsquashfs, _is_squashfs, _parse_exec,
                             _parse_unsquashfs_listing, _pick_tree_icon,
                             _select_icon_entries, _version_from_filename,
                             icon_size_dir, inspect, sanitize_id, validate)
from appman.squashfs import SquashFSError

from _common import sample_appimage

SAMPLE = sample_appimage()


def _tiny_png(size: int = 64) -> bytes:
    return (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"
            + struct.pack(">II", size, size) + b"\x00" * 4)


class IconSizeTest(unittest.TestCase):
    def test_svg_is_scalable(self):
        self.assertEqual(icon_size_dir(".svg", b"<svg/>"), "scalable")

    def test_exact_png_size(self):
        self.assertEqual(icon_size_dir(".png", _tiny_png(24)), "24x24")
        self.assertEqual(icon_size_dir(".png", _tiny_png(512)), "512x512")

    def test_rounds_up_to_standard_size(self):
        self.assertEqual(icon_size_dir(".png", _tiny_png(100)), "128x128")

    def test_unknown_defaults(self):
        self.assertEqual(icon_size_dir(".xpm", b"x"), "512x512")


class FilenameTest(unittest.TestCase):
    def test_id_strips_version(self):
        self.assertEqual(_app_id_from_filename("/tmp/Example-1.2.3.AppImage"),
                         "example")

    def test_version_from_filename(self):
        self.assertEqual(_version_from_filename("/tmp/Foo-Bar_1.2.3.AppImage"),
                         "1.2.3")
        self.assertIsNone(_version_from_filename("/tmp/Foo.AppImage"))

    def test_sanitize(self):
        self.assertEqual(sanitize_id("My App!!"), "my-app")
        self.assertEqual(sanitize_id("  "), "appimage")


def _write_fake(path: str, *, elf=True, magic=True, shoff=64, shentsize=64, shnum=2):
    data = bytearray(192)
    if elf:
        data[0:4] = b"\x7fELF"
        data[4] = 2
        data[5] = 1
    if magic:
        data[8:11] = b"AI\x02"
    struct.pack_into("<H", data, 18, 0x3E)
    struct.pack_into("<Q", data, 40, shoff)
    struct.pack_into("<H", data, 58, shentsize)
    struct.pack_into("<H", data, 60, shnum)
    data.extend(b"not a squashfs payload")
    with open(path, "wb") as handle:
        handle.write(data)


class ValidationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _path(self, name):
        return os.path.join(self.tmp.name, name)

    def test_not_elf(self):
        path = self._path("text.AppImage")
        with open(path, "wb") as handle:
            handle.write(b"hello")
        with self.assertRaises(AppImageError):
            validate(path)

    def test_elf_without_magic(self):
        path = self._path("plain.AppImage")
        _write_fake(path, magic=False)
        with self.assertRaisesRegex(AppImageError, "missing AppImage magic"):
            validate(path)

    def test_corrupt_payload(self):
        path = self._path("Broken-1.0.0.AppImage")
        _write_fake(path)
        with self.assertRaisesRegex(AppImageError, "corrupt AppImage"):
            validate(path)

    def test_truncated_elf_header_64(self):
        path = self._path("short64.AppImage")
        with open(path, "wb") as handle:
            handle.write(b"\x7fELF\x02\x01" + b"\x00" * 10)
        with self.assertRaisesRegex(AppImageError, "truncated ELF header"):
            validate(path)

    def test_truncated_elf_header_63_bytes(self):
        path = self._path("short63.AppImage")
        data = bytearray(63)
        data[0:4] = b"\x7fELF"
        data[4] = 2
        data[5] = 1
        data[8:11] = b"AI\x02"
        with open(path, "wb") as handle:
            handle.write(data)
        with self.assertRaisesRegex(AppImageError, "truncated ELF header"):
            validate(path)

    def test_truncated_elf_header_32(self):
        path = self._path("short32.AppImage")
        with open(path, "wb") as handle:
            handle.write(b"\x7fELF\x01\x01" + b"\x00" * 10)
        with self.assertRaisesRegex(AppImageError, "truncated ELF header"):
            validate(path)

    def test_missing_file(self):
        with self.assertRaisesRegex(AppImageError, "not found"):
            validate(self._path("nope.AppImage"))


class ParseExecTest(unittest.TestCase):
    def test_drops_apprun(self):
        self.assertEqual(_parse_exec("AppRun %U"), ["%U"])

    def test_drops_mismatched_program_name(self):
        self.assertEqual(_parse_exec("some-product %U"), ["%U"])

    def test_drops_appimage_name(self):
        self.assertEqual(_parse_exec("SomeProduct.AppImage --foo"), ["--foo"])

    def test_drops_absolute_program_path(self):
        self.assertEqual(_parse_exec("/opt/app/AppRun -x"), ["-x"])

    def test_program_only_yields_no_args(self):
        self.assertEqual(_parse_exec("myapp"), [])

    def test_empty(self):
        self.assertEqual(_parse_exec(None), [])
        self.assertEqual(_parse_exec(""), [])

    def test_keeps_quoted_arguments(self):
        self.assertEqual(_parse_exec('myapp "a b" --x'), ["a b", "--x"])


class PayloadDetectionTest(unittest.TestCase):
    def _superblock(self, major: int) -> io.BytesIO:
        raw = bytearray(96)
        raw[0:4] = b"hsqs"
        struct.pack_into("<IIIIHHHHHH", raw, 4,
                         1, 0, 4096, 0, 1, 12, 0, 1, major, 0)
        return io.BytesIO(bytes(raw))

    def test_accepts_version_4(self):
        self.assertTrue(_is_squashfs(self._superblock(4), 0))

    def test_rejects_version_3(self):
        self.assertFalse(_is_squashfs(self._superblock(3), 0))


class TreeSymlinkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, "root")
        self.outside = os.path.join(self.tmp.name, "outside")
        os.makedirs(self.root)
        os.makedirs(self.outside)
        self.secret = os.path.join(self.outside, "id_rsa")
        with open(self.secret, "wb") as handle:
            handle.write(_tiny_png(64))
        self.secret_desktop = os.path.join(self.outside, "evil.desktop")
        with open(self.secret_desktop, "w", encoding="utf-8") as handle:
            handle.write("[Desktop Entry]\nName=Evil\n")

    def test_desktop_symlink_outside_rejected(self):
        os.symlink(self.secret_desktop, os.path.join(self.root, "evil.desktop"))
        self.assertIsNone(_choose_desktop_name(self.root, ["evil.desktop"], "evil"))

    def test_desktop_regular_file_accepted(self):
        with open(os.path.join(self.root, "app.desktop"), "w", encoding="utf-8") as handle:
            handle.write("[Desktop Entry]\nName=App\n")
        self.assertEqual(_choose_desktop_name(self.root, ["app.desktop"], "app"),
                         "app.desktop")

    def test_icon_symlink_outside_rejected(self):
        os.symlink(self.secret, os.path.join(self.root, "evil.png"))
        self.assertIsNone(_pick_tree_icon(self.root, "evil"))

    def test_diricon_symlink_outside_rejected(self):
        os.symlink(self.secret, os.path.join(self.root, ".DirIcon"))
        self.assertIsNone(_pick_tree_icon(self.root, None))

    def test_icon_symlink_inside_accepted(self):
        real = os.path.join(self.root, "real.png")
        with open(real, "wb") as handle:
            handle.write(_tiny_png(64))
        os.symlink(real, os.path.join(self.root, "app.png"))
        picked = _pick_tree_icon(self.root, "app")
        self.assertIsNotNone(picked)
        self.assertEqual(picked[0], "app.png")

    def test_pixmap_directory_symlink_outside_rejected(self):
        os.makedirs(os.path.join(self.root, "usr", "share"))
        os.symlink(self.outside, os.path.join(self.root, "usr/share/pixmaps"))
        os.symlink(self.secret, os.path.join(self.outside, "app.png"))
        self.assertIsNone(_pick_tree_icon(self.root, "app"))


@unittest.skipUnless(SAMPLE, "no sample AppImage available (set APPMAN_TEST_APPIMAGE)")
class InspectTest(unittest.TestCase):
    def test_inspect_metadata(self):
        meta = inspect(SAMPLE)
        self.assertEqual(meta.appimage_type, 2)
        self.assertTrue(meta.app_id)
        self.assertTrue(meta.name)
        self.assertTrue(meta.arch)
        if meta.desktop_filename is not None:
            self.assertTrue(meta.desktop_filename.endswith(".desktop"))
        if meta.icon_bytes is not None:
            self.assertIn(meta.icon_ext, (".png", ".svg", ".svgz", ".xpm"))
        for arg in meta.exec_args:
            self.assertFalse(arg.startswith("--appimage-"))


class ListingParseTest(unittest.TestCase):
    LISTING = (
        "drwxr-xr-x root/root         0 2024-01-01 00:00 squashfs-root\n"
        "drwxr-xr-x root/root         0 2024-01-01 00:00 squashfs-root/usr\n"
        "-rw-r--r-- root/root      1234 2024-01-01 00:00 squashfs-root/app.desktop\n"
        "lrwxrwxrwx root/root         0 2024-01-01 00:00 squashfs-root/.DirIcon -> usr/share/icons/app.svg\n"
        "-rw-r--r-- root/root    512000 2024-01-01 00:00 squashfs-root/usr/share/icons/app.svg\n"
    )

    def test_parses_paths_types_and_links(self):
        entries = {entry.path: entry for entry in _parse_unsquashfs_listing(self.LISTING)}
        self.assertNotIn("squashfs-root", entries)
        self.assertTrue(entries["usr"].is_dir)
        self.assertFalse(entries["app.desktop"].is_dir)
        self.assertEqual(entries["app.desktop"].size, 1234)
        self.assertTrue(entries[".DirIcon"].is_link)
        self.assertEqual(entries[".DirIcon"].target, "usr/share/icons/app.svg")
        self.assertEqual(entries["usr/share/icons/app.svg"].size, 512000)

    def test_ignores_malformed_lines(self):
        self.assertEqual(_parse_unsquashfs_listing("garbage\n\n"), [])


class IconSelectTest(unittest.TestCase):
    LISTING = (
        "drwxr-xr-x root/root         0 2024-01-01 00:00 squashfs-root\n"
        "lrwxrwxrwx root/root         0 2024-01-01 00:00 squashfs-root/.DirIcon -> app.svg\n"
        "-rw-r--r-- root/root       100 2024-01-01 00:00 squashfs-root/app.svg\n"
        "-rw-r--r-- root/root   268435456 2024-01-01 00:00 squashfs-root/app.png\n"
        "-rw-r--r-- root/root       200 2024-01-01 00:00 squashfs-root/usr/share/icons/hicolor/app.svg\n"
    )

    def _by_path(self, listing=None):
        return {entry.path: entry
                for entry in _parse_unsquashfs_listing(listing or self.LISTING)}

    def test_selects_diricon_and_named_candidates(self):
        selected = _select_icon_entries(self._by_path(), "app")
        self.assertIn(".DirIcon", selected)
        self.assertIn("app.svg", selected)
        self.assertIn("usr/share/icons/hicolor/app.svg", selected)

    def test_skips_oversized_icon(self):
        self.assertNotIn("app.png", _select_icon_entries(self._by_path(), "app"))

    def test_skips_absolute_symlink_target(self):
        listing = (
            "drwxr-xr-x root/root         0 2024-01-01 00:00 squashfs-root\n"
            "lrwxrwxrwx root/root         0 2024-01-01 00:00 squashfs-root/.DirIcon -> /etc/passwd\n"
        )
        self.assertNotIn(".DirIcon", _select_icon_entries(self._by_path(listing), None))

    def test_skips_escaping_symlink_target(self):
        listing = (
            "drwxr-xr-x root/root         0 2024-01-01 00:00 squashfs-root\n"
            "lrwxrwxrwx root/root         0 2024-01-01 00:00 squashfs-root/app.png -> ../../secret.png\n"
        )
        self.assertEqual(_select_icon_entries(self._by_path(listing), "app"), [])


class UnsquashfsInspectTest(unittest.TestCase):
    DESKTOP = (
        "[Desktop Entry]\nName=Fallback App\nX-AppImage-Version=9.9\n"
        "Icon=fallback\nExec=AppRun %U\nCategories=Game;\n"
        "StartupWMClass=Fallback\n"
    )
    LISTING = (
        "drwxr-xr-x root/root         0 2024-01-01 00:00 squashfs-root\n"
        "-rw-r--r-- root/root   1073741824 2024-01-01 00:00 squashfs-root/AppRun\n"
        "-rw-r--r-- root/root      1024 2024-01-01 00:00 squashfs-root/fallback.desktop\n"
        "lrwxrwxrwx root/root         0 2024-01-01 00:00 squashfs-root/.DirIcon -> fallback.png\n"
        "-rw-r--r-- root/root     65000 2024-01-01 00:00 squashfs-root/fallback.png\n"
    )

    def _fake_extract(self, exe, image_path, offset, dest, paths):
        files = {
            "fallback.desktop": self.DESKTOP.encode("utf-8"),
            ".DirIcon": _tiny_png(64),
            "fallback.png": _tiny_png(512),
        }
        for path in paths:
            data = files.get(path)
            if data is None:
                continue
            full = os.path.join(dest, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as handle:
                handle.write(data)
        return True

    def test_selective_extraction_reads_metadata(self):
        entries = _parse_unsquashfs_listing(self.LISTING)
        meta = AppImageMetadata(path="/tmp/Fallback.AppImage", size=0)
        with mock.patch("appman.appimage.which", return_value="/usr/bin/unsquashfs"), \
             mock.patch("appman.appimage._unsquashfs_list", return_value=entries), \
             mock.patch("appman.appimage._unsquashfs_extract",
                        side_effect=self._fake_extract):
            self.assertTrue(_inspect_unsquashfs(
                "/tmp/Fallback.AppImage", 0, meta, "fallback"))
        self.assertEqual(meta.name, "Fallback App")
        self.assertEqual(meta.version, "9.9")
        self.assertEqual(meta.icon_ext, ".png")
        self.assertEqual(meta.icon_bytes[:8], b"\x89PNG\r\n\x1a\n")

    def test_large_apprun_is_never_extracted(self):
        entries = _parse_unsquashfs_listing(self.LISTING)
        meta = AppImageMetadata(path="/tmp/Fallback.AppImage", size=0)
        requested = []

        def record(exe, image_path, offset, dest, paths):
            requested.extend(paths)
            return self._fake_extract(exe, image_path, offset, dest, paths)

        with mock.patch("appman.appimage.which", return_value="/usr/bin/unsquashfs"), \
             mock.patch("appman.appimage._unsquashfs_list", return_value=entries), \
             mock.patch("appman.appimage._unsquashfs_extract", side_effect=record):
            _inspect_unsquashfs("/tmp/Fallback.AppImage", 0, meta, "fallback")
        self.assertNotIn("AppRun", requested)
        self.assertIn("fallback.desktop", requested)


@unittest.skipUnless(SAMPLE, "no sample AppImage available (set APPMAN_TEST_APPIMAGE)")
class UnsquashfsFallbackTest(unittest.TestCase):
    DESKTOP = (
        "[Desktop Entry]\nName=Fallback App\nX-AppImage-Version=9.9\n"
        "Icon=fallback\nExec=AppRun %U\nCategories=Game;\n"
        "StartupWMClass=Fallback\n"
    )
    LISTING = (
        "drwxr-xr-x root/root         0 2024-01-01 00:00 squashfs-root\n"
        "-rw-r--r-- root/root      1024 2024-01-01 00:00 squashfs-root/fallback.desktop\n"
        "lrwxrwxrwx root/root         0 2024-01-01 00:00 squashfs-root/.DirIcon -> fallback.png\n"
        "-rw-r--r-- root/root     65000 2024-01-01 00:00 squashfs-root/fallback.png\n"
    )

    def _fake_extract(self, exe, image_path, offset, dest, paths):
        files = {
            "fallback.desktop": self.DESKTOP.encode("utf-8"),
            ".DirIcon": _tiny_png(64),
            "fallback.png": _tiny_png(512),
        }
        for path in paths:
            data = files.get(path)
            if data is None:
                continue
            full = os.path.join(dest, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as handle:
                handle.write(data)
        return True

    def test_falls_back_when_compression_unsupported(self):
        entries = _parse_unsquashfs_listing(self.LISTING)
        error = SquashFSError("unsupported SquashFS compression: lzo")
        with mock.patch("appman.appimage.SquashFS", side_effect=error), \
             mock.patch("appman.appimage.which", return_value="/usr/bin/unsquashfs"), \
             mock.patch("appman.appimage._unsquashfs_list", return_value=entries), \
             mock.patch("appman.appimage._unsquashfs_extract",
                        side_effect=self._fake_extract):
            meta = inspect(SAMPLE)
        self.assertEqual(meta.name, "Fallback App")
        self.assertEqual(meta.version, "9.9")
        self.assertEqual(meta.app_id, "fallback")
        self.assertEqual(meta.icon_ext, ".png")
        self.assertEqual(meta.icon_bytes[:8], b"\x89PNG\r\n\x1a\n")

    def test_extracts_only_needed_paths(self):
        entries = _parse_unsquashfs_listing(self.LISTING)
        error = SquashFSError("unsupported SquashFS compression: lzo")
        requested = []

        def record(exe, image_path, offset, dest, paths):
            requested.extend(paths)
            return self._fake_extract(exe, image_path, offset, dest, paths)

        with mock.patch("appman.appimage.SquashFS", side_effect=error), \
             mock.patch("appman.appimage.which", return_value="/usr/bin/unsquashfs"), \
             mock.patch("appman.appimage._unsquashfs_list", return_value=entries), \
             mock.patch("appman.appimage._unsquashfs_extract", side_effect=record):
            inspect(SAMPLE)
        self.assertLessEqual(set(requested),
                             {"fallback.desktop", ".DirIcon", "fallback.png"})
        self.assertIn("fallback.desktop", requested)

    def test_reports_missing_unsquashfs(self):
        error = SquashFSError("unsupported SquashFS compression: lzo")
        with mock.patch("appman.appimage.SquashFS", side_effect=error), \
             mock.patch("appman.appimage.which", return_value=None):
            with self.assertRaisesRegex(AppImageError, "squashfs-tools"):
                inspect(SAMPLE)


if __name__ == "__main__":
    unittest.main()
