import os
import struct
import tempfile
import unittest
from unittest import mock

from appman.appimage import (AppImageError, _app_id_from_filename,
                             _choose_desktop_name, _pick_tree_icon,
                             _version_from_filename, icon_size_dir, inspect,
                             sanitize_id, validate)
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

    def test_missing_file(self):
        with self.assertRaisesRegex(AppImageError, "not found"):
            validate(self._path("nope.AppImage"))


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


@unittest.skipUnless(SAMPLE, "no sample AppImage available (set APPMAN_TEST_APPIMAGE)")
class UnsquashfsFallbackTest(unittest.TestCase):
    DESKTOP = (
        "[Desktop Entry]\nName=Fallback App\nX-AppImage-Version=9.9\n"
        "Icon=fallback\nExec=AppRun %U\nCategories=Game;\n"
        "StartupWMClass=Fallback\n"
    )

    def _fake_extract(self, image_path, offset, dest):
        with open(os.path.join(dest, "fallback.desktop"), "w", encoding="utf-8") as fh:
            fh.write(self.DESKTOP)
        with open(os.path.join(dest, ".DirIcon"), "wb") as fh:
            fh.write(_tiny_png(64))
        with open(os.path.join(dest, "fallback.png"), "wb") as fh:
            fh.write(_tiny_png(512))
        return True

    def test_falls_back_when_compression_unsupported(self):
        error = SquashFSError("unsupported SquashFS compression: lzo")
        with mock.patch("appman.appimage.SquashFS", side_effect=error), \
             mock.patch("appman.appimage.which", return_value="/usr/bin/unsquashfs"), \
             mock.patch("appman.appimage._unsquashfs_extract",
                        side_effect=self._fake_extract):
            meta = inspect(SAMPLE)
        self.assertEqual(meta.name, "Fallback App")
        self.assertEqual(meta.version, "9.9")
        self.assertEqual(meta.app_id, "fallback")
        self.assertEqual(meta.icon_ext, ".png")
        self.assertEqual(meta.icon_bytes[:8], b"\x89PNG\r\n\x1a\n")

    def test_reports_missing_unsquashfs(self):
        error = SquashFSError("unsupported SquashFS compression: lzo")
        with mock.patch("appman.appimage.SquashFS", side_effect=error), \
             mock.patch("appman.appimage.which", return_value=None):
            with self.assertRaisesRegex(AppImageError, "squashfs-tools"):
                inspect(SAMPLE)


if __name__ == "__main__":
    unittest.main()
