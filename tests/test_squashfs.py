import io
import struct
import unittest

from appman.appimage import read_elf_info
from appman.squashfs import SquashFS, SquashFSError

from _common import sample_appimage

SAMPLE = sample_appimage()


def _superblock(major: int, minor: int = 0) -> bytes:
    raw = bytearray(96)
    raw[0:4] = b"hsqs"
    struct.pack_into("<IIIIHHHHHH", raw, 4,
                     1, 0, 4096, 0, 1, 12, 0, 1, major, minor)
    return bytes(raw)


class VersionTest(unittest.TestCase):
    def test_version_4_accepted(self):
        squash = SquashFS(io.BytesIO(_superblock(4)))
        self.assertEqual(squash.major, 4)

    def test_version_3_rejected(self):
        with self.assertRaisesRegex(SquashFSError, "unsupported SquashFS version 3.0"):
            SquashFS(io.BytesIO(_superblock(3)))


@unittest.skipUnless(SAMPLE, "no sample AppImage available (set APPMAN_TEST_APPIMAGE)")
class SquashFSTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fileobj = open(SAMPLE, "rb")
        info = read_elf_info(cls.fileobj)
        cls.payload = info.payload_offset
        cls.squash = SquashFS(cls.fileobj, cls.payload)

    @classmethod
    def tearDownClass(cls):
        cls.fileobj.close()

    def _root_entries(self):
        return self.squash.readdir(self.squash.root_inode_ref)

    def test_superblock(self):
        self.assertEqual(self.squash.major, 4)
        self.assertGreater(self.squash.block_size, 0)

    def test_root_listing(self):
        entries = self._root_entries()
        self.assertGreater(len(entries), 0)
        for name, _ref, inode in entries:
            self.assertIsInstance(name, str)
            self.assertTrue(name)

    def test_read_root_desktop(self):
        desktop = next((name for name, _ref, inode in self._root_entries()
                        if inode.is_file and name.endswith(".desktop")), None)
        if desktop is None:
            self.skipTest("sample AppImage has no root .desktop entry")
        data = self.squash.read_path(desktop)
        self.assertIsNotNone(data)
        self.assertTrue(data.startswith(b"[Desktop Entry]"))

    def test_symlink_resolution(self):
        inode = self.squash.lookup(".DirIcon")
        if inode is None or not inode.is_file:
            self.skipTest("sample AppImage has no .DirIcon")
        data = self.squash.read(inode)
        self.assertNotEqual(data, b"")

    def test_missing_path(self):
        self.assertIsNone(self.squash.lookup("does/not/exist"))

    def test_read_multi_block_file(self):
        target = None
        for name, _ref, inode in self._root_entries():
            if inode.is_file and self.squash.block_size < inode.size < 30_000_000:
                target = (name, inode)
                break
        if target is None:
            self.skipTest("no medium sized file in sample AppImage")
        name, inode = target
        data = self.squash.read_path(name)
        self.assertEqual(len(data), inode.size)


if __name__ == "__main__":
    unittest.main()
