import unittest

from appman.desktop import build_exec, escape_exec_arg, parse_desktop


class DesktopTest(unittest.TestCase):
    def test_parse_basic(self):
        entry = parse_desktop(
            "[Desktop Entry]\nName=Test\nExec=AppRun --foo %U\n# comment\n"
            "X-AppImage-Version=2.0\n\n[Other]\nName=Ignored\n"
        )
        self.assertEqual(entry["Name"], "Test")
        self.assertEqual(entry["Exec"], "AppRun --foo %U")
        self.assertEqual(entry["X-AppImage-Version"], "2.0")
        self.assertIsNone(entry.get("Missing"))

    def test_parse_ignores_other_groups(self):
        entry = parse_desktop("[Other]\nName=Nope\n")
        self.assertIsNone(entry.get("Name"))

    def test_escape(self):
        self.assertEqual(escape_exec_arg("simple"), "simple")
        self.assertEqual(escape_exec_arg("/a path/x"), '"/a path/x"')
        self.assertEqual(escape_exec_arg('a"b'), '"a\\"b"')

    def test_build_exec(self):
        self.assertEqual(build_exec("/bin/app", ["--x", "a b"]),
                         "/bin/app --x \"a b\"")


if __name__ == "__main__":
    unittest.main()
