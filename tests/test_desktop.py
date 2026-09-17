import unittest

from appman.desktop import (build_exec, escape_exec_arg, escape_value,
                            parse_desktop)


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

    def test_escape_value_roundtrip(self):
        for raw in ("plain", "line1\nline2", "tab\there", "cr\rhere",
                    "back\\slash", "Utility;\nExec=/bin/evil"):
            self.assertEqual(parse_desktop(
                f"[Desktop Entry]\nName={escape_value(raw)}\n")["Name"], raw)

    def test_escape_value_keeps_value_on_one_line(self):
        line = f"Categories={escape_value('Utility;\nExec=/bin/evil')}"
        self.assertNotIn("\n", line)
        entry = parse_desktop(f"[Desktop Entry]\n{line}\nName=Test\n")
        self.assertEqual(entry["Categories"], "Utility;\nExec=/bin/evil")
        self.assertIsNone(entry.get("Exec"))


if __name__ == "__main__":
    unittest.main()
