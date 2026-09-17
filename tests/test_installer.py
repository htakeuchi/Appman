import os
import tempfile
import unittest
import unittest.mock

from appman import installer, paths, registry
from appman.appimage import sha256_file
from appman.installer import _build_desktop, _managed_paths
from appman.util import is_within

from _common import sample_appimage

SAMPLE = sample_appimage()


@unittest.skipUnless(SAMPLE, "no sample AppImage available (set APPMAN_TEST_APPIMAGE)")
class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = {
            "APPMAN_HOME": os.path.join(self.tmp.name, "appman-home"),
            "XDG_DATA_HOME": os.path.join(self.tmp.name, "data"),
        }
        self._patch = unittest.mock.patch.dict(os.environ, env)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_install_lifecycle(self):
        outcome = installer.install(SAMPLE, yes=True)
        app = outcome.app
        self.assertTrue(app.id)
        self.assertTrue(os.path.isfile(app.appimage_path))
        self.assertTrue(os.access(app.appimage_path, os.X_OK))
        self.assertTrue(os.path.isfile(app.launcher_path))
        self.assertTrue(os.path.isfile(paths.db_path(app.id)))
        if app.icon_path is not None:
            self.assertTrue(os.path.isfile(app.icon_path))

        with open(app.launcher_path, encoding="utf-8") as handle:
            content = handle.read()
        self.assertIn(app.appimage_path, content)
        if app.icon_theme_name:
            self.assertIn(f"Icon={app.icon_theme_name}", content)

        self.assertEqual(registry.match(app.id).id, app.id)

        second = installer.install(SAMPLE, yes=True)
        self.assertTrue(second.already_installed)

        force = installer.install(SAMPLE, force=True)
        self.assertTrue(force.replaced)
        self.assertTrue(os.path.isfile(force.backup_path))

        repo = installer.remove(app, yes=True)
        self.assertFalse(os.path.exists(app.appimage_path))
        self.assertFalse(os.path.exists(app.launcher_path))
        self.assertFalse(os.path.exists(paths.db_path(app.id)))
        self.assertIsNone(registry.load(app.id))

    def test_dry_run_does_not_change(self):
        installer.install(SAMPLE, dry_run=True)
        self.assertEqual(registry.load_all(), [])
        self.assertFalse(os.path.exists(paths.apps_dir()))

    def test_recorded_hash_matches_installed_copy(self):
        app = installer.install(SAMPLE, yes=True).app
        self.assertEqual(app.sha256, sha256_file(app.appimage_path))

    def test_rollback_restores_previous_install(self):
        first = installer.install(SAMPLE, yes=True).app
        with open(first.launcher_path, encoding="utf-8") as handle:
            launcher = handle.read()
        with open(paths.db_path(first.id), encoding="utf-8") as handle:
            database = handle.read()
        original_hash = sha256_file(first.appimage_path)

        with unittest.mock.patch("appman.registry.save",
                                 side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                installer.install(SAMPLE, force=True, yes=True)

        self.assertEqual(sha256_file(first.appimage_path), original_hash)
        with open(first.launcher_path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), launcher)
        with open(paths.db_path(first.id), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), database)

    def test_remove_reports_failures(self):
        app = installer.install(SAMPLE, yes=True).app
        os.unlink(app.launcher_path)
        os.mkdir(app.launcher_path)
        with self.assertRaisesRegex(installer.InstallError, "could not be removed"):
            installer.remove(app, yes=True)

    def test_is_within_resolves_symlinks(self):
        managed = os.path.join(self.tmp.name, "managed")
        outside = os.path.join(self.tmp.name, "outside")
        os.makedirs(managed)
        os.makedirs(outside)
        link = os.path.join(managed, "link")
        os.symlink(outside, link)
        self.assertFalse(is_within(os.path.join(link, "secret"), managed))
        self.assertTrue(is_within(os.path.join(managed, "file"), managed))

    def test_managed_paths_refuses_outside(self):
        outside = os.path.join(self.tmp.name, "outside")
        app = registry.InstalledApp(
            id="evil",
            name="Evil",
            version=None,
            installed_at="2020-01-01T00:00:00+00:00",
            sha256=None,
            size=0,
            appimage_path=os.path.join(outside, "evil.AppImage"),
            original_filename="evil.AppImage",
            icon_path=os.path.join(outside, "icon.png"),
            launcher_path=os.path.join(outside, "notours.desktop"),
        )
        targets = _managed_paths(app)
        self.assertNotIn(app.appimage_path, targets)
        self.assertNotIn(app.icon_path, targets)
        self.assertNotIn(app.launcher_path, targets)
        # The registry record always lives under the managed db directory.
        self.assertEqual(targets, [paths.db_path(app.id)])


class RegistryDeleteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = {
            "APPMAN_HOME": os.path.join(self.tmp.name, "appman-home"),
            "XDG_DATA_HOME": os.path.join(self.tmp.name, "data"),
        }
        self._patch = unittest.mock.patch.dict(os.environ, env)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        paths.ensure_dirs()

    def test_refuses_id_escaping_db_dir(self):
        outside = os.path.join(self.tmp.name, "outside.json")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write("{}")
        registry.delete("../../outside")
        self.assertTrue(os.path.exists(outside))

    def test_deletes_managed_entry(self):
        target = paths.db_path("ok")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("{}")
        registry.delete("ok")
        self.assertFalse(os.path.exists(target))

    def test_remove_deletes_registry_file(self):
        app = registry.InstalledApp(
            id="solo",
            name="Solo",
            version=None,
            installed_at="2020-01-01T00:00:00+00:00",
            sha256=None,
            size=0,
            appimage_path=paths.appimage_path("solo"),
            original_filename="solo.AppImage",
            launcher_path=paths.launcher_path("solo"),
        )
        with open(paths.db_path("solo"), "w", encoding="utf-8") as handle:
            handle.write(app.to_json())
        with open(app.launcher_path, "w", encoding="utf-8") as handle:
            handle.write("[Desktop Entry]\n")
        installer.remove(app, yes=True)
        self.assertFalse(os.path.exists(paths.db_path("solo")))
        self.assertFalse(os.path.exists(app.launcher_path))


class InstallErrorTest(unittest.TestCase):
    def test_truncated_elf_reports_clean_error(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "short.AppImage")
        with open(path, "wb") as handle:
            handle.write(b"\x7fELF\x02\x01" + b"\x00" * 10)
        with self.assertRaises(installer.InstallError) as caught:
            installer.install(path)
        self.assertIn("truncated ELF header", str(caught.exception))


class BuildDesktopTest(unittest.TestCase):
    def test_values_cannot_inject_keys(self):
        app = registry.InstalledApp(
            id="evil",
            name="Ok",
            version=None,
            installed_at="2020-01-01T00:00:00+00:00",
            sha256=None,
            size=0,
            appimage_path="/apps/evil.AppImage",
            original_filename="evil.AppImage",
            comment="hi",
            categories="Utility;\nExec=/bin/evil\nX-Evil=1",
        )
        desktop = _build_desktop(app)
        entry = {}
        for line in desktop.splitlines():
            key, _, value = line.partition("=")
            entry[key] = value
        self.assertEqual(entry["Categories"], "Utility;\\nExec=/bin/evil\\nX-Evil=1")
        self.assertNotIn("X-Evil", entry)


if __name__ == "__main__":
    unittest.main()
