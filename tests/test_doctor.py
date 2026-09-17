import subprocess
import unittest
from unittest import mock

from appman import doctor, registry

from _common import sample_appimage

SAMPLE = sample_appimage()


@unittest.skipUnless(SAMPLE, "no sample AppImage available (set APPMAN_TEST_APPIMAGE)")
class DoctorRuntimePolicyTest(unittest.TestCase):
    def _app(self) -> registry.InstalledApp:
        return registry.InstalledApp(
            id="sample",
            name="Sample App",
            version="1.0",
            installed_at="2020-01-01T00:00:00+00:00",
            sha256=None,
            size=0,
            appimage_path=SAMPLE,
            original_filename="Sample-1.0.AppImage",
            arch="unknown",
        )

    def test_non_deep_does_not_execute(self):
        with mock.patch("appman.doctor.subprocess.run",
                        side_effect=AssertionError("runtime was executed")):
            checks = doctor.app_checks(self._app(), deep=False)
        titles = [check.title for check in checks]
        self.assertFalse(any(title.startswith("Runtime probe") for title in titles))
        self.assertIn("Runtime execution", titles)

    def test_deep_executes_runtime(self):
        def fake_run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0,
                                               stdout="Version: fake\n", stderr="")

        with mock.patch("appman.doctor.subprocess.run", side_effect=fake_run):
            checks = doctor.app_checks(self._app(), deep=True)
        titles = [check.title for check in checks]
        self.assertIn("Runtime probe --appimage-version", titles)


if __name__ == "__main__":
    unittest.main()
