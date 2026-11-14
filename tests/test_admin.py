"""Administrator helpers: run only from Program Files, and only the version this copy of gotchu ships."""
import base64
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from gotchu import admin, harden, tripwire


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


class RunTests(unittest.TestCase):
    def test_installed_helpers_are_compared_with_this_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, dest = os.path.join(tmp, "src"), os.path.join(tmp, "dest")
            for name in admin.HELPERS:
                write(os.path.join(source, name), name.encode())
            self.assertEqual(admin.state(source, dest), "missing")
            for name in admin.HELPERS:
                write(os.path.join(dest, name), name.encode())
            self.assertEqual(admin.state(source, dest), "current")
            write(os.path.join(source, admin.HELPERS[2]), b"edited by some program")
            self.assertEqual(admin.state(source, dest), "different")

    def test_nothing_is_elevated_while_the_installed_helpers_differ(self):
        with mock.patch.object(admin, "state", return_value="different"), mock.patch.object(admin, "_elevate") as elevate:
            ok, message = admin.run("harden_apply.ps1", [])
        self.assertFalse(ok)
        self.assertIn("gotchu setup", message)
        elevate.assert_not_called()

    def test_helpers_run_from_program_files_only(self):
        with mock.patch.object(admin, "state", return_value="current"), \
                mock.patch.object(admin, "_elevate", return_value=0) as elevate:
            self.assertEqual(admin.run("harden_apply.ps1", ["-Lock", "asr"]), (True, ""))
        args = elevate.call_args[0][0]
        self.assertIn(f'"{os.path.join(admin.INSTALLED, "harden_apply.ps1")}"', args)
        self.assertFalse(any(admin.HERE in a for a in args))

    def test_declined_prompt(self):
        with mock.patch.object(admin, "state", return_value="current"), \
                mock.patch.object(admin, "_elevate", return_value=admin.CANCELLED):
            self.assertEqual(admin.run("harden_apply.ps1", []), (False, admin.DECLINED))

    def test_a_prompt_nobody_answers_is_explained_not_crashed_on(self):
        slow = subprocess.TimeoutExpired("powershell.exe", 300)
        with mock.patch.object(admin, "state", return_value="current"), \
                mock.patch.object(admin.subprocess, "run", side_effect=slow):
            self.assertEqual(admin.run("harden_apply.ps1", []), (False, admin.NO_ANSWER))

    def test_an_old_journal_is_handed_over_once_then_deleted(self):
        saved = b'\xef\xbb\xbf{"previous": 0}'   # as earlier versions wrote it
        with tempfile.TemporaryDirectory() as tmp:
            legacy, journal = os.path.join(tmp, "old"), os.path.join(tmp, "new")
            write(os.path.join(legacy, "cloud_level.json"), saved)
            with mock.patch.object(harden, "LEGACY_JOURNAL", legacy), mock.patch.object(harden, "JOURNAL", journal), \
                    mock.patch.object(admin, "run", return_value=(True, "")) as run, \
                    mock.patch.object(harden, "collect", return_value={"cloud_level": 2}):
                self.assertEqual(harden.change("cloud_level"), (True, "Turned on."))
                args = run.call_args[0][1]
                self.assertEqual(base64.b64decode(args[args.index("-Legacy") + 1]), saved)
                self.assertFalse(os.path.exists(os.path.join(legacy, "cloud_level.json")))
                self.assertFalse(harden.change("cloud_level", undo=True)[0])     # nothing saved any more

    def test_the_tripwire_plan_is_checked_by_its_fingerprint(self):
        seen = {}

        def fake_run(script, args):
            with open(args[args.index("-PlanFile") + 1].strip('"'), "rb") as f:
                seen["hash"] = hashlib.sha256(f.read()).hexdigest()
            seen["given"] = args[args.index("-PlanHash") + 1]
            return True, ""

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(tripwire, "LOCAL", tmp), \
                mock.patch.object(tripwire, "guarded", return_value=[]), mock.patch.object(admin, "run", side_effect=fake_run):
            self.assertEqual(tripwire._elevated("on"), (True, ""))
            self.assertEqual(seen["given"], seen["hash"])
            self.assertEqual(os.listdir(tmp), [])     # the plan does not outlive the change


@unittest.skipUnless(sys.platform == "win32", "runs Windows PowerShell")
class PowerShellTests(unittest.TestCase):
    """The PowerShell gotchu builds, run here without the permission prompt."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = os.path.join(tmp.name, "it's a folder")    # a space and a quote, as user names can have
        os.makedirs(self.tmp)

    def run_ps(self, args):
        out = subprocess.run(["powershell.exe", "-NoProfile", "-Command", admin.launcher(args, elevate=False)],
                             capture_output=True, timeout=120)
        return out.returncode

    def test_launcher_passes_arguments_and_the_exit_code(self):
        script, out = os.path.join(self.tmp, "echo.ps1"), os.path.join(self.tmp, "out.txt")
        write(script, b"param([string]$Path, [string]$Word)\n$Word | Set-Content -LiteralPath $Path\nexit 3\n")
        code = self.run_ps(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f'"{script}"',
                            "-Path", f'"{out}"', "-Word", "hello"])
        self.assertEqual(code, 3)
        with open(out, encoding="utf-8-sig") as f:
            self.assertEqual(f.read().strip(), "hello")

    def test_install_keeps_only_the_files_gotchu_read(self):
        source, dest = os.path.join(self.tmp, "src"), os.path.join(self.tmp, "Program Files", "gotchu")
        for name in admin.HELPERS:
            write(os.path.join(source, name), f"# {name}\n".encode())
        hashes = {name: admin._sha256(os.path.join(source, name)) for name in admin.HELPERS}

        def install():
            return self.run_ps(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                                f'"{admin.install_script(hashes, source, dest)}"'])

        self.assertEqual(install(), 0)
        self.assertEqual(admin.state(source, dest), "current")
        write(os.path.join(source, admin.HELPERS[1]), b"# swapped in after gotchu read it\n")
        self.assertEqual(install(), 2)
        self.assertFalse(os.path.exists(os.path.join(dest, admin.HELPERS[1])))


if __name__ == "__main__":
    unittest.main()
