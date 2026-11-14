"""The command line: when a command cannot run, it says why in plain words and exits with 3."""
import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from gotchu import __main__ as cli
from gotchu import report, vault


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(argv)
    return code, out.getvalue()


class CliTests(unittest.TestCase):
    def test_powershell_that_answers_nothing_is_explained(self):
        silent = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"blocked by policy")
        with mock.patch.object(report.subprocess, "run", return_value=silent):
            code, out = run(["scan"])
        self.assertEqual(code, 3)
        self.assertIn("Windows PowerShell did not give gotchu an answer, so the scan could not finish", out)

    def test_vault_passphrase_change(self):
        with mock.patch.object(vault, "exists", return_value=True), \
                mock.patch.object(vault, "unlock", return_value=b"k" * 32), \
                mock.patch.object(vault, "change_passphrase") as change, \
                mock.patch("getpass.getpass", side_effect=["recovery-key", "short"]):
            self.assertEqual(run(["vault", "passphrase"])[0], 1)            # too short: refused
            change.assert_not_called()
        with mock.patch.object(vault, "exists", return_value=True), \
                mock.patch.object(vault, "unlock", return_value=b"k" * 32), \
                mock.patch.object(vault, "change_passphrase") as change, \
                mock.patch("getpass.getpass", side_effect=["recovery-key", "new staple passphrase",
                                                           "new staple passphrase"]):
            code, out = run(["vault", "passphrase"])
        self.assertEqual(code, 0)
        change.assert_called_once_with(b"k" * 32, "new staple passphrase")
        self.assertIn("Passphrase changed", out)

    def test_a_missing_download_is_explained(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = run(["check", os.path.join(tmp, "gone.zip")])
        self.assertEqual(code, 3)
        self.assertIn("does not exist", out)


    def test_powershell_is_started_by_its_full_path(self):
        # By name alone, Windows would run a powershell.exe sitting in the current folder (a download, say).
        self.assertTrue(os.path.isabs(report.POWERSHELL) and os.path.isfile(report.POWERSHELL))
        silent = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"")
        with mock.patch.object(report.subprocess, "run", return_value=silent) as started:
            run(["scan"])
        self.assertEqual(started.call_args.args[0][0], report.POWERSHELL)

    def test_the_window_remembers_small_things_and_survives_a_damaged_file(self):
        from gotchu import desktop
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "gotchu", "app.json")
            desktop.save_state(path, skipped=["asr"])
            desktop.save_state(path, done=["step"])
            self.assertEqual(desktop.load_state(path), {"skipped": ["asr"], "done": ["step"]})
            with open(path, "w") as f:
                f.write("{not json")
            self.assertEqual(desktop.load_state(path), {})


if __name__ == "__main__":
    unittest.main()
