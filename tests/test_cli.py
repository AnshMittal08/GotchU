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


if __name__ == "__main__":
    unittest.main()
