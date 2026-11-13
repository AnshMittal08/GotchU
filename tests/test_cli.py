"""The command line: when a command cannot run, it says why in plain words and exits with 3."""
import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from gotchu import __main__ as cli
from gotchu import report


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

    def test_a_missing_download_is_explained(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = run(["check", os.path.join(tmp, "gone.zip")])
        self.assertEqual(code, 3)
        self.assertIn("does not exist", out)


if __name__ == "__main__":
    unittest.main()
