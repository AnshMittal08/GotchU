"""Harmless re-creations of real malware packaging tricks. Run: python -m unittest -v"""
import os
import tempfile
import unittest
import zipfile

from gotchu import check


def make_zip(folder, name, files):
    path = os.path.join(folder, name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for member, data in files.items():
            z.writestr(member, data)
    return path


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def titles(self, path):
        return [(sev, title) for sev, title, _ in check.analyse(path)]

    def test_fake_game_installer_is_dangerous(self):
        path = make_zip(self.tmp.name, "Download_Game_Archive_free_1234.zip", {
            "Setup.exe": b"MZ" + b"\0" * 100,
            "renpy/main.py": b"print('engine')",
            "data/libwin.rpa": b"RPA-3.0 0000 4242\n",
            "data/libpython.rpmc": b"\0" * (25 * 1024 * 1024),   # padding
            "data/wRu9y6BVCokq.tK": os.urandom(300 * 1024),       # encrypted payload
        })
        found = self.titles(path)
        self.assertEqual(check.verdict(check.analyse(path))[0], "DANGEROUS")
        self.assertTrue(any(s == "HIGH" and "Padding" in t for s, t in found))
        self.assertTrue(any(s == "HIGH" and "Encrypted" in t for s, t in found))
        self.assertTrue(any("Game engine" in t for _, t in found))
        self.assertTrue(any("pirated" in t for _, t in found))

    def test_disguised_program_and_shortcut(self):
        path = make_zip(self.tmp.name, "invoice.zip", {"invoice.pdf.exe": b"MZ", "open me.lnk": b"L\0"})
        found = self.titles(path)
        self.assertTrue(any("disguised" in t for _, t in found))
        self.assertTrue(any("Shortcut" in t for _, t in found))

    def test_a_folder_can_be_checked_without_its_subfolders(self):
        os.makedirs(os.path.join(self.tmp.name, "app", "resources"))
        for name in ("app/app.exe", "app/resources/data.bin"):
            with open(os.path.join(self.tmp.name, name), "wb") as f:
                f.write(b"MZ")
        folder = os.path.join(self.tmp.name, "app")
        self.assertEqual([m.name for m in check.members(folder, recursive=False)], ["app.exe"])
        self.assertEqual(len(check.members(folder)), 2)

    def test_ordinary_zip_passes(self):
        path = make_zip(self.tmp.name, "notes.zip", {
            "readme.txt": b"hello " * 1000,
            "photo.jpg": b"\xff\xd8\xff" + os.urandom(200 * 1024),  # real compressed format: fine
        })
        self.assertEqual(check.verdict(check.analyse(path))[0], "NO KNOWN TRICKS FOUND")


if __name__ == "__main__":
    unittest.main()
