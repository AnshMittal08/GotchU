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


def lock(path):
    """Mark every member as password-protected, the way an encrypted zip is marked."""
    with open(path, "rb") as f:
        data = bytearray(f.read())
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = data.find(signature)
        while i >= 0:
            data[i + offset] |= 1
            i = data.find(signature, i + 4)
    with open(path, "wb") as f:
        f.write(data)
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

    def test_password_protected_programs_are_reported_not_crashed_on(self):
        path = lock(make_zip(self.tmp.name, "invoice_password_1234.zip", {"Invoice.exe": b"MZ" + b"\0" * 200}))
        found = self.titles(path)
        self.assertIn(("HIGH", "Password-protected archive with programs inside"), found)
        lock(make_zip(self.tmp.name, "photos.zip", {"a.jpg": b"\xff\xd8\xff", "b.jpg": b"\xff\xd8\xff"}))
        self.assertIn(("MEDIUM", "Password-protected archive: 2 files could not be checked"),
                      self.titles(os.path.join(self.tmp.name, "photos.zip")))

    def test_a_damaged_archive_is_reported_not_crashed_on(self):
        path = make_zip(self.tmp.name, "setup.zip", {"setup.exe": b"MZ" + os.urandom(4096) + b"\0" * 50000})
        with open(path, "rb") as f:
            data = bytearray(f.read())
        start = data.find(b"setup.exe") + len("setup.exe")
        data[start + 10:start + 400] = b"\xff" * 390        # break the compressed bytes
        with open(path, "wb") as f:
            f.write(data)
        self.assertIn("Parts of the download could not be read", [t for _, t in self.titles(path)])

    def test_disk_images_are_flagged_and_their_empty_space_is_not_padding(self):
        path = os.path.join(self.tmp.name, "Invoice.iso")
        with open(path, "wb") as f:
            f.write(b"\0" * (25 * 1024 * 1024))
        found = self.titles(path)
        self.assertIn(("MEDIUM", "Disk image: Invoice.iso"), found)
        self.assertFalse(any("Padding" in t for _, t in found))

    def test_a_folder_can_be_checked_without_its_subfolders(self):
        os.makedirs(os.path.join(self.tmp.name, "app", "resources"))
        for name in ("app/app.exe", "app/resources/data.bin"):
            with open(os.path.join(self.tmp.name, name), "wb") as f:
                f.write(b"MZ")
        folder = os.path.join(self.tmp.name, "app")
        self.assertEqual([m.name for m in check.members(folder, recursive=False)], ["app.exe"])
        self.assertEqual(len(check.members(folder)), 2)

    def test_an_archive_that_cannot_be_opened_is_never_called_clean(self):
        path = os.path.join(self.tmp.name, "photos.7z")
        with open(path, "wb") as f:
            f.write(b"7z\xbc\xaf\x27\x1c" + b"\0" * 64)
        result = check.result(path)
        self.assertEqual((result["level"], result["verdict"]), ("warn", "COULD NOT LOOK INSIDE"))
        nested = make_zip(self.tmp.name, "bundle.zip", {"readme.txt": b"hello", "inner.rar": b"Rar!" + b"\0" * 64})
        self.assertIn(("MEDIUM", "Archive gotchu cannot look inside: inner.rar"), self.titles(nested))

    def test_ordinary_zip_passes(self):
        path = make_zip(self.tmp.name, "notes.zip", {
            "readme.txt": b"hello " * 1000,
            "photo.jpg": b"\xff\xd8\xff" + os.urandom(200 * 1024),  # real compressed format: fine
        })
        self.assertEqual(check.verdict(check.analyse(path))[0], "NO KNOWN TRICKS FOUND")


if __name__ == "__main__":
    unittest.main()
