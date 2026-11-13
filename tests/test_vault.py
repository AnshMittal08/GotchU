import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

from gotchu import vault

SECRET = b"-----BEGIN RSA PRIVATE KEY-----\nnot-a-real-key\n"


@unittest.skipUnless(sys.platform == "win32", "the vault uses Windows' encryption")
class VaultTests(unittest.TestCase):
    def test_windows_cipher_matches_the_published_answer(self):
        # AES-256-GCM, all-zero key, nonce and block: test case 14 of the GCM specification.
        ciphertext, tag = vault._gcm(bytes(32), bytes(12), bytes(16), b"")
        self.assertEqual(ciphertext.hex(), "cea7403d4d606b6e074ec5d3baf39d18")
        self.assertEqual(tag.hex(), "d0d1c8a799996bf0265b98b5d48ab919")

    def test_round_trip_and_what_a_thief_gets(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, original = os.path.join(tmp, "vault"), os.path.join(tmp, "server.pem")
            with open(original, "wb") as f:
                f.write(SECRET)
            recovery = vault.create("correct horse battery", folder)
            key = vault.unlock("correct horse battery", folder)
            vault.add(key, original, folder, move=True)

            self.assertFalse(os.path.exists(original))                       # moved, not copied
            stolen = b"".join(p.read_bytes() for p in pathlib.Path(folder).iterdir())
            self.assertNotIn(b"PRIVATE KEY", stolen)                         # contents unreadable
            self.assertNotIn(b"server.pem", stolen)                          # so is the file name
            with self.assertRaises(vault.WrongSecret):
                vault.unlock("wrong guess", folder)

            self.assertEqual(vault.get(vault.unlock(recovery.lower(), folder), "server.pem", folder), SECRET)

            blob = pathlib.Path(folder, vault.names(key, folder)["server.pem"] + ".bin")
            data = bytearray(blob.read_bytes())
            data[20] ^= 1
            blob.write_bytes(bytes(data))
            with self.assertRaises(vault.WrongSecret):                       # tampering is detected
                vault.get(key, "server.pem", folder)

    def test_a_vault_from_before_the_stronger_setting_opens_and_is_upgraded(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = os.path.join(tmp, "vault")
            with mock.patch.object(vault, "SCRYPT", vault.LEGACY_SCRYPT):
                recovery = vault.create("correct horse battery", folder)
            header_file = pathlib.Path(folder, "vault.json")
            header = json.loads(header_file.read_text())
            for slot in ("passphrase", "recovery"):
                del header[slot]["scrypt"]                                   # earlier versions did not store it
            header_file.write_text(json.dumps(header))

            key = vault.unlock("correct horse battery", folder)
            self.assertEqual(json.loads(header_file.read_text())["passphrase"]["scrypt"], vault.SCRYPT)
            self.assertEqual(vault.unlock("correct horse battery", folder), key)
            self.assertEqual(vault.unlock(recovery, folder), key)           # the recovery slot is left as it was


if __name__ == "__main__":
    unittest.main()
