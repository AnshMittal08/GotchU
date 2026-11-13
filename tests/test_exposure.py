"""A made-up user profile with secrets in it: they must be counted, and never repeated."""
import json
import os
import sqlite3
import tempfile
import unittest

from gotchu import exposure, report, tripwire

SECRET = "hunter2-do-not-print"


def fake_profile(home):
    chrome = os.path.join(home, "Local", "Google", "Chrome", "User Data", "Default")
    os.makedirs(os.path.join(chrome, "Network"))
    con = sqlite3.connect(os.path.join(chrome, "Login Data"))
    con.execute("CREATE TABLE logins (origin_url TEXT, password_value TEXT)")
    con.executemany("INSERT INTO logins VALUES (?, ?)", [("https://a.example", SECRET), ("https://b.example", SECRET)])
    con.commit()
    con.close()
    con = sqlite3.connect(os.path.join(chrome, "Network", "Cookies"))
    con.execute("CREATE TABLE cookies (host_key TEXT, value TEXT)")
    con.executemany("INSERT INTO cookies VALUES (?, ?)", [("a.example", SECRET), ("a.example", "x"), ("b.example", "y")])
    con.commit()
    con.close()
    os.makedirs(os.path.join(home, ".aws"))
    with open(os.path.join(home, ".aws", "credentials"), "w") as f:
        f.write(f"[default]\naws_secret_access_key = {SECRET}\n")
    os.makedirs(os.path.join(home, "Downloads"))
    with open(os.path.join(home, "Downloads", "server.pem"), "w") as f:
        f.write(f"-----BEGIN RSA PRIVATE KEY-----\n{SECRET}\n")
    with open(os.path.join(home, "Downloads", "certificate.pem"), "w") as f:
        f.write("-----BEGIN CERTIFICATE-----\npublic, not a secret\n")
    return {"LOCALAPPDATA": os.path.join(home, "Local"), "APPDATA": os.path.join(home, "Roaming"), "USERPROFILE": home}


class ExposureTests(unittest.TestCase):
    def test_counts_secrets_without_repeating_them(self):
        with tempfile.TemporaryDirectory() as home:
            items = exposure.collect(fake_profile(home))
            found = {(i["kind"], i["count"]) for i in items}
            self.assertEqual(found, {("passwords", 2), ("sessions", 2), ("cloud", 1), ("keys", 1)})
            self.assertTrue(all(i["readable"] for i in items))
            self.assertNotIn(SECRET, json.dumps(items) + json.dumps(exposure.analyse(items)))

    def test_empty_profile_is_clear(self):
        with tempfile.TemporaryDirectory() as home:
            env = {"LOCALAPPDATA": home, "APPDATA": home, "USERPROFILE": home}
            self.assertEqual(report.level(exposure.analyse(exposure.collect(env))), "ok")

    def test_a_real_wallet_in_a_decoy_folder_is_still_counted(self):
        with tempfile.TemporaryDirectory() as home:
            env = {"LOCALAPPDATA": home, "APPDATA": os.path.join(home, "Roaming"), "USERPROFILE": home}
            os.makedirs(env["APPDATA"])
            decoys, _, _ = tripwire._plant(env["APPDATA"], os.path.join(home, "decoys.json"))
            self.assertEqual(exposure.collect(env, decoys=decoys), [])     # gotchu's decoys are not real wallets
            with open(os.path.join(env["APPDATA"], "Exodus", "exodus.wallet", "passphrase.json"), "w") as f:
                f.write("{}")
            found = [(i["kind"], i["name"]) for i in exposure.collect(env, decoys=decoys)]
            self.assertEqual(found, [("wallet", "Exodus wallet")])


if __name__ == "__main__":
    unittest.main()
