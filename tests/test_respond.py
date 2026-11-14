import json
import os
import sqlite3
import tempfile
import unittest

from gotchu import respond


def item(kind, name, count=1, where=""):
    return {"kind": kind, "name": name, "count": count, "where": where}


class RespondTests(unittest.TestCase):
    def test_only_the_steps_that_apply_and_money_first(self):
        titles = [t for t, _ in respond.steps([])]
        self.assertEqual(len(titles), 4)                         # disconnect, email, clean, stay alert
        self.assertTrue(titles[0].startswith("Disconnect"))

        found = [item("passwords", "Google Chrome", 162), item("wallet", "Exodus wallet"),
                 item("cloud", "Amazon Web Services keys"), item("messenger", "Telegram Desktop")]
        titles = [t for t, _ in respond.steps(found)]
        self.assertLess(titles.index("Move your crypto to a new wallet now"), titles.index("Secure your main email account"))
        self.assertIn("Change the 162 passwords saved in your browsers", titles)
        details = " ".join(d for _, d in respond.steps(found))
        self.assertIn("delete the access key in IAM", details)
        self.assertIn("Terminate all other sessions", details)

    def test_sites_lists_names_and_never_a_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            chrome, firefox = os.path.join(tmp, "Login Data"), os.path.join(tmp, "logins.json")
            con = sqlite3.connect(chrome)
            con.execute("CREATE TABLE logins (origin_url TEXT, password_value BLOB)")
            con.execute("INSERT INTO logins VALUES ('https://bank.example/login', 'hunter2')")
            con.commit()
            con.close()
            with open(firefox, "w", encoding="utf-8") as f:
                json.dump({"logins": [{"hostname": "https://mail.example", "encryptedPassword": "hunter2"}]}, f)
            found = respond.sites([item("passwords", "Chrome", 1, chrome), item("passwords", "Firefox", 1, firefox)])
        self.assertEqual(found, ["bank.example", "mail.example"])
        self.assertNotIn("hunter2", " ".join(found))


if __name__ == "__main__":
    unittest.main()
