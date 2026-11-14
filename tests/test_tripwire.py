import json
import os
import tempfile
import unittest

from gotchu import report, tripwire
from tests.test_exposure import fake_profile

ALERT = {"time": "2026-11-13T10:00:00", "program": r"C:\Users\A\AppData\Local\Temp\x.exe", "file": "f", "cut": True}


class TripwireTests(unittest.TestCase):
    def test_decoys_never_go_where_the_real_app_lives(self):
        installed = r"C:\Users\A\AppData\Roaming\Electrum"
        planned = tripwire.plan(r"C:\Users\A\AppData\Roaming", exists=lambda p: p == installed)
        self.assertEqual(len(planned), len(tripwire.DECOYS) - 1)
        self.assertNotIn(installed, [root for root, _ in planned])

    def test_levels(self):
        state = {"on": True, "cut": True, "decoys": ["f"], "stores": [], "alerts": [], "sightings": []}
        self.assertEqual(report.level(tripwire.analyse(state)), "ok")
        self.assertEqual(report.level(tripwire.analyse({**state, "alerts": [ALERT]})), "danger")
        self.assertEqual(report.level(tripwire.analyse({**state, "on": False})), "warn")
        sighting = {"time": "2026-11-13T10:00:00", "program": r"C:\Tools\backup.exe", "store": "Google Chrome", "file": "f"}
        self.assertEqual(report.level(tripwire.analyse({**state, "sightings": [sighting]})), "warn")

    def test_only_stores_with_a_known_owner_are_watched(self):
        with tempfile.TemporaryDirectory() as home:
            watched = tripwire.guarded(fake_profile(home))
            self.assertEqual(sorted(os.path.basename(w["path"]) for w in watched), ["Cookies", "Login Data"])
            self.assertTrue(all(w["owners"] == ["chrome.exe"] and w["signer"] == "Google LLC" for w in watched))

    def test_review_items(self):
        state = {"on": True, "cut": False, "decoys": ["f"], "stores": [], "alerts": [], "sightings": [],
                 "moved_in": [r"C:\Users\A\AppData\Roaming\Exodus"]}
        self.assertEqual(report.level(tripwire.analyse(state)), "warn")
        sighting = {"time": "2026-11-13T10:00:00", "program": r"C:\Program Files\Backup\backup.exe", "kind": "decoy",
                    "reason": "installed", "store": "a decoy file", "file": "f"}
        found = tripwire.analyse({**state, "moved_in": [], "sightings": [sighting]})
        self.assertEqual(report.level(found), "warn")
        self.assertIn("backup.exe read a decoy file", [t for _, t, _ in found])

    def test_reads_of_real_stores_are_grouped_and_weighed(self):
        state = {"on": True, "cut": False, "decoys": ["f"], "stores": [], "alerts": [], "sightings": []}

        def read(program, store, **more):
            return {"time": "2026-11-14T09:13:21", "program": program, "store": store, "file": "f", **more}

        edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        imports = [read(edge, f"Google Chrome (Profile 1: {f})", signed=True, known=True) for f in ("Login Data", "Web Data")]
        found = tripwire.analyse({**state, "sightings": imports})
        self.assertEqual(report.level(found), "ok")                      # a browser importing is information
        self.assertIn("msedge.exe read Google Chrome 2 times", [t for _, t, _ in found])
        thief = read(r"C:\Users\A\Downloads\setup.exe", "Google Chrome (Default: Login Data)", signed=False, known=False)
        self.assertEqual(report.level(tripwire.analyse({**state, "sightings": imports + [thief]})), "danger")

    def test_a_dead_watcher_is_reported(self):
        state = {"on": True, "cut": False, "decoys": ["f"], "stores": [], "alerts": [], "sightings": [], "watching": False}
        self.assertEqual(report.level(tripwire.analyse(state)), "warn")
        self.assertIn("not running", tripwire.analyse(state)[0][1])


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


class DecoyTests(unittest.TestCase):
    """Decoys sit where a wallet app would live. Removing them must never take a real wallet with them."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.appdata = os.path.join(tmp.name, "Roaming")
        os.makedirs(self.appdata)
        self.state_file = os.path.join(tmp.name, "gotchu", "decoys.json")
        self.state, _, _ = tripwire._plant(self.appdata, self.state_file)
        self.exodus = os.path.join(self.appdata, "Exodus")
        self.real = os.path.join(self.exodus, "exodus.wallet", "passphrase.json")   # the real app, installed later

    def test_off_removes_exactly_what_was_planted(self):
        self.assertEqual(len(self.state["files"]), len(tripwire.DECOYS))
        self.assertEqual(tripwire._remove_decoys(self.state_file), [])
        self.assertEqual(os.listdir(self.appdata), [])
        self.assertFalse(os.path.exists(self.state_file))

    def test_a_wallet_installed_since_is_never_deleted(self):
        write(self.real, b"real wallet")
        electrum = next(f for f in self.state["files"] if "Electrum" in f)
        write(electrum, b"a real Electrum wallet written over the decoy")

        left = tripwire._remove_decoys(self.state_file)
        self.assertTrue(os.path.isfile(self.real))
        self.assertFalse(os.path.exists(os.path.join(self.exodus, "exodus.wallet", "seed.seco")))   # only the decoy went
        self.assertEqual(left, [electrum])                                                          # changed: kept
        self.assertEqual(sorted(os.listdir(self.appdata)), ["Electrum", "Exodus"])

    def test_old_decoys_without_fingerprints_stay_when_a_wallet_moved_in(self):
        old = {"roots": self.state["roots"], "files": self.state["files"]}   # what earlier versions saved
        write(self.state_file, json.dumps(old).encode())
        write(self.real, b"real wallet")
        decoy = os.path.join(self.exodus, "exodus.wallet", "seed.seco")

        self.assertEqual(tripwire._remove_decoys(self.state_file), [decoy])
        self.assertTrue(os.path.isfile(self.real) and os.path.isfile(decoy))
        self.assertEqual(os.listdir(self.appdata), ["Exodus"])

    def test_switching_on_again_retires_a_decoy_a_wallet_now_uses(self):
        write(self.real, b"real wallet")
        self.assertEqual(tripwire.moved_in(tripwire.load_state(self.state_file)), [self.exodus])

        state, retired, left = tripwire._plant(self.appdata, self.state_file)
        self.assertEqual((retired, left), ([self.exodus], []))
        self.assertTrue(os.path.isfile(self.real))
        self.assertNotIn(self.exodus, state["roots"])
        self.assertEqual(len(state["files"]), len(tripwire.DECOYS) - 1)
        self.assertEqual(tripwire.moved_in(state), [])

    def test_only_untouched_decoys_count_as_decoys(self):
        wallet = os.path.join(self.exodus, "exodus.wallet")
        self.assertTrue(tripwire.only_decoys(wallet, self.state))
        write(self.real, b"real wallet")
        self.assertFalse(tripwire.only_decoys(wallet, self.state))
        self.assertFalse(tripwire.only_decoys(self.appdata, {"roots": [], "files": [], "hashes": {}}))


if __name__ == "__main__":
    unittest.main()
