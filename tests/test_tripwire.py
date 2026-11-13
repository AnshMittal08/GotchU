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


if __name__ == "__main__":
    unittest.main()
