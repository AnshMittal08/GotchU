import unittest

from gotchu import report, tripwire

ALERT = {"time": "2026-11-13T10:00:00", "program": r"C:\Users\A\AppData\Local\Temp\x.exe", "file": "f", "cut": True}


class TripwireTests(unittest.TestCase):
    def test_decoys_never_go_where_the_real_app_lives(self):
        installed = r"C:\Users\A\AppData\Roaming\Electrum"
        planned = tripwire.plan(r"C:\Users\A\AppData\Roaming", exists=lambda p: p == installed)
        self.assertEqual(len(planned), len(tripwire.DECOYS) - 1)
        self.assertNotIn(installed, [root for root, _ in planned])

    def test_levels(self):
        state = {"on": True, "cut": True, "decoys": ["f"], "alerts": []}
        self.assertEqual(report.level(tripwire.analyse(state)), "ok")
        self.assertEqual(report.level(tripwire.analyse({**state, "alerts": [ALERT]})), "danger")
        self.assertEqual(report.level(tripwire.analyse({**state, "on": False})), "warn")


if __name__ == "__main__":
    unittest.main()
