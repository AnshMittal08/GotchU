import unittest

from gotchu import harden, report

OPEN = {"smart_app_control": 0, "asr_blocking": [], "folder_protection": 0, "network_protection": 0,
        "cloud_level": 0, "memory_integrity": 0, "is_admin": True, "file_history": False, "defender_active": True}
LOCKED = {"smart_app_control": 1, "asr_blocking": [i.upper() for i in harden.ASR_RULES], "folder_protection": 1,
          "network_protection": 1, "cloud_level": 2, "memory_integrity": 1, "is_admin": False,
          "file_history": True, "defender_active": True}


class HardenTests(unittest.TestCase):
    def test_every_lock_reported_off_on_an_open_pc(self):
        off = [t for s, t, _ in harden.analyse(OPEN) if s == "MEDIUM"]
        self.assertEqual(len(off), len(harden.LOCKS))

    def test_locked_pc_is_clear(self):
        self.assertEqual(report.level(harden.analyse(LOCKED)), "ok")

    def test_guided_locks_are_never_changed_by_gotchu(self):
        ok, message = harden.change("smart_app_control")
        self.assertFalse(ok)
        self.assertIn("Windows Security", message)


if __name__ == "__main__":
    unittest.main()
