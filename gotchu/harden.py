"""Harden: switch on the protections that stop attacks outright, and keep them on.

Every lock states what it stops, what gets less convenient, and what to do instead if the
user declines. Changing a lock saves the previous setting first, so undo is exact.
`analyse()` is pure so it can be tested with made-up states.
"""
import json
import os
import subprocess

from . import report
from .report import INFO, MEDIUM

HERE = os.path.dirname(__file__)
JOURNAL = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "gotchu", "journal")

# Attack-surface-reduction rules gotchu turns on (IDs from Microsoft's ASR rules reference).
# Left out on purpose because Microsoft documents them as noisy or heuristic on personal PCs:
# prevalence/age (01443614...), PsExec/WMI process creation (d1e49aac...), copied system tools (c0033c00...).
ASR_RULES = {
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "abuse of vulnerable signed drivers",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "stealing Windows sign-in secrets (LSASS)",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "hiding in WMI to survive restarts",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "programs and scripts arriving by email",
    "d3e037e1-3eb8-44c8-a917-57927947596d": "scripts launching downloaded programs",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "scrambled (obfuscated) scripts",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "untrusted programs running from USB",
    "c1db55ab-c21a-4637-bb3f-a12568109d35": "ransomware-like behaviour",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Office launching other programs",
    "3b576869-a4ec-4529-8536-b80a7769e899": "Office writing programs to disk",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Office injecting code into other programs",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Office macros calling Windows directly",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "Outlook launching other programs",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Adobe Reader launching other programs",
    "33ddedf1-c6e0-47cb-833e-de6133960387": "forced restart into Safe Mode",
}

# can_apply: gotchu can switch it on and undo it. Others are guided (the user does it in Windows).
LOCKS = [
    {"key": "smart_app_control", "can_apply": False,
     "on": lambda s: s.get("smart_app_control") == 1,
     "name": "Only trusted programs can run (Smart App Control)",
     "stops": "Stops unknown and unsigned programs from starting at all - fake installers and planted DLLs never run.",
     "cost": "Unsigned tools, cracks and some small apps will not run, and there is no per-app exception.",
     "alternative": "Turn it on in Windows Security > App & browser control (no reinstall needed on recent "
                    "Windows 11). If you decline: check every download with gotchu before opening it."},
    {"key": "asr", "can_apply": True,
     "on": lambda s: set(ASR_RULES) <= {str(i).lower() for i in (s.get("asr_blocking") or [])},
     "name": "Common malware techniques are blocked (attack-surface-reduction rules)",
     "stops": f"Blocks {len(ASR_RULES)} techniques, including: " + "; ".join(list(ASR_RULES.values())[:6]) + ".",
     "cost": "Some document macros, scrambled scripts and old installers get blocked.",
     "alternative": "If you decline: nothing replaces these rules; rely on checking downloads first."},
    {"key": "folder_protection", "can_apply": True,
     "on": lambda s: s.get("folder_protection") == 1,
     "name": "Documents are protected from ransomware (Controlled Folder Access)",
     "stops": "Only approved programs can change files in Documents, Pictures and Desktop.",
     "cost": "Games and tools that save there are blocked until you allow them once in Windows Security.",
     "alternative": "If you decline: keep a backup that is not always connected."},
    {"key": "network_protection", "can_apply": True,
     "on": lambda s: s.get("network_protection") == 1,
     "name": "Known-bad websites are blocked for every program (network protection)",
     "stops": "Stops any program, not just the browser, from reaching servers known to host malware.",
     "cost": "A site is occasionally blocked by mistake.",
     "alternative": "If you decline: only the browser's own filter protects you."},
    {"key": "cloud_level", "can_apply": True,
     "on": lambda s: (s.get("cloud_level") or 0) >= 2,
     "name": "New, unknown files get a stricter check (cloud protection level)",
     "stops": "Brand-new files are held until Microsoft's cloud has looked at them.",
     "cost": "Unknown files open a few seconds later.",
     "alternative": "If you decline: the default level lets more new files through."},
    {"key": "memory_integrity", "can_apply": False,
     "on": lambda s: s.get("memory_integrity") == 1,
     "name": "The core of Windows is protected (memory integrity)",
     "stops": "Stops malicious and vulnerable drivers from loading into Windows itself.",
     "cost": "Very old drivers may stop working; needs a restart.",
     "alternative": "Turn it on in Windows Security > Device security > Core isolation."},
    {"key": "standard_account", "can_apply": False,
     "on": lambda s: not s.get("is_admin"),
     "name": "Everyday use is on a standard account, not an administrator",
     "stops": "Malware you run by mistake cannot change Windows or hide deep in the system.",
     "cost": "Windows asks for the admin password when you install software.",
     "alternative": "If you decline: never approve an admin prompt you did not expect."},
    {"key": "backup", "can_apply": False,
     "on": lambda s: bool(s.get("file_history")),
     "name": "Your files are backed up (File History)",
     "stops": "Lets you get files back after ransomware, a stolen laptop or a wipe.",
     "cost": "Needs an external drive or cloud space.",
     "alternative": "Any backup works - an external drive you unplug afterwards is the safest."},
]
BY_KEY = {lock["key"]: lock for lock in LOCKS}


def collect():
    out = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                          "-File", os.path.join(HERE, "harden.ps1")], capture_output=True, timeout=120)
    return json.loads(out.stdout.decode("utf-8", "replace"))


def analyse(state):
    findings = []
    for lock in LOCKS:
        if lock["on"](state):
            findings.append((INFO, f"On: {lock['name']}", lock["stops"]))
        else:
            findings.append((MEDIUM, f"Off: {lock['name']}",
                             f"{lock['stops']} Cost: {lock['cost']} {lock['alternative']}"))
    if not state.get("defender_active"):
        findings.append((INFO, "Windows Defender is not the active antivirus",
                         "Several of these protections only work while Defender is active."))
    return findings


def result():
    state = collect()
    findings = analyse(state)
    off = sum(1 for f in findings if f[0] == MEDIUM)
    total = len(LOCKS)
    labels = {
        "warn": (f"{total - off} OF {total} LOCKS ON",
                 "Each lock that is off is a way in. They are listed with what they cost and the alternative."),
        "ok": ("LOCKED DOWN", "Every protection gotchu knows about is on. Keep Windows updated."),
    }
    locks = [{"key": k["key"], "name": k["name"], "stops": k["stops"], "cost": k["cost"],
              "alternative": k["alternative"], "on": bool(k["on"](state)), "can_apply": k["can_apply"],
              "can_undo": os.path.exists(os.path.join(JOURNAL, k["key"] + ".json"))} for k in LOCKS]
    return report.build(f"{state.get('edition', 'this PC')} (build {state.get('build', '?')})",
                        findings, labels, locks=locks)


def change(key, undo=False):
    """Turn one protection on (or put it back). Windows asks the user for permission.

    Returns (ok, message). The previous setting is journalled before the change.
    """
    lock = BY_KEY.get(key)
    if not lock or not lock["can_apply"]:
        return False, "gotchu cannot change that protection; turn it on in Windows Security."
    if undo and not os.path.exists(os.path.join(JOURNAL, key + ".json")):
        return False, "gotchu did not turn that on, so there is nothing to undo."
    os.makedirs(JOURNAL, exist_ok=True)
    result_file = os.path.join(JOURNAL, key + ".result")
    if os.path.exists(result_file):
        os.remove(result_file)

    args = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f'"{os.path.join(HERE, "harden_apply.ps1")}"',
            "-Lock", key, "-JournalDir", f'"{JOURNAL}"', "-AsrIds", ",".join(ASR_RULES)] + (["-Undo"] if undo else [])
    listed = ",".join("'" + a.replace("'", "''") + "'" for a in args)
    subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                    f"Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList {listed}"],
                   capture_output=True, timeout=300)

    if not os.path.exists(result_file):
        return False, "Nothing was changed: the Windows permission prompt was declined or closed."
    with open(result_file, encoding="utf-8-sig") as f:
        outcome = f.read().strip()
    os.remove(result_file)
    if outcome != "ok":
        return False, "Windows refused the change. " + outcome.removeprefix("error: ")
    now_on = lock["on"](collect())
    if undo:
        return True, "Put back the way it was."
    if not now_on:
        return False, "The change was sent but Windows still reports it as off. Another security product may control it."
    return True, "Turned on."
