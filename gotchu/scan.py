"""Scan: look for signs that this PC is infected right now. Read-only.

`collect()` takes a snapshot of the PC; `analyse()` is pure and judges a snapshot,
so the rules can be tested with made-up snapshots.
"""
import json
import os
import re

from . import check, exposure, report
from .report import HIGH, INFO, MEDIUM

# Windows programs that always live in System32 / SysWOW64 (explorer.exe: C:\Windows).
SYSTEM_NAMES = {"svchost.exe", "dllhost.exe", "rundll32.exe", "conhost.exe", "csrss.exe", "lsass.exe",
                "services.exe", "winlogon.exe", "smss.exe", "taskhostw.exe", "runtimebroker.exe",
                "spoolsv.exe", "wininit.exe", "explorer.exe", "sihost.exe", "ctfmon.exe"}
SYSTEM_DIRS = re.compile(r"(?i)^[a-z]:\\windows\\(system32|syswow64|explorer\.exe$|winsxs|immersivecontrolpanel)")
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
                "rundll32.exe", "cmd.exe"}
DOWNLOAD_AND_RUN = re.compile(r"(?i)downloadstring|downloadfile|frombase64string|start-bitstransfer|"
                              r"\b(iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod)\b.*\|\s*(iex|invoke-expression)|"
                              r"mshta\s+(https?:|javascript:|vbscript:)|-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{60,}")
HIDDEN_WINDOW = re.compile(r"(?i)-w(in|indowstyle)?\s+h(idden)?\b")
DROP_FOLDER = re.compile(r"(?i)\\tmp-\d{5}-[a-z0-9]{12}\\")
TEMP = re.compile(r"(?i)\\appdata\\local\\temp\\|\\windows\\temp\\")
USER_WRITABLE = re.compile(r"(?i)\\appdata\\|\\users\\public\\|\\downloads\\|\\windows\\temp\\")
# Names that Windows and Docker put in the hosts file themselves.
OWN_HOSTS = re.compile(r"(?i)^(localhost|.*\.docker\.internal|.*\.localhost)$")
SECURITY_SITES = re.compile(r"(?i)microsoft|windowsupdate|defender|virustotal|kaspersky|avast|avg\.|bitdefender|malwarebytes|"
                            r"eset\.|norton|mcafee|sophos|trendmicro")
# How Chrome and its relatives record where an extension came from: 4 is a folder on this PC, 8 the command line.
LOADED_FROM_FOLDER = {4, 8}
STARTUP_SCRIPTS = {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".pif", ".scr"}

LABELS = {
    "danger": ("SIGNS OF INFECTION", "Something on this PC behaves the way malware does. Disconnect from the "
               "internet and deal with the items marked HIGH before you sign in to anything."),
    "warn": ("WORTH A LOOK", "Nothing clearly malicious, but some things deserve a second look."),
    "ok": ("NO SIGNS FOUND", "None of the known signs of infection are present. This is not a guarantee - "
           "some malware hides from checks like these."),
}


def collect():
    return report.powershell_json(os.path.join(os.path.dirname(__file__), "collect.ps1"), "the scan")


def analyse(snap):
    """Return (severity, title, detail) findings for a snapshot from collect()."""
    findings = []

    def add(sev, title, detail):
        findings.append((sev, title, detail))

    for p in snap.get("processes", []):
        name, path, cmd = (p.get("name") or "").lower(), p.get("path") or "", p.get("cmd") or ""
        tag = f"{p.get('name')} (process {p.get('pid')})"

        if name in SYSTEM_NAMES and path and not SYSTEM_DIRS.match(path):
            add(HIGH, f"Fake Windows program: {tag}",
                f"It uses a Windows system name but runs from {path}. The real one never lives there.")
        elif name == "dllhost.exe" and cmd and "/processid" not in cmd.lower():
            add(HIGH, f"Hijacked Windows helper: {tag}",
                "dllhost.exe is always started with a /Processid argument. Without one, another program "
                "started it to hide its own code inside a trusted Windows process.")

        if DROP_FOLDER.search(path):
            add(HIGH, f"Program running from a malware-style drop folder: {tag}",
                f"{path} - a randomly named folder in Temp, the pattern used by loader malware.")
        elif TEMP.search(path):
            add(MEDIUM, f"Program running from the Temp folder: {tag}",
                f"{path} - installers do this briefly; anything that stays running from Temp is unusual.")

        if name in SCRIPT_HOSTS and DOWNLOAD_AND_RUN.search(cmd):
            add(HIGH, f"Command that downloads and runs code: {tag}", cmd[:300])
        elif name in {"powershell.exe", "pwsh.exe"} and HIDDEN_WINDOW.search(cmd):
            add(MEDIUM, f"PowerShell running with a hidden window: {tag}", cmd[:300])

    for t in snap.get("tasks", []):
        exe = t.get("exe") or ""
        if not t.get("enabled", True) or ":\\" not in exe or not USER_WRITABLE.search(exe):
            continue
        if t.get("hidden") or t.get("highest"):
            traits = " and ".join(x for x, on in (("hidden", t.get("hidden")),
                                                  ("runs with admin rights", t.get("highest"))) if on)
            gone = "" if t.get("exists") else " The program is missing now, but the task still fires at every start."
            add(HIGH, f"Suspicious auto-start task: {t.get('name')}",
                f"It is {traits} and starts {exe} from a folder any program can write to.{gone}")
        elif not t.get("exists"):
            add(INFO, f"Leftover auto-start task: {t.get('name')}", f"It points to {exe}, which no longer exists.")

    for r in snap.get("run", []):
        value = r.get("value") or ""
        if TEMP.search(value) or DROP_FOLDER.search(value):
            add(HIGH, f"Program set to start with Windows from Temp: {r.get('name')}", value[:300])

    # The Start-up folder: installers put a shortcut to their program there. Malware puts itself, a script,
    # or a shortcut to a script host there, to come back after every restart.
    for s in snap.get("startup", []):
        name, path = s.get("name") or "", s.get("path") or ""
        ext = os.path.splitext(name)[1].lower()
        target, args = s.get("target") or "", s.get("args") or ""
        runs = os.path.basename(target).lower()
        what = f"{target} {args}".strip()[:300]
        if ext == ".lnk":
            if TEMP.search(target) or DROP_FOLDER.search(target):
                add(HIGH, f"Start-up shortcut runs a program from Temp: {name}", what)
            elif runs in SCRIPT_HOSTS and DOWNLOAD_AND_RUN.search(args):
                add(HIGH, f"Start-up shortcut downloads and runs code: {name}", what)
            elif runs in SCRIPT_HOSTS or os.path.splitext(runs)[1] in STARTUP_SCRIPTS:
                add(MEDIUM, f"Start-up shortcut runs a script: {name}",
                    f"{what} - it runs every time you sign in. A few tools do this; malware does it to survive a restart.")
        elif ext in STARTUP_SCRIPTS:
            add(MEDIUM, f"Script in the Start-up folder: {name}",
                f"{path} runs every time you sign in. If you did not put it there, do not open it: scan with your "
                "antivirus and remove it.")
        elif ext in {".exe", ".com", ".dll"}:
            add(MEDIUM, f"Program placed in the Start-up folder: {name}",
                f"{path} - installers add a shortcut here, not the program itself. If you do not recognise it, "
                "scan with your antivirus and remove it.")

    for s in snap.get("services", []):
        path = s.get("path") or ""
        if s.get("start") == "Disabled" or not (USER_WRITABLE.search(path) or DROP_FOLDER.search(path)):
            continue
        sev = HIGH if TEMP.search(path) or DROP_FOLDER.search(path) else MEDIUM
        add(sev, f"Windows service runs from a folder any program can write to: {s.get('title') or s.get('name')}",
            f"{path[:300]} - a service starts with Windows and runs with full rights. Real ones live in Program Files "
            "or the Windows folder; malware installs one to come back after every restart.")

    redirected = []
    for line in snap.get("hosts", []):
        address, *names = line.split()
        redirected += [(n, address) for n in names if not OWN_HOSTS.match(n)]
    blocked = [n for n, _ in redirected if SECURITY_SITES.search(n)]
    if blocked:
        add(HIGH, f"The hosts file cuts this PC off from {len(blocked)} security or update sites",
            "Malware does this so antivirus and Windows cannot update: " + ", ".join(blocked[:8])
            + ". Open C:\\Windows\\System32\\drivers\\etc\\hosts in Notepad as administrator and remove those lines.")
    elif redirected:
        add(MEDIUM, f"The hosts file sends {len(redirected)} website names somewhere else",
            "Fine if you, an ad blocker or a work tool added them; otherwise a site you type can lead to a fake copy: "
            + ", ".join(f"{n} -> {a}" for n, a in redirected[:6]) + (" ..." if len(redirected) > 6 else ""))

    proxy = snap.get("proxy") or {}
    if proxy.get("enabled") and proxy.get("server"):
        add(MEDIUM, "Web traffic is routed through a proxy",
            f"{proxy['server']} - fine if you or your workplace set it; otherwise something can read your browsing.")
    if proxy.get("pac"):
        add(MEDIUM, "Web traffic follows an automatic proxy script", proxy["pac"])

    defender = snap.get("defender") or {}
    if defender.get("known") and not defender.get("realtime"):
        add(MEDIUM, "Windows Defender real-time protection is off",
            "Fine if another antivirus is running; otherwise turn it back on - malware often switches it off.")

    forced = [e for e in snap.get("forced_extensions", []) if e]
    if forced:
        add(MEDIUM, f"{len(forced)} browser extensions are force-installed by policy",
            "Normal on a work PC. On a personal PC, adware does this so you cannot remove them: " + ", ".join(forced)[:300])
    return findings


def _sideload_findings(snap):
    """Inspect the folders of programs running from user-writable places for planted DLLs."""
    findings, seen = [], set()
    for p in snap.get("processes", []):
        path = p.get("path") or ""
        folder = os.path.dirname(path)
        if not USER_WRITABLE.search(path) or folder.lower() in seen or not os.path.isdir(folder):
            continue
        seen.add(folder.lower())
        try:
            if len(os.listdir(folder)) > 300:
                continue
            # A planted DLL sits beside the program, so the folder itself is enough - not every subfolder.
            findings += [f for f in check.analyse(folder, recursive=False) if f[0] == HIGH and "untrusted DLL" in f[1]]
        except OSError:
            pass
    return [(s, f"Running now: {t}", d) for s, t, d in findings]


def extension_findings(env=None, secrets=None):
    """Browser extensions loaded from a folder on this PC instead of the browser's store."""
    env = os.environ if env is None else env
    secrets = secrets or exposure.load_map()
    findings = []
    for b in secrets["browsers"]:
        root = exposure.expand(b["root"], env)
        if b["engine"] != "chromium" or not os.path.isdir(root):
            continue
        for profile in [root] + [p.path for p in os.scandir(root) if p.is_dir()]:
            seen = set()
            for name in ("Secure Preferences", "Preferences"):
                try:
                    with open(os.path.join(profile, name), encoding="utf-8") as f:
                        settings = json.load(f).get("extensions", {}).get("settings", {})
                except (OSError, ValueError, AttributeError):
                    continue
                for ext_id, ext in settings.items():
                    if not isinstance(ext, dict) or ext.get("location") not in LOADED_FROM_FOLDER or ext_id in seen:
                        continue
                    seen.add(ext_id)
                    label = (ext.get("manifest") or {}).get("name") or ext_id
                    findings.append((MEDIUM, f"Extension loaded from a folder, not the store: {label} in {b['name']}",
                                     f"{ext.get('path') or ext_id} - developers do this on purpose. If you did not, remove it "
                                     "on the browser's extensions page: malware adds extensions this way to read the pages "
                                     "you visit and the logins you type."))
    return findings


def result():
    snap = collect()
    findings = analyse(snap) + _sideload_findings(snap) + extension_findings()
    findings.append((INFO, f"Looked at {len(snap.get('processes', []))} running programs, "
                           f"{len(snap.get('tasks', []))} auto-start tasks, "
                           f"{len(snap.get('services', []))} services, "
                           f"{len(snap.get('run', []))} start-up entries and "
                           f"{len(snap.get('startup', []))} items in the Start-up folders", "Nothing was changed on this PC."))
    return report.build("this PC", findings, LABELS)
