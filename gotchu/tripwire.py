"""Tripwire: decoy wallet files that no honest program opens, and an alarm when one is read.

Info-stealers sweep the same list of wallet folders on every PC. gotchu plants fake ones (only
for apps that are not installed), asks Windows to record who reads them, and a small watcher
raises the alarm - and, if chosen, blocks that program from the internet.

It also watches the real stores that have a known owner (browser logins and sessions, Telegram,
Discord). A read by any other program is written down for review. That part does not raise an
alarm yet: first we measure how often honest programs do it.

Limits, stated plainly: the alarm fires for decoys only; the internet block applies to the
program that did the reading; malware that injects itself into the real browser looks like the owner.
"""
import json
import os
import shutil
import subprocess

from . import report
from .report import HIGH, INFO, MEDIUM

HERE = os.path.dirname(__file__)
LOCAL = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "gotchu")
STATE = os.path.join(LOCAL, "decoys.json")           # what gotchu planted, so it can remove exactly that
INSTALLED = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "gotchu")

# Fake wallets, by the folder the real app would use. Skipped when that folder already exists.
DECOYS = [
    (r"%APPDATA%\Electrum", r"wallets\default_wallet"),
    (r"%APPDATA%\Exodus", r"exodus.wallet\seed.seco"),
    (r"%APPDATA%\Bitcoin", r"wallets\wallet.dat"),
    (r"%APPDATA%\Ethereum", r"keystore\UTC--2024-03-11T09-14-02.118Z--5c1f0b7a9e3d4c6b8a2f1e0d9c8b7a6f5e4d3c2b"),
]


def plan(appdata, exists=os.path.exists):
    """Which decoys to plant: only where the real app is absent, so nothing real is ever touched."""
    out = []
    for root, file in DECOYS:
        root = root.replace("%APPDATA%", appdata)
        if not exists(root):
            out.append((root, os.path.join(root, file)))
    return out


CHROMIUM_FILES = ("Login Data", os.path.join("Network", "Cookies"), "Web Data")
FIREFOX_FILES = ("logins.json", "key4.db", "cookies.sqlite")


def guarded(env=None, secrets=None):
    """Real stores worth watching: only those with a known owner, so a read by anyone else means something."""
    from . import exposure   # imported here: exposure imports this module
    env = os.environ if env is None else env
    secrets = secrets or exposure.load_map()
    out = []
    for b in secrets["browsers"]:
        root = exposure.expand(b["root"], env)
        if not os.path.isdir(root):
            continue
        firefox = b["engine"] == "firefox"
        folders = [p.path for p in os.scandir(root) if p.is_dir()] + ([] if firefox else [root])
        for folder in folders:
            for rel in FIREFOX_FILES if firefox else CHROMIUM_FILES:
                path = os.path.join(folder, rel)
                if os.path.isfile(path):
                    out.append({"path": path, "dir": False, "name": f"{b['name']} ({os.path.basename(folder)}: {rel})",
                                "owners": b["owners"], "signer": b.get("signer", "")})
    for store in secrets["stores"]:
        path = exposure.expand(store["path"], env)
        if store.get("watch"):
            path = os.path.join(path, store["watch"])
        if store.get("owners") and os.path.exists(path):
            out.append({"path": path, "dir": os.path.isdir(path), "name": store["name"],
                        "owners": store["owners"], "signer": store.get("signer", "")})
    return out


def _state():
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"roots": [], "files": []}


def decoy_roots():
    return _state()["roots"]


def _plant():
    state = _state()
    if state["files"]:
        return state
    for root, file in plan(os.environ["APPDATA"]):
        os.makedirs(os.path.dirname(file))
        with open(file, "wb") as f:
            f.write(os.urandom(2048))   # meaningless bytes; there is no real wallet in it
        state["roots"].append(root)
        state["files"].append(file)
    os.makedirs(LOCAL, exist_ok=True)
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(state, f)
    return state


def _remove_decoys():
    for root in _state()["roots"]:
        shutil.rmtree(root, ignore_errors=True)
    if os.path.exists(STATE):
        os.remove(STATE)


def _elevated(action, cut=False):
    os.makedirs(LOCAL, exist_ok=True)
    result_file, plan_file = os.path.join(LOCAL, "tripwire.result"), os.path.join(LOCAL, "tripwire.plan")
    if os.path.exists(result_file):
        os.remove(result_file)
    with open(plan_file, "w", encoding="utf-8") as f:
        json.dump({"decoys": _state()["files"], "stores": guarded() if action == "on" else []}, f)
    args = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f'"{os.path.join(HERE, "tripwire_apply.ps1")}"',
            "-Action", action, "-Source", f'"{HERE}"', "-PlanFile", f'"{plan_file}"',
            "-ResultFile", f'"{result_file}"'] + (["-Cut"] if cut else [])
    listed = ",".join("'" + a.replace("'", "''") + "'" for a in args)
    subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                    f"Start-Process powershell.exe -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList {listed}"],
                   capture_output=True, timeout=300)
    os.remove(plan_file)
    if not os.path.exists(result_file):
        return False, "Nothing was changed: the Windows permission prompt was declined or closed."
    with open(result_file, encoding="utf-8-sig") as f:
        outcome = f.read().strip()
    os.remove(result_file)
    return (True, "") if outcome == "ok" else (False, "Windows refused the change. " + outcome.removeprefix("error: "))


def status():
    out = {"on": False, "cut": False, "decoys": [], "stores": [], "alerts": [], "sightings": []}
    try:
        with open(os.path.join(INSTALLED, "tripwire.json"), encoding="utf-8-sig") as f:
            cfg = json.load(f)
        out.update(on=True, cut=bool(cfg.get("cut")), decoys=cfg.get("decoys") or [], stores=cfg.get("stores") or [])
    except (OSError, ValueError):
        return out
    for kind in ("alerts", "sightings"):
        try:
            with open(os.path.join(INSTALLED, kind + ".jsonl"), encoding="utf-8-sig") as f:
                out[kind] = [json.loads(line) for line in f if line.strip()][-20:]
        except (OSError, ValueError):
            continue    # no file means nothing has happened yet
    return out


def change(action, cut=False):
    """action: 'on', 'off' or 'restore' (lift internet blocks). Returns (ok, message)."""
    if action == "on":
        had_decoys = bool(_state()["files"])
        if not _plant()["files"]:
            return False, "No decoys could be planted: every wallet app gotchu imitates is already installed."
        ok, message = _elevated("on", cut)
        if not ok:
            if not had_decoys:
                _remove_decoys()
            return False, message
        return True, "Tripwire is on" + (", and a program that trips it loses its internet." if cut else ", alert only.")
    ok, message = _elevated(action)
    if not ok:
        return False, message
    if action == "off":
        _remove_decoys()
        return True, "Tripwire is off. Decoys removed and Windows' setting put back."
    return True, "Internet blocks lifted and the alarm cleared."


def analyse(state):
    if not state["on"]:
        return [(MEDIUM, "The tripwire is off",
                 "Turn it on to plant decoy wallet files and be warned the moment a program reads one.")]
    findings = [(HIGH, f"Alarm at {a['time'].replace('T', ' ')}: a program read a decoy",
                 f"Program: {a['program']}." + (" gotchu blocked it from the internet." if a.get("cut") else "")
                 + " If this was not you, run a scan and change your passwords from another device.")
                for a in reversed(state["alerts"])]
    findings += [(MEDIUM, f"{os.path.basename(s['program'])} read {s['store']}",
                  f"At {s['time'].replace('T', ' ')}. Program: {s['program']}. This is not the program that owns that "
                  "data. A backup or security tool can be harmless; anything you do not recognise is worth a scan.")
                 for s in reversed(state["sightings"])]
    mode = "A program that trips a decoy loses its internet." if state["cut"] else "Alert only."
    findings.append((INFO, f"The tripwire is on: {len(state['decoys'])} decoys, {len(state['stores'])} real stores watched",
                     mode + " Reads of real stores by other programs are listed here, without an alarm for now."))
    return findings


def result():
    state = status()
    review = ("PROGRAMS TO REVIEW", "Other programs read your browser or chat logins. Check that you recognise each one.")
    labels = {
        "danger": ("THE TRIPWIRE WAS TRIPPED", "Something read a decoy that no honest program touches."),
        "warn": review if state["on"] else ("TRIPWIRE OFF", "Nothing is watching for a thief sweeping this PC."),
        "ok": ("TRIPWIRE SET", "Quiet so far. You will see a warning window the moment a decoy is read."),
    }
    return report.build("decoys and login stores on this PC", analyse(state), labels)
