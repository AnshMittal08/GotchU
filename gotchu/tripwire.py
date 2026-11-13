"""Tripwire: decoy wallet files that no honest program opens, and an alarm when one is read.

Info-stealers sweep the same list of wallet folders on every PC. gotchu plants fake ones (only
for apps that are not installed), asks Windows to record who reads them, and a small watcher
raises the alarm - and, if chosen, blocks that program from the internet.

Limits, stated plainly: it catches a thief that sweeps for wallets, not one that takes only
browser data; and the internet block applies to the program that did the reading.
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
    result_file, decoy_file = os.path.join(LOCAL, "tripwire.result"), os.path.join(LOCAL, "tripwire.decoys")
    if os.path.exists(result_file):
        os.remove(result_file)
    with open(decoy_file, "w", encoding="utf-8") as f:
        f.write("\n".join(_state()["files"]))
    args = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f'"{os.path.join(HERE, "tripwire_apply.ps1")}"',
            "-Action", action, "-Source", f'"{HERE}"', "-DecoyFile", f'"{decoy_file}"',
            "-ResultFile", f'"{result_file}"'] + (["-Cut"] if cut else [])
    listed = ",".join("'" + a.replace("'", "''") + "'" for a in args)
    subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                    f"Start-Process powershell.exe -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList {listed}"],
                   capture_output=True, timeout=300)
    os.remove(decoy_file)
    if not os.path.exists(result_file):
        return False, "Nothing was changed: the Windows permission prompt was declined or closed."
    with open(result_file, encoding="utf-8-sig") as f:
        outcome = f.read().strip()
    os.remove(result_file)
    return (True, "") if outcome == "ok" else (False, "Windows refused the change. " + outcome.removeprefix("error: "))


def status():
    out = {"on": False, "cut": False, "decoys": [], "alerts": []}
    try:
        with open(os.path.join(INSTALLED, "tripwire.json"), encoding="utf-8-sig") as f:
            cfg = json.load(f)
        out.update(on=True, cut=bool(cfg.get("cut")), decoys=cfg.get("decoys") or [])
        with open(os.path.join(INSTALLED, "alerts.jsonl"), encoding="utf-8-sig") as f:
            out["alerts"] = [json.loads(line) for line in f if line.strip()][-10:]
    except (OSError, ValueError):
        pass
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
    mode = "A program that trips it loses its internet." if state["cut"] else "Alert only."
    findings.append((INFO, f"The tripwire is on, watching {len(state['decoys'])} decoys", mode))
    return findings


def result():
    labels = {
        "danger": ("THE TRIPWIRE WAS TRIPPED", "Something read a decoy that no honest program touches."),
        "warn": ("TRIPWIRE OFF", "Nothing is watching for a thief sweeping this PC."),
        "ok": ("TRIPWIRE SET", "Quiet so far. You will see a warning window the moment a decoy is read."),
    }
    return report.build("decoy files on this PC", analyse(status()), labels)
