"""Tripwire: decoy files that no honest program opens, and an alarm when one is read.

Info-stealers sweep the same list of wallet and browser folders on every PC. gotchu plants fake ones
(only for apps that are not installed), asks Windows to record who reads them, and a small watcher
raises the alarm - and, if chosen, blocks that program from the internet.

It also watches the real stores that have a known owner (browser logins and sessions, Telegram,
Discord). A read by any other program is written down for review. That part does not raise an
alarm yet: first we measure how often honest programs do it.

Limits, stated plainly: the alarm fires for decoys only; the internet block applies to the
program that did the reading; malware that injects itself into the real browser looks like the owner.
"""
import hashlib
import json
import os
import time

from . import admin, report
from .report import HIGH, INFO, MEDIUM

LOCAL = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "gotchu")
STATE = os.path.join(LOCAL, "decoys.json")           # what gotchu planted, so it can remove exactly that
INSTALLED = admin.INSTALLED                          # watcher, its settings and its logs: admin-only
DECOY_SIZE = 2048

HEARTBEAT_SECONDS = 180                              # the watcher marks a file every 30 seconds while it runs

# Fake wallets and fake browser logins, by the folder the real app would use. Skipped when that folder
# already exists. The browser ones sit in a profile name ("Profile 7") that a thief sweeping every profile
# reads, but that the real browser, installed later, would never open or write to.
DECOYS = [
    (r"%APPDATA%\Electrum", r"wallets\default_wallet"),
    (r"%APPDATA%\Exodus", r"exodus.wallet\seed.seco"),
    (r"%APPDATA%\Bitcoin", r"wallets\wallet.dat"),
    (r"%APPDATA%\Ethereum", r"keystore\UTC--2024-03-11T09-14-02.118Z--5c1f0b7a9e3d4c6b8a2f1e0d9c8b7a6f5e4d3c2b"),
    (r"%LOCALAPPDATA%\BraveSoftware", r"Brave-Browser\User Data\Profile 7\Login Data"),
    (r"%LOCALAPPDATA%\Vivaldi", r"User Data\Profile 7\Login Data"),
]


def plan(appdata, exists=os.path.exists):
    """Which decoys to plant: only where the real app is absent, so nothing real is ever touched."""
    out = []
    local = os.path.join(os.path.dirname(appdata.rstrip("\\/")), "Local")   # AppData\Local sits beside AppData\Roaming
    for root, file in DECOYS:
        root = root.replace("%LOCALAPPDATA%", local).replace("%APPDATA%", appdata)
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
    planted = load_state()
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
                if os.path.isfile(path) and not only_decoys(path, planted):   # a decoy is watched as a decoy
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


def load_state(path=STATE):
    """What gotchu planted: decoy folders, decoy files and a fingerprint of each file."""
    try:
        with open(path, encoding="utf-8") as f:
            saved = json.load(f)
    except (OSError, ValueError):
        saved = {}
    return {"roots": saved.get("roots", []), "files": saved.get("files", []), "hashes": saved.get("hashes", {})}


def _within(path, folder):
    path, folder = os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(folder))
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def _ours(file, state):
    """Is this still the decoy gotchu planted, unchanged? A wallet app installed since may have written over it."""
    want = state["hashes"].get(file)
    try:
        if want:
            with open(file, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest() == want
        return os.path.getsize(file) == DECOY_SIZE   # planted by a version that kept no fingerprint
    except OSError:
        return False


def _foreign(folder, state):
    """The first file under folder that is not one of gotchu's unchanged decoys, or None."""
    planted = {os.path.normcase(f): f for f in state["files"]}
    for root, _, files in os.walk(folder):
        for name in files:
            path = os.path.join(root, name)
            original = planted.get(os.path.normcase(path))
            if original is None or not _ours(original, state):
                return path
    return None


def only_decoys(path, state=None):
    """True when path holds nothing but gotchu's own decoys, so it is not a real wallet."""
    state = load_state() if state is None else state
    if not any(_within(path, root) for root in state["roots"]):
        return False
    if os.path.isdir(path):
        return _foreign(path, state) is None
    original = next((f for f in state["files"] if os.path.normcase(f) == os.path.normcase(path)), None)
    return original is not None and _ours(original, state)


def moved_in(state=None):
    """Decoy folders that another program, most likely the real wallet app, now uses too."""
    state = load_state() if state is None else state
    return [root for root in state["roots"] if os.path.isdir(root) and _foreign(root, state)]


def _clear(root, state):
    """Delete gotchu's decoys under root, then the folders it made for them if they are now empty.

    Nothing else is ever deleted: a wallet app installed since may keep real data in the same folder.
    Returns the decoy files that had to be left in place.
    """
    alone = _foreign(root, state) is None
    left = []
    for file in [f for f in state["files"] if _within(f, root) and os.path.exists(f)]:
        # Without a fingerprint, the file is only deleted when nothing else has moved into its folder.
        if not _ours(file, state) or (file not in state["hashes"] and not alone):
            left.append(file)
            continue
        os.remove(file)
        folder = os.path.dirname(file)
        while _within(folder, root):
            try:
                os.rmdir(folder)    # succeeds only on an empty folder
            except OSError:
                break
            folder = os.path.dirname(folder)
    return left


def _drop(state, root):
    gone = [f for f in state["files"] if _within(f, root)]
    state["roots"] = [r for r in state["roots"] if r != root]
    state["files"] = [f for f in state["files"] if f not in gone]
    for f in gone:
        state["hashes"].pop(f, None)


def _plant(appdata=None, path=STATE):
    """Retire decoys whose folder a real app now uses, then plant any that are missing.

    Returns (state, retired folders, decoy files left in place).
    """
    state = load_state(path)
    retired, left = [], []
    for root in list(state["roots"]):
        if os.path.isdir(root) and _foreign(root, state):
            left += _clear(root, state)
            retired.append(root)
        if root in retired or not os.path.isdir(root):
            _drop(state, root)
    for root, file in plan(appdata or os.environ["APPDATA"]):
        os.makedirs(os.path.dirname(file))
        data = os.urandom(DECOY_SIZE)   # meaningless bytes; there is no real wallet in it
        with open(file, "wb") as f:
            f.write(data)
        state["roots"].append(root)
        state["files"].append(file)
        state["hashes"][file] = hashlib.sha256(data).hexdigest()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f)
    return state, retired, left


def _remove_decoys(path=STATE):
    """Remove every decoy gotchu planted. Returns the decoy files that had to be left in place."""
    state = load_state(path)
    left = []
    for root in state["roots"]:
        if os.path.isdir(root):
            left += _clear(root, state)
    if os.path.exists(path):
        os.remove(path)
    return left


def _note(retired, left):
    out = ""
    if retired:
        out += " Retired the decoy in " + ", ".join(retired) + ": a wallet app now uses that folder."
    if left:
        out += (" Left in place because a wallet app now uses the folder or has changed the file: " + ", ".join(left)
                + ". Delete these yourself only if you are sure they are not real wallet files.")
    return out


def _elevated(action, cut=False):
    args = ["-Action", action] + (["-Cut"] if cut else [])
    plan_file = os.path.join(LOCAL, "tripwire.plan")
    if action == "on":
        state = load_state()
        from . import exposure
        readers = exposure.load_map().get("known_readers", [])
        data = json.dumps({"decoys": state["files"], "roots": state["roots"], "stores": guarded(),
                           "readers": readers}).encode("utf-8")
        os.makedirs(LOCAL, exist_ok=True)
        with open(plan_file, "wb") as f:
            f.write(data)
        # Any program can change that folder, so the helper uses the plan only if it is exactly these bytes.
        args += ["-PlanFile", f'"{plan_file}"', "-PlanHash", hashlib.sha256(data).hexdigest()]
    try:
        return admin.run("tripwire_apply.ps1", args)
    finally:
        if os.path.exists(plan_file):
            os.remove(plan_file)


def status():
    out = {"on": False, "cut": False, "decoys": [], "stores": [], "alerts": [], "sightings": []}
    try:
        with open(os.path.join(INSTALLED, "tripwire.json"), encoding="utf-8-sig") as f:
            cfg = json.load(f)
        out.update(on=True, cut=bool(cfg.get("cut")), decoys=cfg.get("decoys") or [], stores=cfg.get("stores") or [])
    except (OSError, ValueError):
        return out
    out["moved_in"] = moved_in()
    try:    # is the watcher alive? It marks this file while it runs.
        out["watching"] = time.time() - os.path.getmtime(os.path.join(INSTALLED, "heartbeat")) < HEARTBEAT_SECONDS
    except OSError:
        out["watching"] = False
    for kind, keep in (("alerts", 20), ("sightings", 500)):
        try:
            with open(os.path.join(INSTALLED, kind + ".jsonl"), encoding="utf-8-sig") as f:
                out[kind] = [json.loads(line) for line in f if line.strip()][-keep:]
        except (OSError, ValueError):
            continue    # no file means nothing has happened yet
    return out


def change(action, cut=False):
    """action: 'on', 'off' or 'restore' (lift internet blocks). Returns (ok, message)."""
    if action == "on":
        had_decoys = bool(load_state()["files"])
        state, retired, left = _plant()
        if not state["files"]:
            return False, ("No decoys could be planted: every wallet app gotchu imitates is already installed."
                           + _note(retired, left))
        ok, message = _elevated("on", cut)
        if not ok:
            if not had_decoys:
                _remove_decoys()
            return False, message
        return True, ("Tripwire is on" + (", and a program that trips it loses its internet." if cut else ", alert only.")
                      + _note(retired, left))
    ok, message = _elevated(action)
    if not ok:
        return False, message
    if action == "off":
        left = _remove_decoys()
        return True, "Tripwire is off. Decoys removed and Windows' setting put back." + _note([], left)
    return True, "Internet blocks lifted and the alarm cleared."


def _sightings(sightings):
    """Reads listed for review, newest first: one line per program and thing read, however often it happened."""
    groups = {}
    for s in sightings:
        what = "decoy" if s.get("kind") == "decoy" else s["store"].split(" (")[0]   # "Google Chrome (Profile 1: Cookies)"
        key = (s["program"], what, s.get("reason"))
        group = groups.setdefault(key, {**s, "count": 0})
        group["count"] += 1
        group.update(time=s["time"], signed=s.get("signed", group.get("signed")), known=s.get("known", group.get("known")))
        groups[key] = groups.pop(key)   # most recent last
    return [_sighting(g) for g in reversed(groups.values())]


def _sighting(s):
    """One group of reads that is listed for review rather than alarmed."""
    often = f" {s['count']} times" if s.get("count", 1) > 1 else ""
    head = f"{'Last at' if often else 'At'} {s['time'].replace('T', ' ')}. Program: {s['program']}."
    if s.get("kind") != "decoy":
        name, store = os.path.basename(s["program"]), s["store"].split(" (")[0]
        if s.get("known"):
            return (INFO, f"{name} read {store}{often}",
                    f"{head} Browsers do this when they offer to bring your data over from another browser. "
                    "It is signed by its maker and installed in Program Files.")
        if s.get("signed") is False:
            return (HIGH, f"An unsigned program read {store}{often}: {name}",
                    f"{head} It is not the program that owns that data, and no publisher has signed it. That is what a "
                    "password thief looks like. If you do not recognise it, disconnect from the internet and run gotchu scan.")
        return (MEDIUM, f"{name} read {store}{often}",
                f"{head} This is not the program that owns that data. A backup or security tool can be harmless; "
                "anything you do not recognise is worth a scan.")
    if s.get("reason") == "moved_in":
        why = ("The decoy's folder now also holds another program's files, so the real wallet app was probably "
               "installed there since. Run gotchu tripwire --on to retire the decoy.")
    else:
        why = ("It is installed in Program Files and signed by its maker, so it was listed instead of raising the "
               "alarm or losing its internet: antivirus and backup tools read every file.")
    return (MEDIUM, f"{os.path.basename(s['program'])} read a decoy file{often}",
            f"{head} {why} If you do not recognise it, run a scan.")


def analyse(state):
    if not state["on"]:
        return [(MEDIUM, "The tripwire is off",
                 "Turn it on to plant decoy files and be warned the moment a program reads one.")]
    findings = [(HIGH, f"Alarm at {a['time'].replace('T', ' ')}: a program read a decoy",
                 f"Program: {a['program']}." + (" gotchu blocked it from the internet." if a.get("cut") else "")
                 + " If this was not you, run a scan and change your passwords from another device.")
                for a in reversed(state["alerts"])]
    if not state.get("watching", True):
        findings.append((MEDIUM, "The tripwire is switched on, but its watcher is not running",
                         "Nothing is watching the decoys right now, so a thief would not raise the alarm. Run gotchu "
                         "tripwire --on to start it again. If you have just updated gotchu, run gotchu setup first."))
    findings += [(MEDIUM, f"A wallet app now uses a decoy folder: {root}",
                  "The decoy there is no longer a reliable trap, and the real app may trip it. Run gotchu tripwire --on "
                  "to retire it: gotchu deletes only its own decoy file, never the app's data.")
                 for root in state.get("moved_in", [])]
    findings += _sightings(state["sightings"])
    mode = "A program that trips a decoy loses its internet." if state["cut"] else "Alert only."
    findings.append((INFO, f"The tripwire is on: {len(state['decoys'])} decoys, {len(state['stores'])} real stores watched",
                     mode + " Reads of real stores by other programs are listed here, without an alarm for now."))
    return findings


def result():
    state = status()
    review = ("WORTH A LOOK", "Each item below says what was seen and what to do: programs other than the owner "
              "that read your logins or a decoy, and decoys that need retiring.")
    tripped = ("THE TRIPWIRE WAS TRIPPED", "Something read a decoy that no honest program touches.")
    unsigned = ("A PROGRAM TO CHECK NOW", "An unsigned program read your saved logins. It is listed first below.")
    labels = {
        "danger": tripped if state["alerts"] else unsigned,
        "warn": review if state["on"] else ("TRIPWIRE OFF", "Nothing is watching for a thief sweeping this PC."),
        "ok": ("TRIPWIRE SET", "Quiet so far. You will see a warning window the moment a decoy is read."),
    }
    return report.build("decoys and login stores on this PC", analyse(state), labels)
