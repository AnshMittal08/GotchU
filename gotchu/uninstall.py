"""Remove GotchU from this PC: everything it set up is put back the way it was. The vault is kept.

Each step uses the same code as switching that piece off by hand, so nothing here changes Windows in a new way.
It can be run again: a step already done is skipped, and it stops at the first one that does not finish.
"""
import os
import shutil

from . import admin, desktop, harden, tripwire, vault

LAST_STEP = "pip uninstall gotchu"


def plan():
    """What removing GotchU will do on this PC: [{"key", "text", "admin"}], in the order it is done."""
    trip = tripwire.status()
    locks = [k for k in harden.LOCKS if k["can_apply"] and harden._saved(k["key"])]
    steps = []
    needs_admin = trip["on"] or locks
    if needs_admin and admin.state() == "different":
        steps.append({"key": "helpers", "admin": True,
                      "text": "Bring GotchU's administrator helpers up to date, so they can put things back"})
    if trip["on"]:
        steps.append({"key": "tripwire", "admin": True,
                      "text": "Turn off the theft alarm: remove the decoy files and the watcher, lift any internet "
                              "block, and put Windows' file-audit setting back"})
    elif tripwire.load_state(tripwire.STATE)["files"]:
        steps.append({"key": "decoys", "admin": False, "text": "Remove the decoy files left from an earlier switch-on"})
    for k in locks:
        steps.append({"key": "lock:" + k["key"], "admin": True,
                      "text": f"Put back the Windows setting GotchU changed: {k['name']}"})
    if os.path.isdir(admin.INSTALLED):
        steps.append({"key": "remove_helpers", "admin": True, "text": f"Remove {admin.INSTALLED}"})
    if desktop.menu_on() or desktop.shortcut_on() or _signin_on():
        steps.append({"key": "desktop", "admin": False,
                      "text": "Remove the right-click entry, the Start-menu and desktop shortcuts, and the check at sign-in"})
    if _local_files():
        steps.append({"key": "local", "admin": False, "text": f"Delete GotchU's settings and history in {tripwire.LOCAL}"})
    return steps


def kept():
    """What is deliberately left, in words for the user."""
    if vault.exists(vault.FOLDER):
        return (f"Your vault is kept in {vault.FOLDER}: it holds your encrypted files. To open it later, install "
                "GotchU again. Delete that folder yourself only once you have taken out everything you need.")
    return ""


def run():
    """Do every step of plan(). Returns (ok, done: [text], message)."""
    done = []
    for step in plan():
        ok, message = _do(step["key"])
        if not ok:
            return False, done, f"Stopped at: {step['text']}. {message} Run the removal again to finish."
        done.append(step["text"])
    return True, done, f"GotchU has put back everything it set up. Last step, in a terminal: {LAST_STEP}"


def _do(key):
    if key == "helpers":
        return admin.install()
    if key == "tripwire":
        return tripwire.change("off")
    if key == "decoys":
        left = tripwire._remove_decoys(tripwire.STATE)
        return True, tripwire._note([], left)
    if key.startswith("lock:"):
        return harden.change(key[5:], undo=True)
    if key == "remove_helpers":
        return admin.remove()
    if key == "desktop":
        desktop.set_signin(False)
        ok = desktop.set_menu(False) and desktop.set_shortcut(False)
        return ok, "" if ok else "Windows would not remove the right-click entry or the shortcuts."
    if key == "local":
        for path in _local_files():
            try:
                shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
            except OSError:
                return False, f"Windows would not delete {path}; close GotchU's window and try again."
        return True, ""
    return False, "Unknown step."


def _local_files():
    """Everything in GotchU's own folder except the vault."""
    try:
        names = os.listdir(tripwire.LOCAL)
    except OSError:
        return []
    keep = os.path.normcase(os.path.abspath(vault.FOLDER))
    return [os.path.join(tripwire.LOCAL, n) for n in names
            if os.path.normcase(os.path.abspath(os.path.join(tripwire.LOCAL, n))) != keep]


def _signin_on():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, desktop.RUN_KEY) as key:
            winreg.QueryValueEx(key, "GotchU")
        return True
    except OSError:
        return False
