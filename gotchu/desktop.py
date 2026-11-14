"""What makes gotchu an app instead of a command: its own window, a Start-menu shortcut, a right-click
entry in File Explorer, and a check at sign-in for an alarm nobody answered.

Everything here is for the current user only (no administrator rights) and each piece can be removed again.
"""
import json
import os
import subprocess
import sys
import time
import winreg

from . import report

HERE = os.path.dirname(__file__)
ICON = os.path.join(HERE, "gotchu.ico")
LOCAL = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "gotchu")
STATE = os.path.join(LOCAL, "app.json")              # small things the window remembers between runs
MENU_KEYS = (r"Software\Classes\*\shell\GotchU", r"Software\Classes\Directory\shell\GotchU")
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
MENU_TEXT = "Check with GotchU"


def pythonw():
    """Python without a console window, from the same installation that is running now."""
    exe = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return exe if os.path.isfile(exe) else sys.executable


def command(*extra):
    return " ".join([f'"{pythonw()}"', "-m", "gotchu", "app", *extra])


# ---- what the window remembers ----

def load_state(path=None):
    try:
        with open(path or STATE, encoding="utf-8") as f:
            saved = json.load(f)
        return saved if isinstance(saved, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path=None, **changes):
    path = path or STATE
    state = {**load_state(path), **changes}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, path)
    return state


def note_scan(result):
    """Remember when this PC was last scanned and what the scan said."""
    try:
        save_state(last_scan={"time": time.time(), "level": result["level"], "verdict": result["verdict"]})
    except OSError:
        pass    # a scan is still a scan if its date cannot be written down


# ---- "Check with GotchU" in File Explorer's right-click menu ----

def menu_on():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, MENU_KEYS[0] + r"\command") as key:
            return winreg.QueryValue(key, None) == command('"%1"')
    except OSError:
        return False


def set_menu(on):
    for path in MENU_KEYS:
        if on:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
                winreg.SetValue(key, None, winreg.REG_SZ, MENU_TEXT)
                winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, ICON)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path + r"\command") as key:
                winreg.SetValue(key, None, winreg.REG_SZ, command('"%1"'))
        else:
            for sub in (path + r"\command", path):
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
                except OSError:
                    pass
    return menu_on() == bool(on)


# ---- at sign-in: open the window only if an alarm is waiting for an answer ----

def set_signin(on):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if on:
                winreg.SetValueEx(key, "GotchU", 0, winreg.REG_SZ, command("--if-alarm"))
            else:
                winreg.DeleteValue(key, "GotchU")
    except OSError:
        pass


# ---- Start-menu and desktop shortcuts ----

def _programs():
    return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "GotchU.lnk")


def shortcut_on():
    return os.path.isfile(_programs())


def set_shortcut(on):
    args = ["-Target", pythonw(), "-Icon", ICON] + ([] if on else ["-Remove"])
    try:
        subprocess.run([report.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                        os.path.join(HERE, "shortcut.ps1")] + args, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return shortcut_on() == bool(on)


# ---- the window itself ----

def _browser():
    """A browser that can show one page as its own window (no tabs, no address bar). Edge ships with Windows."""
    roots = [os.environ.get(name) for name in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA")]
    for tail in (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe"):
        for root in roots:
            exe = os.path.join(root, tail) if root else ""
            if os.path.isfile(exe):
                return exe
    return None


def open_window(url):
    """Show the page as an app window. False when no suitable browser is installed."""
    exe = _browser()
    if not exe:
        return False
    try:
        subprocess.Popen([exe, f"--app={url}", "--window-size=1240,780"])
    except OSError:
        return False
    return True


# ---- things the window can do with a file it has just checked ----

def recycle(path):
    """Move a file to the Recycle Bin, where it can still be put back."""
    try:
        out = subprocess.run([report.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                              os.path.join(HERE, "recycle.ps1"), "-Path", path], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return out.returncode == 0 and not os.path.exists(path)


def reveal(path):
    """Open File Explorer with the file selected."""
    explorer = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "explorer.exe")
    try:
        subprocess.Popen([explorer, "/select,", os.path.normpath(path)])
    except OSError:
        return False
    return True
