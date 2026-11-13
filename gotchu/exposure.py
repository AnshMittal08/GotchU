"""Exposure: what a thief could take from this PC right now.

Walks the secrets map (secrets_map.json) the way an info-stealer would, but only counts.
It never decrypts, copies or prints a secret. Each store is also opened for one byte, as an
ordinary program would, to show whether anything stops a thief from reading it today.
"""
import json
import os
import re
import sqlite3
from pathlib import Path

from . import report, tripwire
from .report import MEDIUM

HERE = os.path.dirname(__file__)
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "site-packages"}
KEY_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
CODES = re.compile(r"(recovery|backup)[-_ ]?codes?", re.I)
NOT_REAL_ENV = (".example", ".sample", ".template", ".dist")

FIX = {
    "passwords": "Move them to a password manager with its own master lock, then delete them from the browser.",
    "sessions": "A stolen session opens the account without your password or 2-step code. Sign out of sites "
                "you rarely use, and after any infection use 'sign out everywhere' on the important ones.",
    "messenger": "A copy of this folder signs a thief in as you. Set a local passcode in the app if it has one.",
    "cloud": "Use short-lived sign-in instead of a key saved in a file, and delete keys you no longer need.",
    "keys": "Put them in the vault (gotchu vault add --move <file>) so a stolen copy is useless.",
    "wallet": "Keep savings in a hardware wallet; anything left here can be emptied by one bad download.",
}


def load_map():
    with open(os.path.join(HERE, "secrets_map.json"), encoding="utf-8") as f:
        return json.load(f)


def expand(path, env):
    return re.sub(r"%([^%]+)%", lambda m: env.get(m.group(1), env.get(m.group(1).upper(), m.group(0))), path)


def _count(db, query):
    """Count rows without changing the file. None when the owner has it locked."""
    try:
        con = sqlite3.connect(Path(db).as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            return con.execute(query).fetchone()[0]
        finally:
            con.close()
    except sqlite3.Error:
        return None


def _first_file(path):
    if os.path.isfile(path):
        return path
    for root, _, files in os.walk(path):
        if files:
            return os.path.join(root, files[0])
    return None


def can_read(path):
    """Can an ordinary program open this right now? This is all a thief needs."""
    target = _first_file(path)
    if not target:
        return False
    try:
        with open(target, "rb") as f:
            f.read(1)
        return True
    except OSError:
        return False


def _item(kind, name, count, unit, where, owners=()):
    return {"kind": kind, "name": name, "count": count, "unit": unit, "where": where,
            "owners": list(owners), "readable": can_read(where)}


def _browser(entry, root, wallets):
    items = []
    if entry["engine"] == "firefox":
        profiles = [p.path for p in os.scandir(root) if p.is_dir()]
    else:
        profiles = [root] + [p.path for p in os.scandir(root) if p.is_dir()]
    for profile in profiles:
        label = entry["name"] if len(profiles) < 3 else f"{entry['name']} ({os.path.basename(profile)})"
        if entry["engine"] == "firefox":
            logins = os.path.join(profile, "logins.json")
            saved = None
            if os.path.isfile(logins):
                try:
                    with open(logins, encoding="utf-8") as f:
                        saved = len(json.load(f).get("logins", []))
                except (OSError, ValueError):
                    pass
            cookies, cookie_query = os.path.join(profile, "cookies.sqlite"), "SELECT COUNT(DISTINCT host) FROM moz_cookies"
        else:
            logins = os.path.join(profile, "Login Data")
            saved = _count(logins, "SELECT COUNT(*) FROM logins") if os.path.isfile(logins) else None
            cookies = os.path.join(profile, "Network", "Cookies")
            cookie_query = "SELECT COUNT(DISTINCT host_key) FROM cookies"
            for ext_id, wallet in wallets.items():
                data = os.path.join(profile, "Local Extension Settings", ext_id)
                if os.path.isdir(data):
                    items.append(_item("wallet", f"{wallet} in {label}", 1, "wallet", data, entry["owners"]))
        if saved:
            items.append(_item("passwords", label, saved, "saved passwords", logins, entry["owners"]))
        if os.path.isfile(cookies):
            sites = _count(cookies, cookie_query)
            if sites != 0:  # None = locked while the browser is open, still worth reporting
                items.append(_item("sessions", label, sites, "websites with a stored session", cookies, entry["owners"]))
    return items


def _is_key_file(path, name):
    low = name.lower()
    ext = os.path.splitext(low)[1]
    try:
        if low == ".env" or (low.startswith(".env.") and not low.endswith(NOT_REAL_ENV)):
            return os.path.getsize(path) > 0
        if CODES.search(low):
            return True
        if ext in (".pem", ".key", ".ppk") or low in KEY_NAMES:
            with open(path, "rb") as f:
                head = f.read(2048)
            return b"PRIVATE KEY" in head or b"PuTTY-User-Key-File" in head
        if ext == ".json" and os.path.getsize(path) < 16384:
            with open(path, "rb") as f:
                return b'"private_key"' in f.read()
    except OSError:
        pass
    return False


def _key_files(folder, depth=3):
    found = []
    base = folder.rstrip("\\/").count(os.sep)
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS] if root.count(os.sep) - base < depth else []
        found += [os.path.join(root, n) for n in files if _is_key_file(os.path.join(root, n), n)]
    return found


def collect(env=None, secrets=None):
    env = os.environ if env is None else env
    secrets = secrets or load_map()
    items = []
    for entry in secrets["browsers"]:
        root = expand(entry["root"], env)
        if os.path.isdir(root):
            items += _browser(entry, root, secrets.get("wallet_extensions", {}))
    planted = [r.lower() for r in tripwire.decoy_roots()]   # gotchu's own decoys are not real wallets
    for store in secrets["stores"]:
        path = expand(store["path"], env)
        if not os.path.exists(path) or any(path.lower().startswith(r) for r in planted):
            continue
        if store.get("contains"):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    if store["contains"] not in f.read():
                        continue
            except OSError:
                continue
        if store.get("rows") and _count(path, store["rows"]) == 0:
            continue  # the store exists but is empty (signed out)
        unit = {"messenger": "signed-in session", "cloud": "login", "wallet": "wallet"}[store["kind"]]
        items.append(_item(store["kind"], store["name"], 1, unit, path, store.get("owners", ())))
    for folder in secrets["key_file_folders"]:
        folder = expand(folder, env)
        files = _key_files(folder) if os.path.isdir(folder) else []
        if files:
            item = _item("keys", os.path.basename(folder) + " folder", len(files), "key and secret files", files[0])
            item["where"] = folder
            item["examples"] = [os.path.basename(f) for f in files[:5]]
            items.append(item)
    return items


def analyse(items):
    findings = []
    for i in items:
        amount = f"{i['count']} {i['unit']}" if i["count"] is not None else f"{i['unit'].capitalize()} (not counted: in use)"
        state = "Any program you run can read this." if i["readable"] else "Locked while its owner is running; readable once it closes."
        names = " Files: " + ", ".join(i["examples"]) + "." if i.get("examples") else ""
        findings.append((MEDIUM, f"{i['name']}: {amount}", f"{state} {FIX[i['kind']]}{names} Location: {i['where']}"))
    return findings


def result():
    items = collect()
    readable = sum(1 for i in items if i["readable"])
    labels = {
        "warn": (f"A THIEF COULD READ {readable} OF {len(items)} SECRET STORES",
                 "This is what one bad download could take from this PC today. Nothing here was copied or shown."),
        "ok": ("NOTHING FOUND TO STEAL", "gotchu found no saved passwords, sessions or keys in the places it knows."),
    }
    return report.build("this PC, as a thief would see it", analyse(items), labels, items=items)
