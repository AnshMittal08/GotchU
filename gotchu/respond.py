"""Respond: you ran something bad. What could it have taken, and what do you do, in what order?

Builds a checklist from the exposure report: only the steps that apply to what is on this PC, ordered
by how fast the loss happens and how much each step protects the ones after it.

Limit, stated plainly: gotchu cannot tell what was actually taken. The list covers everything a thief
could have read, because that is the safe assumption.
"""
import json
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from . import exposure, report, tripwire
from .report import MEDIUM

MESSENGER = {
    "Telegram Desktop": "Telegram: on your phone, Settings > Devices > Terminate all other sessions.",
    "Discord": "Discord: change your password, which signs every device out.",
    "Signal": "Signal: on your phone, Settings > Linked devices, and unlink this PC.",
}
CLOUD = {
    "Amazon Web Services keys": "AWS: delete the access key in IAM and make a new one.",
    "Google Cloud sign-in": "Google Cloud: run gcloud auth revoke --all, then sign in again.",
    "Google Cloud application key": "Google Cloud application key: delete that key in the console and make a new one.",
    "Azure sign-in": "Azure: run az logout, and revoke your sessions in Microsoft Entra.",
    "Kubernetes cluster access": "Kubernetes: have the cluster's credentials replaced, or ask whoever runs the cluster.",
    "Docker registry login": "Docker: run docker logout, and revoke the access token at the registry.",
    "GitHub command-line token": "GitHub: revoke the token under Settings > Applications, then run gh auth login.",
    "Git saved passwords": "Git: revoke the saved tokens at the sites they belong to.",
    "npm publish token": "npm: revoke the token at npmjs.com.",
}


def sites(items):
    """Websites that have a password saved in a browser on this PC. Names only; a password is never read."""
    found = set()
    for item in items:
        if item["kind"] != "passwords":
            continue
        where = item["where"]
        try:
            if where.lower().endswith(".json"):                                   # Firefox
                with open(where, encoding="utf-8") as f:
                    urls = [login.get("hostname", "") for login in json.load(f).get("logins", [])]
            else:                                                                 # Chrome and its relatives
                con = sqlite3.connect(Path(where).as_uri() + "?mode=ro&immutable=1", uri=True)
                try:
                    urls = [row[0] for row in con.execute("SELECT DISTINCT origin_url FROM logins")]
                finally:
                    con.close()
        except (OSError, ValueError, sqlite3.Error):
            continue
        found.update(urlsplit(u).hostname or u for u in urls if u)
    return sorted(found)


def steps(items):
    """The checklist as (title, detail), in the order to do it."""
    by_kind = {}
    for item in items:
        by_kind.setdefault(item["kind"], []).append(item)

    def names(kind):
        return sorted({i["name"] for i in by_kind.get(kind, [])})

    def total(kind):
        return sum(i["count"] or 0 for i in by_kind.get(kind, []))

    out = [("Disconnect this PC from the internet, and do every step below from another device",
            "The malware may still be running and watching what you type. A phone on mobile data is fine.")]
    if "wallet" in by_kind:
        out.append(("Move your crypto to a new wallet now",
                    "This comes first because a transfer cannot be undone. On a device that was not infected, make a "
                    "new wallet with a new recovery phrase and send everything to it. Treat the old wallet's keys as "
                    "copied. Found on this PC: " + ", ".join(names("wallet")) + "."))
    out.append(("Secure your main email account",
                "Whoever holds your email can reset every other password. Change its password, turn on 2-step sign-in, "
                "use its 'sign out of all devices' option, and look for forwarding rules or recovery addresses you did not add."))
    if "sessions" in by_kind:
        out.append(("Sign out everywhere on the accounts that matter",
                    f"{len(by_kind['sessions'])} browser profiles on this PC hold signed-in sessions. A stolen session "
                    "works without your password or 2-step code, and a new password does not always end it. On each "
                    "important account - email, bank, social, work - use 'sign out of all devices'."))
    if "passwords" in by_kind:
        out.append((f"Change the {total('passwords')} passwords saved in your browsers",
                    "Start with money, email and work. Give each site its own password and keep them in a password "
                    "manager, not in the browser. gotchu respond --sites lists the websites."))
    if "messenger" in by_kind:
        out.append(("End the other sessions in your chat apps",
                    " ".join(MESSENGER.get(n, f"{n}: sign out of all other devices in its settings.") for n in names("messenger"))))
    if "cloud" in by_kind:
        out.append(("Replace your cloud and developer keys",
                    " ".join(CLOUD.get(n, f"{n}: revoke it at the service and make a new one.") for n in names("cloud"))
                    + " If any of these belong to your employer, tell them today."))
    if "keys" in by_kind:
        out.append((f"Replace the {total('keys')} key and secret files found in: " + ", ".join(names("keys")),
                    "Make new keys, put the new ones on your servers and services, and remove the old ones there. "
                    "Then keep the new ones in the vault: gotchu vault add --move <file>."))
    out.append(("Clean this PC before you trust it again",
                "Run gotchu scan, then a Microsoft Defender Offline scan from Windows Security. If the malware had "
                "administrator rights, or you are not sure, back up your documents and reset Windows: "
                "Settings > System > Recovery > Reset this PC."))
    out.append(("Stay alert for the next few weeks",
                "Watch bank statements and sign-in alerts. Stolen details are used for convincing scams, so be wary of "
                "messages that know things about you."))
    return out


LABELS = {"warn": ("DO THESE IN ORDER", "gotchu cannot tell what was actually taken. This list covers everything a thief "
                   "could have read on this PC, which is the safe assumption.")}


def result(with_sites=False):
    items = exposure.collect()
    findings = [(MEDIUM, f"{n}. {title}", detail) for n, (title, detail) in enumerate(steps(items), 1)]
    extra = {}
    if with_sites:
        with tripwire.own_reads():
            extra["sites"] = sites(items)
    return report.build("what to do after running something bad", findings, LABELS, **extra)
