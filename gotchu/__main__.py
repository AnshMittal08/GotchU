import argparse
import json
import os
import sys

from . import __version__, check, exposure, harden, report, respond, scan, tripwire


def _choose_passphrase(getpass, prompt, nothing):
    """Ask for a new passphrase twice. None (after saying why) if it is too short or the two differ."""
    passphrase = getpass.getpass(f"{prompt} (at least 10 characters; a few random words work well): ")
    if len(passphrase) < 10:
        print(f"Too short. {nothing}")
        return None
    if passphrase != getpass.getpass("Type it again: "):
        print(f"The two did not match. {nothing}")
        return None
    return passphrase


RECOVERY_NOTE = ("Write this on paper now and keep it away from this PC. It is shown only once.\n"
                 "If you forget the passphrase, this key is the only other way in. Lose both and the\n"
                 "files in the vault are gone for good.")


def _vault(args):
    import getpass
    import os

    from . import vault
    try:
        if args.action == "create":
            if vault.exists():
                print("There is already a vault on this PC.")
                return 1
            passphrase = _choose_passphrase(getpass, "Choose a passphrase", "Nothing was created.")
            if passphrase is None:
                return 1
            recovery = vault.create(passphrase)
            print(f"\nVault created in {vault.FOLDER}\n\nRECOVERY KEY:  {recovery}\n\n{RECOVERY_NOTE}")
            return 0
        if args.action == "restore":
            vault.restore(args.folder)
            print(f"Vault restored from {args.folder}. It opens with the passphrase or recovery key it had when it was backed up.")
            return 0
        if not vault.exists():
            print("There is no vault yet. Make one with: gotchu vault create")
            return 1
        if args.action == "backup":
            count = vault.backup(args.folder)
            print(f"Copied the vault ({report.plural(count, 'file')}, still encrypted) to {args.folder}.\n"
                  "The copy is useless without your passphrase or recovery key, so it is safe on a USB stick or in cloud storage.")
            return 0
        key = vault.unlock(getpass.getpass("Vault passphrase (or recovery key): "))
        if args.action == "list":
            print("\n".join(sorted(vault.names(key))) or "The vault is empty.")
        elif args.action == "add":
            for path in args.paths:
                name = vault.add(key, path, name=args.name if len(args.paths) == 1 else None, move=args.move)
                print(f"{name}: in the vault" + (", original deleted." if args.move else
                      f". The original is still at {path} - delete it, or add with --move."))
            if args.move:
                print("A deleted file can sometimes be recovered from the disk. If a key was ever exposed, replace it.")
        elif args.action == "get":
            target = args.to or args.name
            if os.path.isdir(target):       # a folder to put it in, the way most people write it
                target = os.path.join(target, os.path.basename(args.name))
            if os.path.exists(target):
                print(f"{target} already exists. Nothing was written.")
                return 1
            with open(target, "wb") as f:
                f.write(vault.get(key, args.name))
            print(f"Written to {target}. It is an ordinary file again - delete it when you are done.")
        elif args.action == "use":
            command = [part for part in args.run if part != "--"]
            if not command:
                print("Give the command to run, for example: gotchu vault use server.pem -- ssh -i {} user@host")
                return 1
            return vault.use(key, args.name, command)
        elif args.action == "passphrase":
            passphrase = _choose_passphrase(getpass, "Choose a new passphrase", "Nothing was changed.")
            if passphrase is None:
                return 1
            vault.change_passphrase(key, passphrase)
            print("Passphrase changed. The old one no longer opens the vault; your recovery key still does.")
        elif args.action == "recovery":
            recovery = vault.replace_recovery(key)
            print(f"\nNEW RECOVERY KEY:  {recovery}\n\nThe old recovery key no longer opens the vault.\n{RECOVERY_NOTE}")
        else:
            vault.remove(key, args.name)
            print(f"{args.name} removed from the vault.")
        return 0
    except vault.WrongSecret:
        print("That did not open the vault. Nothing was changed.")
    except KeyError as e:
        print(e.args[0])
    except (OSError, ValueError) as e:
        print(e)
    return 1


def _setup(args):
    from . import admin
    ok, message = admin.remove() if args.remove else admin.install()
    print(message)
    if ok and not args.remove:
        if admin.own_folder_writable():
            print(f"\nNote: gotchu itself is in a folder your account can change ({admin.HERE}). A program running as\n"
                  "you could change it, including what it asks Windows to run as administrator. For the strongest\n"
                  "setup, install gotchu with a Python that is installed for all users, in Program Files.")
        if tripwire.status()["on"]:
            print("\nThe tripwire is on: run gotchu tripwire --on once more so its watcher uses the new version.")
    return 0 if ok else 1


def _uninstall(args):
    from . import uninstall
    steps = uninstall.plan()
    if not steps:
        print("GotchU has nothing set up on this PC. To remove the program itself: " + uninstall.LAST_STEP)
        return 0
    prompts = sum(s["admin"] for s in steps)
    print("Removing GotchU will:\n" + "\n".join(f"  - {s['text']}" for s in steps))
    if prompts:
        print(f"\nWindows will ask for your permission {report.plural(prompts, 'time')}. Choose Yes each time.")
    if uninstall.kept():
        print("\n" + uninstall.kept())
    if not args.yes:
        try:
            answer = input("\nType yes to go ahead: ") if sys.stdin and sys.stdin.isatty() else ""
        except EOFError:        # no keyboard to answer with
            answer = ""
        if answer.strip().lower() != "yes":
            print("Nothing was changed. To go ahead without being asked: gotchu uninstall --yes")
            return 1
    ok, done, message = uninstall.run()
    for text in done:
        print(f"  done: {text}")
    print("\n" + message)
    return 0 if ok else 1


class _Parser(argparse.ArgumentParser):
    """A mistyped command ends with code 3 (could not run). argparse's own 2 would read as 'dangerous'."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")


def main(argv=None):
    # A name in a script the console cannot show (Hindi in a redirected file, say) prints as "?", not a crash.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    parser = _Parser(prog="gotchu", description="Free, local, read-only PC safety checks.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("check", help="inspect a download (zip, folder or file) without running it")
    p.add_argument("path")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p = sub.add_parser("scan", help="look for signs that this PC is infected right now")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p = sub.add_parser("exposure", help="show what a thief could take from this PC right now (counts only)")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p = sub.add_parser("harden", help="show which Windows protections are on; turn one on or put it back")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    changeable = [k["key"] for k in harden.LOCKS if k["can_apply"]]
    p.add_argument("--on", choices=changeable, metavar="LOCK", help="turn on: " + ", ".join(changeable))
    p.add_argument("--undo", choices=changeable, metavar="LOCK", help="put a lock back the way it was")
    p = sub.add_parser("tripwire", help="decoy files that raise an alarm when a thief reads them")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p.add_argument("--on", action="store_true", help="plant the decoys and start watching (alert only)")
    p.add_argument("--cut", action="store_true", help="with --on: also block the reading program from the internet")
    p.add_argument("--off", action="store_true", help="remove the decoys and put Windows back as it was")
    p.add_argument("--restore", action="store_true", help="after an alarm: lift the internet blocks and clear the alarm")
    p = sub.add_parser("vault", help="keep key files encrypted so a stolen copy is useless")
    act = p.add_subparsers(dest="action", required=True)
    act.add_parser("create", help="make the vault and choose its passphrase")
    a = act.add_parser("add", help="encrypt files into the vault")
    a.add_argument("paths", nargs="+")
    a.add_argument("--move", action="store_true", help="delete the original once the vault copy is verified")
    a.add_argument("--name", help="store a single file under another name")
    act.add_parser("list", help="show what is in the vault")
    a = act.add_parser("get", help="take a file out as an ordinary file")
    a.add_argument("name")
    a.add_argument("--to", help="a folder to put it in, or a full file name (default: this folder)")
    a = act.add_parser("use", help="run a command with the file present only while it runs")
    a.add_argument("name")
    a.add_argument("run", nargs=argparse.REMAINDER, help="the command; {} is replaced by the file's path")
    a = act.add_parser("remove", help="delete a file from the vault")
    a.add_argument("name")
    act.add_parser("passphrase", help="choose a new passphrase (opens with the old one or the recovery key)")
    act.add_parser("recovery", help="make a new recovery key; the old one stops working")
    a = act.add_parser("backup", help="copy the vault, still encrypted, to another folder or drive")
    a.add_argument("folder", help="a new or empty folder")
    a = act.add_parser("restore", help="bring a backed-up vault back onto a PC that has none")
    a.add_argument("folder", help="the folder a backup was copied to")
    p = sub.add_parser("respond", help="after running something bad: what to do, in what order")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p.add_argument("--sites", action="store_true", help="also list the websites with a password saved on this PC (names only)")
    p = sub.add_parser("setup", help="install or update gotchu's administrator helpers in Program Files")
    p.add_argument("--remove", action="store_true", help="remove them, once nothing gotchu turned on still needs them")
    p = sub.add_parser("uninstall", help="put back everything GotchU set up, before removing it (the vault is kept)")
    p.add_argument("--yes", action="store_true", help="go ahead without asking")
    p = sub.add_parser("app", help="open GotchU in its own window")
    p.add_argument("path", nargs="?", help="a download to check as soon as the window opens")
    p.add_argument("--if-alarm", action="store_true", help="open only if an alarm is waiting for an answer (used at sign-in)")
    p = sub.add_parser("ui", help="open the same window as a tab in your browser")
    p.add_argument("path", nargs="?", help="a download to check as soon as the window opens")
    p.add_argument("--no-browser", action="store_true", help="start without opening a browser")
    args = parser.parse_args(argv)

    if args.command in ("app", "ui"):
        from . import ui
        if args.command == "app":
            if args.if_alarm and not tripwire.status()["alerts"]:
                return 0
            return ui.serve(window="app", path=args.path)
        return ui.serve(window=None if args.no_browser else "tab", path=args.path)

    if args.command == "vault":
        return _vault(args)

    if args.command == "setup":
        return _setup(args)

    if args.command == "uninstall":
        return _uninstall(args)

    try:
        return _run(args)
    except report.CouldNotRun as e:
        print(e)
        return 3


def _run(args):
    if args.command == "harden" and (args.on or args.undo):
        ok, message = harden.change(args.on or args.undo, undo=bool(args.undo))
        print(message)
        return 0 if ok else 1

    if args.command == "tripwire" and (args.on or args.off or args.restore):
        ok, message = tripwire.change("on" if args.on else "off" if args.off else "restore", cut=args.cut)
        print(message)
        return 0 if ok else 1

    if args.command == "check":
        if not args.path.strip():
            raise report.CouldNotRun("Give the file or folder to check, for example: gotchu check Downloads\\game.zip")
        if not os.path.exists(check.long_path(args.path)):
            raise report.CouldNotRun(f"{args.path} does not exist, or Windows will not let gotchu see it. "
                                     "Check the path and try again.")
        try:
            result = check.result(args.path)
        except OSError as e:
            raise report.CouldNotRun(f"Windows would not let gotchu read {args.path} ({e.strerror or e}). "
                                     "Try a copy in your Downloads folder.") from None
    elif args.command == "tripwire":
        result = tripwire.result()
    elif args.command == "exposure":
        result = exposure.result()
    elif args.command == "respond":
        result = respond.result(with_sites=args.sites)
    elif args.command == "scan":
        from . import desktop
        result = scan.result()
        desktop.note_scan(result)
    else:
        result = harden.result()
    print(json.dumps(result, indent=2) if args.json else report.render(result))
    if args.command == "respond" and args.sites and not args.json:
        print(f"\nWebsites with a password saved on this PC ({len(result['sites'])}):\n" + "\n".join(result["sites"]))
    return {"danger": 2, "warn": 1}.get(result["level"], 0)


if __name__ == "__main__":
    sys.exit(main())
