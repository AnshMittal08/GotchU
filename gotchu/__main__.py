import argparse
import json
import sys

from . import __version__, check, exposure, harden, report, scan, tripwire


def _vault(args):
    import getpass
    import os

    from . import vault
    try:
        if args.action == "create":
            if vault.exists():
                print("There is already a vault on this PC.")
                return 1
            passphrase = getpass.getpass("Choose a passphrase (at least 10 characters; a few random words work well): ")
            if len(passphrase) < 10:
                print("Too short. Nothing was created.")
                return 1
            if passphrase != getpass.getpass("Type it again: "):
                print("The two did not match. Nothing was created.")
                return 1
            recovery = vault.create(passphrase)
            print(f"\nVault created in {vault.FOLDER}\n\nRECOVERY KEY:  {recovery}\n\n"
                  "Write this on paper now and keep it away from this PC. It is shown only once.\n"
                  "If you forget the passphrase, this key is the only other way in. Lose both and the\n"
                  "files in the vault are gone for good.")
            return 0
        if not vault.exists():
            print("There is no vault yet. Make one with: gotchu vault create")
            return 1
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


def main(argv=None):
    parser = argparse.ArgumentParser(prog="gotchu", description="Free, local, read-only PC safety checks.")
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
    a.add_argument("--to", help="where to write it (default: this folder)")
    a = act.add_parser("use", help="run a command with the file present only while it runs")
    a.add_argument("name")
    a.add_argument("run", nargs=argparse.REMAINDER, help="the command; {} is replaced by the file's path")
    a = act.add_parser("remove", help="delete a file from the vault")
    a.add_argument("name")
    p = sub.add_parser("ui", help="open the gotchu window in your browser")
    p.add_argument("path", nargs="?", help="a download to check as soon as the window opens")
    p.add_argument("--no-browser", action="store_true", help="start without opening a browser")
    args = parser.parse_args(argv)

    if args.command == "ui":
        from . import ui
        return ui.serve(open_browser=not args.no_browser, path=args.path)

    if args.command == "vault":
        return _vault(args)

    if args.command == "harden" and (args.on or args.undo):
        ok, message = harden.change(args.on or args.undo, undo=bool(args.undo))
        print(message)
        return 0 if ok else 1

    if args.command == "tripwire" and (args.on or args.off or args.restore):
        ok, message = tripwire.change("on" if args.on else "off" if args.off else "restore", cut=args.cut)
        print(message)
        return 0 if ok else 1

    if args.command == "check":
        result = check.result(args.path)
    elif args.command == "tripwire":
        result = tripwire.result()
    elif args.command == "exposure":
        result = exposure.result()
    else:
        result = scan.result() if args.command == "scan" else harden.result()
    print(json.dumps(result, indent=2) if args.json else report.render(result))
    return {"danger": 2, "warn": 1}.get(result["level"], 0)


if __name__ == "__main__":
    sys.exit(main())
