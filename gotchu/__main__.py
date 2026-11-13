import argparse
import json
import sys

from . import __version__, check, exposure, harden, report, scan, tripwire


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
    p = sub.add_parser("ui", help="open the gotchu window in your browser")
    p.add_argument("path", nargs="?", help="a download to check as soon as the window opens")
    p.add_argument("--no-browser", action="store_true", help="start without opening a browser")
    args = parser.parse_args(argv)

    if args.command == "ui":
        from . import ui
        return ui.serve(open_browser=not args.no_browser, path=args.path)

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
