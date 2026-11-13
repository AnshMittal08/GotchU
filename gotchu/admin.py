"""Administrator helpers: the only gotchu code that runs with administrator rights.

They run from C:\\Program Files\\gotchu, which only an administrator can change - never from gotchu's
own folder, which is often one that any program running as you can change.

They are copied there the first time they are needed, or by `gotchu setup` after an update. After
that, gotchu will not ask Windows to elevate while its own copy differs from the installed one, so a
program that edits gotchu's files cannot slip its code into a permission prompt you were expecting.

Limit, stated plainly: if gotchu's own folder is one you can change, a program running as you could
change gotchu itself. `gotchu setup` says so; installing for all users, in Program Files, closes it.
"""
import hashlib
import os
import subprocess
import tempfile

HERE = os.path.dirname(__file__)
INSTALLED = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "gotchu")
HELPERS = ("harden_apply.ps1", "tripwire_apply.ps1", "tripwire_watch.ps1")
CANCELLED = 1223    # Windows' code for "the user said no"
DECLINED = "Nothing was changed: the Windows permission prompt was declined or closed."


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest().upper()


def state(source=HERE, dest=INSTALLED):
    """'current', 'missing' (not installed yet) or 'different' (installed, but not this copy's version)."""
    missing = False
    for name in HELPERS:
        try:
            with open(os.path.join(dest, name), "rb") as f:
                installed = f.read()
        except FileNotFoundError:
            missing = True
            continue
        with open(os.path.join(source, name), "rb") as f:
            if f.read() != installed:
                return "different"
    return "missing" if missing else "current"


def own_folder_writable(folder=HERE):
    """Can this account change gotchu's own files? Then so can any program it runs."""
    try:
        with tempfile.TemporaryFile(dir=folder):
            return True
    except OSError:
        return False


def _quote(text):
    return "'" + text.replace("'", "''") + "'"


def launcher(args, elevate=True):
    """PowerShell that starts powershell.exe with `args` - with administrator rights, after Windows asks -
    waits for it, and exits with its exit code (CANCELLED if the prompt was declined)."""
    verb = "-Verb RunAs " if elevate else ""
    listed = ",".join(_quote(a) for a in args)
    return (f"try {{ $p = Start-Process powershell.exe {verb}-Wait -PassThru -WindowStyle Hidden -ArgumentList {listed} }} "
            f"catch {{ exit {CANCELLED} }}; if ($null -eq $p.ExitCode) {{ exit 1 }}; exit $p.ExitCode")


def _elevate(args):
    out = subprocess.run(["powershell.exe", "-NoProfile", "-Command", launcher(args)], capture_output=True, timeout=300)
    return out.returncode


def install_script(hashes, source=HERE, dest=INSTALLED):
    """PowerShell, run elevated, that copies the helpers into dest. A copy is kept only if it is exactly the
    file gotchu read (same SHA-256), so a file swapped in the meantime never stays in Program Files."""
    pairs = ",".join(f"@({_quote(name)},{_quote(digest)})" for name, digest in hashes.items())
    return (f"$ErrorActionPreference = 'Stop'; $d = {_quote(dest)}; New-Item -ItemType Directory -Force -Path $d | Out-Null; "
            f"foreach ($f in @({pairs})) {{ $to = Join-Path $d $f[0]; "
            f"Copy-Item -LiteralPath (Join-Path {_quote(source)} $f[0]) -Destination $to -Force; "
            "if ((Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash -ne $f[1]) "
            "{ Remove-Item -LiteralPath $to -Force; exit 2 } }; exit 0")


def install(source=HERE, dest=INSTALLED):
    """Copy the helpers into Program Files: one Windows permission prompt. Returns (ok, message)."""
    if state(source, dest) == "current":
        return True, f"GotchU's administrator helpers in {dest} are installed and up to date."
    hashes = {name: _sha256(os.path.join(source, name)) for name in HELPERS}
    script = install_script(hashes, source, dest)
    code = _elevate(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f'"{script}"'])
    if code == CANCELLED:
        return False, DECLINED
    if code == 2:
        return False, ("A helper file changed while it was being installed, so it was removed again. "
                       "Run gotchu scan, then try again.")
    if code or state(source, dest) != "current":
        return False, f"Windows could not install GotchU's administrator helpers in {dest}."
    return True, f"Installed GotchU's administrator helpers in {dest}."


def remove(dest=INSTALLED):
    """Remove the helpers, but only when nothing gotchu set up still needs them. Returns (ok, message)."""
    if os.path.exists(os.path.join(dest, "tripwire.json")):
        return False, "The tripwire is on and uses these helpers. Turn it off first: gotchu tripwire --off"
    journal = os.path.join(dest, "journal")
    pending = sorted(os.path.splitext(n)[0] for n in os.listdir(journal)) if os.path.isdir(journal) else []
    if pending:
        return False, ("These helpers are needed to put back what GotchU turned on: " + ", ".join(pending)
                       + ". Undo those first with gotchu harden --undo <lock>.")
    if not os.path.isdir(dest):
        return True, "GotchU's administrator helpers are not installed."
    code = _elevate(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                     f'"Remove-Item -LiteralPath {_quote(dest)} -Recurse -Force"'])
    if code == CANCELLED:
        return False, DECLINED
    if os.path.isdir(dest):
        return False, f"Windows could not remove {dest}."
    return True, f"Removed {dest}."


def run(script, args):
    """Run one helper from Program Files with administrator rights; Windows asks the user first.

    The first time, the helpers are installed before that (one more prompt). Returns (ok, message).
    """
    current = state()
    if current == "different":
        return False, (f"GotchU's administrator helpers in {INSTALLED} are not the ones in this copy of GotchU, "
                       "so nothing was changed. If you have just updated GotchU, run: gotchu setup. "
                       "If you have not, something may have changed GotchU's files: run gotchu scan first.")
    if current == "missing":
        ok, message = install()
        if not ok:
            return False, message
    code = _elevate(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f'"{os.path.join(INSTALLED, script)}"']
                    + list(args))
    if code == CANCELLED:
        return False, DECLINED
    if code:
        try:
            with open(os.path.join(INSTALLED, "last-error.txt"), encoding="utf-8-sig") as f:
                return False, "Windows refused the change. " + f.read().strip()
        except OSError:
            return False, f"Windows refused the change (code {code})."
    return True, ""
