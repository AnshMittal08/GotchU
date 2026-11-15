"""Shared result shape for every command: a verdict plus findings, as data or as text."""
import contextlib
import json
import os
import subprocess
import tempfile
import time

# Always Windows' own PowerShell, by its full path. Asked for by name alone, Windows looks in the current
# folder first, so a file called powershell.exe inside a download would be run instead.
POWERSHELL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
                          "powershell.exe")

HIGH, MEDIUM, INFO = "HIGH", "MEDIUM", "INFO"
_ORDER = {HIGH: 0, MEDIUM: 1, INFO: 2}


class CouldNotRun(Exception):
    """A command could not finish. The message says why, in words for the user."""


def powershell_json(script, what, timeout=180):
    """Run one of gotchu's read-only PowerShell collectors and return what it printed, as data."""
    try:
        out = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                              "-File", script], capture_output=True, timeout=timeout)
        return json.loads(out.stdout.decode("utf-8", "replace"))
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise CouldNotRun(f"Windows PowerShell did not give gotchu an answer, so {what} could not finish. Security "
                          "software or a policy set by your workplace may be blocking it. Nothing was changed.") from None


def level(findings):
    sevs = {f[0] for f in findings}
    return "danger" if HIGH in sevs else "warn" if MEDIUM in sevs else "ok"


def build(subject, findings, labels, **extra):
    """labels maps level ('danger' / 'warn' / 'ok') to (verdict, advice)."""
    lvl = level(findings)
    verdict, advice = labels[lvl]
    ordered = sorted(findings, key=lambda f: _ORDER[f[0]])
    return {"subject": subject, "level": lvl, "verdict": verdict, "advice": advice,
            "findings": [{"severity": s, "title": t, "detail": d} for s, t, d in ordered], **extra}


def plural(count, word):
    return f"{count} {word}{'' if count == 1 else 's'}"


def save_json(path, data):
    """Write the whole file or nothing. A reader never sees half a file, and a crash leaves the old one."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        for attempt in range(100):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:     # Windows: another gotchu is reading it at this instant
                if attempt == 99:
                    raise
                time.sleep(0.02)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


@contextlib.contextmanager
def _locked(path, wait=10):
    """One writer at a time, across gotchu's processes and the window's threads."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".lock", "a+b") as f:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            deadline = time.time() + wait
            while True:
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.time() > deadline:
                        raise
                    time.sleep(0.02)
            try:
                yield
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)


def update_json(path, change, default):
    """Read a small JSON file, change it and write it back, without losing a change made at the same moment
    by another gotchu. A file damaged beyond reading starts again from default."""
    with _locked(path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            data = default
        except ValueError:
            data = default
        data = change(data)
        save_json(path, data)
        return data


def render(result):
    lines = [f"Checked: {result['subject']}"]
    if result.get("sha256"):
        lines.append(f"SHA256:  {result['sha256']}")
    if result.get("origin"):
        lines.append(f"Downloaded from: {result['origin']}")
    lines += ["", f"VERDICT: {result['verdict']}", result["advice"], ""]
    for f in result["findings"]:
        lines += [f"[{f['severity']}] {f['title']}", f"       {f['detail']}"]
    return "\n".join(lines)
