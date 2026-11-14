"""Shared result shape for every command: a verdict plus findings, as data or as text."""
import json
import os
import subprocess

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
