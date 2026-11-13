"""Shared result shape for every command: a verdict plus findings, as data or as text."""

HIGH, MEDIUM, INFO = "HIGH", "MEDIUM", "INFO"
_ORDER = {HIGH: 0, MEDIUM: 1, INFO: 2}


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
