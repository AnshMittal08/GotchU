"""The gotchu window: one page served only to this PC, shown as an app window or in the browser.

Safety of the server itself:
  - listens on 127.0.0.1 only, on a random port;
  - every action needs a one-time token that only the opened page knows, so no
    other website can ask it to do anything;
  - the Host header must match, which blocks DNS-rebinding tricks;
  - it deletes or reveals only the file it was last asked to check.
"""
import hmac
import json
import os
import secrets
import subprocess
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

from . import __version__, admin, check, desktop, exposure, harden, report, respond, scan, tripwire

HERE = os.path.dirname(__file__)
FONTS = ("barlow-500.woff2", "barlow-600.woff2", "barlow-semicondensed-600.woff2")
WORTH_CHECKING = {".zip", ".7z", ".rar", ".iso", ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk",
                  ".scr", ".jar", ".hta", ".img", ".vhd", ".vhdx"}
START_SECONDS = 300     # an app window that never loads its page: stop waiting for it
IDLE_SECONDS = 150      # a page that has gone quiet (a hidden window still reports about once a minute)
NOT_OURS = {"error": "This page was not opened by gotchu. Open GotchU again."}


def recent_downloads(limit=12):
    folder = os.path.join(os.path.expanduser("~"), "Downloads")
    rows = []
    try:
        for entry in os.scandir(folder):
            if entry.is_file() and os.path.splitext(entry.name)[1].lower() in WORTH_CHECKING:
                st = entry.stat()
                rows.append({"name": entry.name, "path": entry.path, "size": st.st_size, "modified": st.st_mtime})
    except OSError:
        pass
    return sorted(rows, key=lambda r: r["modified"], reverse=True)[:limit]


def browse(folder):
    cmd = [report.POWERSHELL, "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File",
           os.path.join(HERE, "browse.ps1")] + (["-Folder"] if folder else [])
    out = subprocess.run(cmd, capture_output=True, timeout=600)
    return out.stdout.decode("utf-8", "replace").strip()


def activity(trip):
    """Alarms, and reads listed for review, newest first. Repeats of the same read are counted, not listed."""
    rows = [{"time": a.get("time", ""), "kind": "alarm", "program": a.get("program", ""), "cut": bool(a.get("cut"))}
            for a in trip["alerts"]]
    seen = {}
    for s in trip["sightings"]:
        what = "a decoy file" if s.get("kind") == "decoy" else str(s.get("store", "your logins")).split(" (")[0]
        key = (s.get("program", ""), what)
        if key in seen:
            seen[key]["count"] += 1
            seen[key]["time"] = max(seen[key]["time"], s.get("time", ""))
        else:
            seen[key] = {"time": s.get("time", ""), "kind": "review", "program": key[0], "what": what, "count": 1}
    rows += seen.values()
    marks = [{"time": r["time"], "kind": "alarm"} for r in rows if r["kind"] == "alarm"]
    marks += [{"time": s.get("time", ""), "kind": "review"} for s in trip["sightings"]]
    return sorted(rows, key=lambda r: r["time"], reverse=True)[:8], marks[-400:]


def status():
    """Everything Home needs that can be read at once (the Windows locks take a few seconds and come separately)."""
    trip = tripwire.status()
    alert = trip["alerts"][-1] if trip["alerts"] else None
    saved = desktop.load_state()
    events, marks = activity(trip)
    return {
        "events": events, "marks": marks,
        "version": __version__,
        "tripwire": {"on": trip["on"], "cut": trip["cut"], "watching": bool(trip.get("watching")),
                     "decoys": len(trip["decoys"]), "stores": len(trip["stores"]),
                     "alert": alert and {"time": alert.get("time", ""), "program": alert.get("program", ""),
                                         "cut": bool(alert.get("cut"))}},
        "helpers": admin.state(),
        "menu": desktop.menu_on(), "shortcut": desktop.shortcut_on(),
        "welcomed": bool(saved.get("welcomed")), "theme": saved.get("theme", "system"),
        "last_scan": saved.get("last_scan"),
        "downloads": recent_downloads(4),
    }


def set_tripwire(on, cut):
    ok, message = tripwire.change("on", cut=cut) if on else tripwire.change("off")
    if ok:
        desktop.set_signin(on)      # with the tripwire on, an alarm nobody answered opens the window at sign-in
    return ok, message


def answer_alarm():
    """'Yes, it is mine': lift the internet block, clear the alarm, and retire a decoy a real app now uses."""
    cut = tripwire.status()["cut"]
    ok, message = tripwire.change("restore")
    if ok and tripwire.moved_in():
        ok, message = tripwire.change("on", cut=cut)
    return ok, message


def update_helpers():
    """After gotchu is updated: put this version's helpers in Program Files and restart the watcher with them."""
    ok, message = admin.install()
    trip = tripwire.status()
    if ok and trip["on"]:
        ok, message = tripwire.change("on", cut=trip["cut"])
    return ok, message


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _allowed(self):
        token = self.headers.get("X-GotchU-Token", "")
        ok = self.headers.get("Host") == self.server.host and hmac.compare_digest(token, self.server.token)
        if ok:
            self.server.seen = time.time()
        return ok

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(HERE, "app.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if path.startswith("/fonts/") and path[7:] in FONTS:
            with open(os.path.join(HERE, "fonts", path[7:]), "rb") as f:
                return self._send(200, f.read(), "font/woff2")
        if not self._allowed():
            return self._send(403, NOT_OURS)
        if path == "/api/status":
            return self._send(200, status())
        self._send(404, {"error": "Not found."})

    def do_POST(self):
        if not self._allowed():
            return self._send(403, NOT_OURS)
        try:
            body = json.loads(self.rfile.read(max(0, int(self.headers.get("Content-Length") or 0))) or b"{}")
        except ValueError:
            return self._send(400, {"error": "The request could not be read."})
        if not isinstance(body, dict):
            return self._send(400, {"error": "The request could not be read."})
        try:
            answer = self._act(self.path, body)
        except PermissionError:
            return self._send(400, {"error": "Windows would not let gotchu read that. Try a copy in your Downloads folder."})
        except report.CouldNotRun as e:
            return self._send(500, {"error": str(e)})
        except Exception as e:  # report instead of dropping the connection
            return self._send(500, {"error": f"That could not finish: {e}"})
        if answer is None:
            return self._send(404, {"error": "Not found."})
        self._send(*answer)

    def _act(self, path, body):
        """One action. Returns (http code, answer), or None for a path that does not exist."""
        server = self.server

        def changed(ok, message):
            return 200, {"ok": ok, "message": message, "status": status()}

        if path == "/api/ping":
            return 200, {}
        if path == "/api/bye":
            server.bye = time.time()
            return 200, {}
        if path == "/api/check":
            target = body.get("path")
            target = target.strip().strip('"') if isinstance(target, str) else ""
            if not target or not os.path.exists(check.long_path(target)):
                return 400, {"error": "That file or folder does not exist. Check the path and try again."}
            server.checked = os.path.abspath(target)
            return 200, {**check.result(target), "path": server.checked, "is_file": os.path.isfile(check.long_path(target))}
        if path == "/api/browse":
            return 200, {"path": browse(bool(body.get("folder")))}
        if path in ("/api/delete", "/api/reveal"):
            target = body.get("path")
            if not isinstance(target, str) or not server.checked or os.path.abspath(target) != server.checked:
                return 400, {"error": "gotchu only does this with the file it has just checked."}
            if path == "/api/reveal":
                return 200, {"ok": desktop.reveal(target)}
            if not os.path.isfile(target):
                return 400, {"error": "Only a single file can be moved to the Recycle Bin from here."}
            ok = desktop.recycle(target)
            return 200, {"ok": ok, "message": "Moved to the Recycle Bin." if ok else "Windows could not move it to the Recycle Bin."}
        if path == "/api/scan":
            result = scan.result()
            desktop.note_scan(result)
            return 200, result
        if path == "/api/exposure":
            return 200, exposure.result()
        if path == "/api/tripwire/log":
            return 200, tripwire.result()
        if path == "/api/locks":
            return 200, {"locks": harden.result()["locks"]}
        if path == "/api/lock":
            ok, message = harden.change(str(body.get("key")), undo=bool(body.get("undo")))
            return 200, {"ok": ok, "message": message, "locks": harden.result()["locks"]}
        if path == "/api/prefs":
            keep = {}
            if body.get("theme") in ("light", "dark", "system"):
                keep["theme"] = body["theme"]
            if body.get("welcomed"):
                keep["welcomed"] = True
            desktop.save_state(**keep)
            return 200, {"status": status()}
        if path == "/api/tripwire":
            return changed(*set_tripwire(bool(body.get("on")), bool(body.get("cut"))))
        if path == "/api/alarm":
            return changed(*answer_alarm())
        if path == "/api/helpers":
            return changed(*update_helpers())
        if path == "/api/menu":
            ok = desktop.set_menu(bool(body.get("on")))
            return changed(ok, "" if ok else "Windows would not change the right-click menu.")
        if path == "/api/shortcut":
            ok = desktop.set_shortcut(bool(body.get("on")))
            done = "GotchU is in the Start menu and on the desktop." if body.get("on") else "Shortcuts removed."
            return changed(ok, done if ok else "Windows would not change the shortcuts.")
        if path == "/api/respond":
            items = exposure.collect()
            # In the window the list of websites is a button on that step, not a command to type.
            steps = [{"title": title, "detail": detail.replace(" gotchu respond --sites lists the websites.", "")}
                     for title, detail in respond.steps(items)]
            return 200, {"steps": steps, "done": desktop.load_state().get("done", []), "advice": respond.LABELS["warn"][1]}
        if path == "/api/respond/done":
            done = [t for t in desktop.load_state().get("done", []) if t != body.get("title")]
            if body.get("done") and isinstance(body.get("title"), str):
                done.append(body["title"])
            desktop.save_state(done=done[-40:])
            return 200, {"done": done}
        if path == "/api/respond/sites":
            items = exposure.collect()
            with tripwire.own_reads():
                return 200, {"sites": respond.sites(items)}
        return None


def _stop_when_closed(server):
    """An app window has no terminal to press Ctrl+C in, so the server stops once its page is gone."""
    while True:
        time.sleep(2)
        now = time.time()
        said_bye = server.bye and now - server.bye > 5 and server.seen <= server.bye    # a reload asks again at once
        quiet = now - (server.seen or server.started) > (IDLE_SECONDS if server.seen else START_SECONDS)
        if said_bye or quiet:
            server.shutdown()
            return


def serve(window="tab", path=None, view=None):
    """window: 'app' (its own window), 'tab' (a browser tab) or None (print the address only)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.token = secrets.token_urlsafe(24)
    server.host = f"127.0.0.1:{server.server_address[1]}"
    server.checked, server.bye, server.seen, server.started = None, 0, 0, time.time()
    query = [f"check={quote(os.path.abspath(path), safe='')}"] if path else []
    query += [f"view={quote(view, safe='')}"] if view else []
    url = f"http://{server.host}/{'?' + '&'.join(query) if query else ''}#{server.token}"
    if window == "app" and desktop.open_window(url):
        threading.Thread(target=_stop_when_closed, args=(server,), daemon=True).start()
    else:
        print(f"gotchu is open at {url}\nKeep this window open while you use it. Press Ctrl+C to close.", flush=True)
        if window:
            webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
