"""The gotchu window: a page served only to this PC, opened in the user's browser.

Safety of the server itself:
  - listens on 127.0.0.1 only, on a random port;
  - every action needs a one-time token that only the opened page knows, so no
    other website can ask it to do anything;
  - the Host header must match, which blocks DNS-rebinding tricks.
"""
import hmac
import json
import os
import secrets
import subprocess
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

from . import __version__, check, exposure, harden, report, scan, tripwire

HERE = os.path.dirname(__file__)
WORTH_CHECKING = {".zip", ".7z", ".rar", ".iso", ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk",
                  ".scr", ".jar", ".hta", ".img", ".vhd", ".vhdx"}


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
    cmd = ["powershell.exe", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File",
           os.path.join(HERE, "browse.ps1")] + (["-Folder"] if folder else [])
    out = subprocess.run(cmd, capture_output=True, timeout=600)
    return out.stdout.decode("utf-8", "replace").strip()


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
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _allowed(self):
        token = self.headers.get("X-GotchU-Token", "")
        return (self.headers.get("Host") == self.server.host
                and hmac.compare_digest(token, self.server.token))

    def do_GET(self):
        if self.path.split("?")[0] in ("/", "/index.html"):
            with open(os.path.join(HERE, "ui.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if not self._allowed():
            return self._send(403, {"error": "This page was not opened by gotchu. Run 'gotchu ui' again."})
        if self.path == "/api/downloads":
            return self._send(200, {"version": __version__, "downloads": recent_downloads()})
        self._send(404, {"error": "Not found."})

    def do_POST(self):
        if not self._allowed():
            return self._send(403, {"error": "This page was not opened by gotchu. Run 'gotchu ui' again."})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "The request could not be read."})
        try:
            if self.path == "/api/check":
                path = (body.get("path") or "").strip().strip('"')
                if not path or not os.path.exists(path):
                    return self._send(400, {"error": "That file or folder does not exist. Check the path and try again."})
                return self._send(200, check.result(path))
            if self.path == "/api/scan":
                return self._send(200, scan.result())
            if self.path == "/api/exposure":
                return self._send(200, exposure.result())
            if self.path == "/api/tripwire":
                return self._send(200, tripwire.result())
            if self.path == "/api/harden":
                return self._send(200, harden.result())
            if self.path == "/api/harden/change":
                ok, message = harden.change(str(body.get("key")), undo=bool(body.get("undo")))
                return self._send(200, {"ok": ok, "message": message, "result": harden.result()})
            if self.path == "/api/browse":
                return self._send(200, {"path": browse(bool(body.get("folder")))})
        except PermissionError:
            return self._send(400, {"error": "Windows would not let gotchu read that. Try a copy in your Downloads folder."})
        except report.CouldNotRun as e:
            return self._send(500, {"error": str(e)})
        except Exception as e:  # report instead of dropping the connection
            return self._send(500, {"error": f"The check could not finish: {e}"})
        self._send(404, {"error": "Not found."})


def serve(open_browser=True, path=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.token = secrets.token_urlsafe(24)
    server.host = f"127.0.0.1:{server.server_address[1]}"
    start = "?check=" + quote(os.path.abspath(path), safe="") if path else ""
    url = f"http://{server.host}/{start}#{server.token}"
    print(f"gotchu is open at {url}\nKeep this window open while you use it. Press Ctrl+C to close.", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
