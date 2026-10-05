"""Generic out-of-band collector for CSPT / CORS-misconfig / open-redirect leaks.

Plain listener: logs whatever hits it and lets your own payload page poll /poll to pick a leaked 
value back up. No target-specific exploit logic here on purpose, see --payload-file. Not for
XSS cookie theft, use a dedicated collector for that (ezXSS, ...)

Quickstart:
    python Collector.py --port 8000
    # point your payload at http://<this host>:8000/collect (or --collect-path)
    # /log for a live view, /poll for the raw JSON feed
"""
import argparse
import json
import threading
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

LOCK = threading.Lock()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, max_captures, log_file):
        self.captures = deque(maxlen=max_captures)
        self.next_id = 1
        self.log_file = Path(log_file) if log_file else None

    def add(self, record):
        with LOCK:
            record["id"] = self.next_id
            self.next_id += 1
            self.captures.append(record)
            if self.log_file:
                with self.log_file.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def latest(self, n=None):
        with LOCK:
            items = list(self.captures)
        if n:
            items = items[-n:]
        return items


LOG_PAGE = """<!doctype html><meta charset=utf-8><title>collector log</title>
<style>
body{font-family:monospace;background:#111;color:#ddd;padding:1em}
table{width:100%;border-collapse:collapse}
td,th{border-bottom:1px solid #333;padding:4px 8px;text-align:left;vertical-align:top}
th{color:#8f8}
.empty{color:#666}
</style>
<h3>collector log (auto-refresh 2s)</h3>
<table id=t><tr><th>#</th><th>time</th><th>from</th><th>method</th><th>path</th>
<th>captured</th></tr></table>
<script>
async function tick(){
  const r = await fetch('/poll?n=200');
  const data = await r.json();
  const rows = data.captures.map(c => `<tr>
    <td>${c.id}</td><td>${c.timestamp}</td><td>${c.remote_addr}</td>
    <td>${c.method}</td><td>${c.path}</td>
    <td><pre style="margin:0">${JSON.stringify(c.captured, null, 0)}</pre></td>
  </tr>`).reverse().join('');
  document.getElementById('t').innerHTML =
    '<tr><th>#</th><th>time</th><th>from</th><th>method</th><th>path</th><th>captured</th></tr>'
    + (rows || '<tr><td class=empty colspan=6>no captures yet</td></tr>');
}
tick(); setInterval(tick, 2000);
</script>
"""

DEFAULT_INDEX = """<!doctype html><meta charset=utf-8><title>.</title>
<p>Generic collector is running. Nothing to see at / by default.</p>
<p>Capture endpoint: configured via --collect-path. Live view: /log. JSON feed: /poll.</p>
"""


def make_handler(store: Store, args):
    class Handler(BaseHTTPRequestHandler):
        server_version = "collector/1.0"

        def log_message(self, fmt, *a):
            print("[*]", fmt % a, flush=True)

        def _cors_headers(self):
            origin = self.headers.get("Origin")
            allowed = args.cors_origin or origin or "*"
            self.send_header("Access-Control-Allow-Origin", allowed)
            if args.allow_credentials and allowed != "*":
                self.send_header("Access-Control-Allow-Credentials", "true")
            req_headers = self.headers.get("Access-Control-Request-Headers")
            self.send_header("Access-Control-Allow-Headers", req_headers or "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

        def _send(self, status, content_type, body: bytes, extra_cors=False):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if extra_cors:
                self._cors_headers()
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors_headers()
            self.end_headers()

        def _capture(self, method):
            parts = urlsplit(self.path)
            query = {k: v[0] for k, v in parse_qs(parts.query).items()}
            body = ""
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                raw = self.rfile.read(length)
                try:
                    body = raw.decode("utf-8", errors="replace")
                except Exception:
                    body = repr(raw)

            headers = {k: v for k, v in self.headers.items()}
            captured = {}
            for name in args.capture_header:
                val = self.headers.get(name)
                if val is not None:
                    captured[f"header:{name}"] = val
            for name in args.capture_param:
                if name in query:
                    captured[f"param:{name}"] = query[name]
            if not args.capture_header and not args.capture_param:
                # No explicit fields configured: keep everything, useful while you are
                # still figuring out which header/param actually carries the value.
                captured = {"query": query, "body": body[:2000]}

            record = {
                "timestamp": now_iso(),
                "remote_addr": self.client_address[0],
                "method": method,
                "path": parts.path,
                "origin": self.headers.get("Origin"),
                "headers": headers,
                "query": query,
                "body": body[:2000],
                "captured": captured,
            }
            store.add(record)
            print(f"[+] capture #{record.get('id')} from {record['remote_addr']} "
                  f"{method} {parts.path} -> {captured}", flush=True)

        def do_GET(self):
            parts = urlsplit(self.path)

            if parts.path == args.collect_path:
                self._capture("GET")
                self._send(200, "text/plain", b"ok", extra_cors=True)
                return

            if parts.path == "/poll":
                n = parse_qs(parts.query).get("n", [None])[0]
                items = store.latest(int(n) if n else None)
                body = json.dumps({"captures": items}, ensure_ascii=False).encode()
                self._send(200, "application/json", body, extra_cors=True)
                return

            if parts.path == "/log":
                self._send(200, "text/html; charset=utf-8", LOG_PAGE.encode())
                return

            if parts.path in ("/", ""):
                if args.payload_file:
                    body = Path(args.payload_file).read_bytes()
                else:
                    body = DEFAULT_INDEX.encode()
                self._send(200, "text/html; charset=utf-8", body)
                return

            self._send(404, "text/plain", b"not found")

        def do_POST(self):
            parts = urlsplit(self.path)
            if parts.path == args.collect_path:
                self._capture("POST")
                self._send(200, "text/plain", b"ok", extra_cors=True)
                return
            self._send(404, "text/plain", b"not found")

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--collect-path", default="/collect",
                     help="Path your payload sends leaked data to (default: /collect)")
    ap.add_argument("--payload-file", help="HTML/JS file to serve at / (your exploit page)")
    ap.add_argument("--log-file", help="Append every capture as JSON lines to this file")
    ap.add_argument("--max-captures", type=int, default=500,
                     help="In-memory ring buffer size (default: 500)")
    ap.add_argument("--cors-origin",
                     help="Fixed Access-Control-Allow-Origin value. Default: reflect the "
                          "request's own Origin header (needed when the leak only works "
                          "with credentials, since '*' cannot be combined with "
                          "Allow-Credentials)")
    ap.add_argument("--allow-credentials", action="store_true",
                     help="Send Access-Control-Allow-Credentials: true")
    ap.add_argument("--capture-header", action="append", default=[],
                     help="Header name to pull out into 'captured' (repeatable), "
                          "e.g. --capture-header X-CSRF-Token")
    ap.add_argument("--capture-param", action="append", default=[],
                     help="Query param name to pull out into 'captured' (repeatable), "
                          "e.g. --capture-param token")
    args = ap.parse_args()

    store = Store(args.max_captures, args.log_file)
    handler = make_handler(store, args)

    print(f"[*] collector listening on {args.host}:{args.port}", flush=True)
    print(f"[*] collect endpoint: /{args.collect_path.lstrip('/')}", flush=True)
    print(f"[*] live view:        http://{args.host}:{args.port}/log", flush=True)
    print(f"[*] json feed:        http://{args.host}:{args.port}/poll", flush=True)
    if args.log_file:
        print(f"[*] persisting captures to {args.log_file}", flush=True)

    ThreadingHTTPServer((args.host, args.port), handler).serve_forever()


if __name__ == "__main__":
    main()
