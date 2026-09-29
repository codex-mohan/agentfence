"""Local read-only dashboard API and page."""

from __future__ import annotations

import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .core import Engine


def serve(engine: Engine, port: int = 8765, *, demo_since: float | None = None,
          run_state: dict | None = None, on_ready=None) -> None:
    token = secrets.token_urlsafe(24)
    page = (Path(__file__).parent / "dashboard.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlsplit(self.path)
            if path.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
                self.end_headers()
                self.wfile.write(page)
                return
            if self.headers.get("Authorization") != f"Bearer {token}":
                self.send_error(401)
                return
            if path.path == "/api/stats":
                value = engine.stats()
            elif path.path == "/api/events":
                session = parse_qs(path.query).get("session", [None])[0]
                value = engine.events(session=session)
            elif path.path == "/api/coverage":
                from .adapters import CAPABILITIES
                value = dict(CAPABILITIES) | {
                    "limits": ["Subprocess effects are not OS-contained", "Unmapped MCP tools are denied", "Laya is an optional semantic signal"],
                }
            elif path.path == "/api/config":
                config = engine.config
                value = {"workspace": config["workspace"], "filesystem": config["filesystem"],
                         "network": config["network"], "execution": config["execution"],
                         "session": config["session"], "laya": config["laya"]}
            elif path.path == "/api/evaluations":
                from .evaluation import latest
                value = latest(engine)
            elif path.path == "/api/provenance":
                with engine._lock:
                    rows = engine.db.execute("SELECT path,trust,source_session,updated_ts FROM file_labels ORDER BY updated_ts DESC LIMIT 100").fetchall()
                value = [{"file": Path(row["path"]).name, "trust": row["trust"],
                          "source_session": row["source_session"], "updated_ts": row["updated_ts"]} for row in rows]
            elif path.path == "/api/demo":
                with engine._lock:
                    if demo_since is None:
                        row = engine.db.execute("""SELECT session FROM events
                            WHERE findings LIKE '%laya_scored%' ORDER BY ts DESC LIMIT 1""").fetchone()
                    else:
                        row = engine.db.execute("""SELECT session FROM events
                            WHERE hook = 'session.start' AND ts >= ? ORDER BY ts DESC LIMIT 1""",
                            (demo_since,)).fetchone()
                session = row["session"] if row else None
                events = list(reversed(engine.events(session=session, limit=100))) if session else []
                scored = [event for event in events if event["score"] is not None]
                blocked = [event for event in events if event["rule"] == "laya_finding"
                           and event["verdict"] == "deny"]
                source = engine.workspace / "src" / "login.py"
                fixed = source.exists() and "return bool(password)" in source.read_text(encoding="utf-8")
                value = {"session": session, "events": events, "score": scored[-1]["score"] if scored else None,
                         "threshold": engine.config["laya"]["threshold"],
                         "laya_blocked": bool(blocked), "legitimate_fix_completed": fixed,
                         "backend": engine.config["laya"]["backend"], "mode": engine.config["laya"]["mode"],
                         "run_status": (run_state or {}).get("status", "historical"),
                         "run_message": (run_state or {}).get("message", "")}
            else:
                self.send_error(404)
                return
            payload = json.dumps(value).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"AgentFence dashboard: http://127.0.0.1:{port}/?token={token}", flush=True)
    try:
        if on_ready:
            on_ready()
        server.serve_forever()
    finally:
        server.server_close()
