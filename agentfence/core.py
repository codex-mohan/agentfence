"""Shared lifecycle, policy, and durable telemetry core."""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .config import load_config


HOOKS = {
    "session.start", "session.end", "turn.before", "turn.after", "context.before",
    "model.before", "model.after", "tool.before", "tool.after", "output.before",
    "operation.error", "operation.cancelled",
}


@dataclass(frozen=True)
class Action:
    kind: str
    resource: str = ""
    text: str = ""
    arguments: dict = field(default_factory=dict)
    source: str = "sdk"


@dataclass(frozen=True)
class Decision:
    verdict: str
    rule: str
    reason: str
    event_id: str
    findings: tuple[str, ...] = ()
    score: float | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


def _matches(relative: str, patterns: list[str]) -> bool:
    name = relative.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(relative.lower(), p.lower()) or
               fnmatch.fnmatchcase(name.lower(), p.lower()) or
               (p.startswith("**/") and fnmatch.fnmatchcase(relative.lower(), p[3:].lower()))
               for p in patterns)


class Engine:
    """One policy implementation shared by SDK, hooks, gateway and harnesses."""

    def __init__(self, config: dict | None = None, detector=None):
        self.config = config or load_config()
        self.detector = detector
        self.workspace = Path(self.config["workspace"]).resolve()
        db = Path(self.config["database"])
        db.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(db), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self.db:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("""CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, ts REAL NOT NULL, session TEXT NOT NULL,
                turn TEXT, operation TEXT, hook TEXT NOT NULL, action TEXT,
                resource TEXT, verdict TEXT, rule TEXT, reason TEXT,
                duration_ms REAL, findings TEXT NOT NULL DEFAULT '[]', score REAL
            )""")
            if "score" not in {row["name"] for row in self.db.execute("PRAGMA table_info(events)")}:
                self.db.execute("ALTER TABLE events ADD COLUMN score REAL")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session, ts)")
            self.db.execute("""CREATE TABLE IF NOT EXISTS session_state (
                session TEXT PRIMARY KEY, untrusted_seen INTEGER NOT NULL DEFAULT 0
            )""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS file_labels (
                path TEXT PRIMARY KEY, trust TEXT NOT NULL, content_hash TEXT NOT NULL,
                source_session TEXT NOT NULL, updated_ts REAL NOT NULL
            )""")

    def close(self) -> None:
        with self._lock:
            self.db.close()

    def _record(self, *, session: str, hook: str, action: Action | None = None,
                verdict: str = "observe", rule: str = "", reason: str = "",
                turn: str = "", operation: str = "", findings: tuple[str, ...] = (),
                duration_ms: float | None = None, score: float | None = None) -> str:
        event_id = str(uuid.uuid4())
        resource = self._display_resource(action) if action else ""
        with self._lock, self.db:
            self.db.execute("""INSERT INTO events
                (id,ts,session,turn,operation,hook,action,resource,verdict,rule,reason,duration_ms,findings,score)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event_id, time.time(), session, turn, operation, hook,
                 action.kind if action else "", resource, verdict, rule, reason,
                 duration_ms, json.dumps(findings), score))
        return event_id

    def _display_resource(self, action: Action) -> str:
        if action.kind.startswith("file."):
            return Path(action.resource).name
        if action.kind == "network.send":
            return (urlsplit(action.resource).hostname or "").lower()
        if action.kind == "process.execute":
            return Path(action.resource).name
        if action.kind == "context.ingest" and action.resource:
            return Path(action.resource).name
        return action.resource[:120]

    def observe(self, hook: str, session: str, action: Action | None = None,
                *, turn: str = "", operation: str = "", reason: str = "") -> str:
        if hook not in HOOKS:
            raise ValueError(f"Unknown hook: {hook}")
        return self._record(session=session, hook=hook, action=action, turn=turn,
                            operation=operation, reason=reason)

    def decide(self, hook: str, session: str, action: Action,
               *, turn: str = "", operation: str = "") -> Decision:
        # Serialize the check and reservation record. A concurrent call must see
        # the first call's budget use before it can make its own decision.
        with self._lock:
            return self._decide_locked(hook, session, action, turn=turn, operation=operation)

    def _decide_locked(self, hook: str, session: str, action: Action,
                       *, turn: str = "", operation: str = "") -> Decision:
        if hook not in {"turn.before", "context.before", "model.before", "model.after", "tool.before", "tool.after", "output.before"}:
            raise ValueError(f"Hook cannot gate an action: {hook}")
        start = time.perf_counter()
        verdict, rule, reason = self._rules(session, action)
        findings: tuple[str, ...] = ()
        score: float | None = None
        laya = self.config["laya"]
        scoped_out = False
        if hook == "tool.after" and action.resource and laya["inspect_paths"]:
            target = Path(action.resource).resolve()
            relative = (target.relative_to(self.workspace).as_posix()
                        if target.is_relative_to(self.workspace) else target.as_posix())
            scoped_out = not _matches(relative, laya["inspect_paths"])
        if hook == "tool.after" and action.source == "scan_ignored":
            findings = ("inspection_skipped_by_policy",)
            if laya["enabled"] and laya["mode"] == "enforce" and verdict == "allow":
                verdict, rule, reason = "require_approval", "inspection_required", "Ignored content needs review in enforcement mode"
        elif scoped_out:
            findings = ("inspection_out_of_scope",)
        elif laya["enabled"] and laya["hooks"].get(hook, False) and action.text:
            if len(action.text) > laya["max_chars"]:
                findings = ("inspection_incomplete",)
                if laya["mode"] == "enforce" and verdict == "allow":
                    verdict, rule, reason = laya["on_error"], "laya_incomplete", "Content exceeds inspection budget"
            else:
                try:
                    if self.detector is None:
                        from .laya_provider import LayaProvider
                        self.detector = LayaProvider(laya)
                    score = self.detector.score(action.text)
                    findings = ("laya_scored",)
                    if score >= laya["threshold"]:
                        findings = ("laya_scored", "possible_instruction_injection")
                        if laya["mode"] == "enforce" and verdict == "allow":
                            verdict, rule, reason = laya["on_finding"], "laya_finding", "Potential instruction injection"
                except Exception as exc:
                    findings = ("detector_unavailable",)
                    if laya["mode"] == "enforce" and verdict == "allow":
                        verdict, rule, reason = laya["on_error"], "laya_error", f"Detector unavailable: {type(exc).__name__}"
        elapsed = (time.perf_counter() - start) * 1000
        event_id = self._record(session=session, hook=hook, action=action,
                                verdict=verdict, rule=rule, reason=reason,
                                turn=turn, operation=operation, findings=findings,
                                duration_ms=elapsed, score=score)
        return Decision(verdict, rule, reason, event_id, findings, score)

    def _rules(self, session: str, action: Action) -> tuple[str, str, str]:
        if action.kind.startswith("file."):
            base = self._file_rule(action)
        elif action.kind == "network.send":
            base = self._network_rule(session, action)
        elif action.kind == "process.execute":
            base = self._process_rule(action)
        elif action.kind in {"turn.input", "context.ingest", "model.request", "model.response", "output.release"}:
            base = ("allow", "default", "Allowed by configured scope")
        else:
            base = ("deny", "unknown_action", "Unknown action requires a trusted mapping")
        if base[0] == "deny":
            return base
        if action.kind in {"file.read", "file.write", "network.send", "process.execute"}:
            with self._lock:
                row = self.db.execute("SELECT COUNT(*) AS n FROM events WHERE session=? AND hook='tool.before'", (session,)).fetchone()
                if row["n"] >= self.config["session"]["max_actions"]:
                    return "deny", "action_budget", "Session action budget exhausted"
                recent = self.db.execute("""SELECT COUNT(*) AS n FROM events WHERE session=? AND hook='tool.before'
                    AND action=? AND resource=?""", (session, action.kind, self._display_resource(action))).fetchone()
                if recent["n"] >= self.config["session"]["repeat_limit"] and base[0] == "allow":
                    return "require_approval", "repeat_limit", "Repeated operation needs review"
        return base

    def _file_rule(self, action: Action) -> tuple[str, str, str]:
        is_write = action.kind in {"file.write", "file.delete", "file.create"}
        if action.kind not in {"file.read", "file.write", "file.delete", "file.create"}:
            return "deny", "unknown_file_operation", "Unsupported filesystem operation"
        requested = Path(action.resource)
        resolved = (self.workspace / requested).resolve() if not requested.is_absolute() else requested.resolve()
        fs = self.config["filesystem"]
        roots_key = "write_roots" if is_write else "read_roots"
        roots = [(self.workspace / root).resolve() for root in fs[roots_key]]
        if not any(resolved == root or root in resolved.parents for root in roots):
            return "deny", "outside_allowed_root", "Path outside permitted roots"
        relative = resolved.relative_to(self.workspace).as_posix() if resolved.is_relative_to(self.workspace) else resolved.as_posix()
        requested_string = requested.as_posix()
        deny_key = "deny_write" if is_write else "deny_read"
        except_key = "allow_write_exceptions" if is_write else "allow_read_exceptions"
        if (_matches(relative, fs[deny_key]) or _matches(requested_string, fs[deny_key])) and not _matches(relative, fs[except_key]):
            return "deny", "protected_path", "Path matches a protected file pattern"
        return "allow", "file_scope", "Path permitted by filesystem policy"

    def _network_rule(self, session: str, action: Action) -> tuple[str, str, str]:
        try:
            parsed = urlsplit(action.resource)
            _ = parsed.port
        except ValueError:
            return "deny", "invalid_destination", "Malformed network destination"
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return "deny", "invalid_destination", "Unsupported or ambiguous network destination"
        if parsed.scheme not in self.config["network"]["allowed_schemes"]:
            return "deny", "unapproved_scheme", "Network scheme is not allowlisted"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in self.config["network"]["allowed_ports"]:
            return "deny", "unapproved_port", "Network port is not allowlisted"
        host = parsed.hostname.lower().rstrip(".")
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            if self.config["network"]["deny_private"] and not ip.is_global:
                return "deny", "private_destination", "Private or local destination not permitted"
        except ValueError:
            if host == "localhost" or host.endswith(".localhost"):
                if self.config["network"]["deny_private"]:
                    return "deny", "private_destination", "Local destination not permitted"
        if not _matches(host, self.config["network"]["allowed_hosts"]):
            return "deny", "unapproved_destination", "Destination is not allowlisted"
        if self.config["session"]["deny_network_after_sensitive_read"]:
            with self._lock:
                rows = self.db.execute("""SELECT resource FROM events WHERE session=? AND hook='tool.after'
                    AND action='file.read' AND verdict='executed'""", (session,)).fetchall()
            if any(_matches(row["resource"], self.config["filesystem"]["sensitive"]) for row in rows):
                return "require_approval", "sensitive_to_network", "Session read sensitive data before outbound transfer"
        return "allow", "network_scope", "Destination permitted by network policy"

    def _process_rule(self, action: Action) -> tuple[str, str, str]:
        executable = Path(action.resource).name.lower()
        policy = self.config["execution"]
        if policy["deny_shells"] and executable in {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
            return "deny", "shell_denied", "Shell execution requires a stronger containment policy"
        if not _matches(executable, policy["allowed_programs"]):
            return "deny", "unapproved_program", "Program is not allowlisted"
        argv = action.arguments.get("argv")
        if not isinstance(argv, list) or not argv or Path(str(argv[0])).name.lower() != executable:
            return "deny", "unverified_arguments", "Structured command arguments required"
        normalized = [executable] + [str(part) for part in argv[1:]]
        if normalized not in [[Path(parts[0]).name.lower()] + parts[1:] for parts in policy["allowed_argv"]]:
            return "deny", "unapproved_arguments", "Command arguments are not allowlisted"
        cwd = Path(str(action.arguments.get("cwd") or self.workspace)).resolve()
        if cwd != self.workspace and self.workspace not in cwd.parents:
            return "deny", "outside_working_root", "Process working directory is outside the workspace"
        return "allow", "execution_scope", "Program permitted by execution policy"

    def record_outcome(self, session: str, action: Action, outcome: str,
                       *, turn: str = "", operation: str = "", reason: str = "") -> str:
        if outcome not in {"executed", "failed", "uncertain"}:
            raise ValueError("Invalid execution outcome")
        return self._record(session=session, hook="tool.after", action=action,
                            verdict=outcome, rule="execution_outcome", reason=reason,
                            turn=turn, operation=operation)

    def mark_untrusted_seen(self, session: str) -> None:
        with self._lock, self.db:
            self.db.execute("""INSERT INTO session_state(session,untrusted_seen) VALUES (?,1)
                ON CONFLICT(session) DO UPDATE SET untrusted_seen=1""", (session,))

    def note_write(self, session: str, path: str | Path, content: str) -> None:
        resolved = str(Path(path).resolve())
        with self._lock, self.db:
            row = self.db.execute("SELECT untrusted_seen FROM session_state WHERE session=?", (session,)).fetchone()
            trust = "untrusted-derived" if row and row["untrusted_seen"] else "locally-written"
            self.db.execute("""INSERT INTO file_labels(path,trust,content_hash,source_session,updated_ts)
                VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET trust=excluded.trust,
                content_hash=excluded.content_hash,source_session=excluded.source_session,
                updated_ts=excluded.updated_ts""",
                (resolved, trust, hashlib.sha256(content.encode("utf-8")).hexdigest(), session, time.time()))

    def file_label(self, path: str | Path) -> dict | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM file_labels WHERE path=?", (str(Path(path).resolve()),)).fetchone()
        return dict(row) if row else None

    def is_scan_ignored(self, path: str | Path) -> bool:
        resolved = Path(path).resolve()
        relative = resolved.relative_to(self.workspace).as_posix() if resolved.is_relative_to(self.workspace) else resolved.as_posix()
        return _matches(relative, self.config["filesystem"]["scan_ignore"])

    def stats(self) -> dict:
        with self._lock:
            total = self.db.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
            sessions = self.db.execute("SELECT COUNT(DISTINCT session) AS n FROM events").fetchone()["n"]
            verdicts = {row["verdict"]: row["n"] for row in self.db.execute("SELECT verdict, COUNT(*) AS n FROM events GROUP BY verdict")}
            rules = [{"rule": row["rule"], "count": row["n"]} for row in self.db.execute("SELECT rule, COUNT(*) AS n FROM events WHERE verdict IN ('deny','require_approval') GROUP BY rule ORDER BY n DESC")]
            hooks = [{"hook": row["hook"], "count": row["n"]} for row in self.db.execute("SELECT hook, COUNT(*) AS n FROM events GROUP BY hook ORDER BY n DESC")]
            durations = [row["duration_ms"] for row in self.db.execute("SELECT duration_ms FROM events WHERE duration_ms IS NOT NULL ORDER BY duration_ms")]
            finding_rows = self.db.execute("SELECT findings FROM events WHERE findings!='[]'").fetchall()
        finding_counts: dict[str, int] = {}
        for row in finding_rows:
            for finding in json.loads(row["findings"]):
                finding_counts[finding] = finding_counts.get(finding, 0) + 1
        def percentile(p: float) -> float:
            if not durations:
                return 0.0
            return round(durations[min(len(durations) - 1, int((len(durations) - 1) * p))], 2)
        return {"events": total, "sessions": sessions, "verdicts": verdicts, "rules": rules,
                "hooks": hooks, "findings": finding_counts,
                "latency_ms": {"p50": percentile(.5), "p95": percentile(.95)},
                "laya": {"enabled": self.config["laya"]["enabled"], "mode": self.config["laya"]["mode"],
                         "backend": self.config["laya"]["backend"],
                         "model": self.config["laya"]["model"],
                         "status": ("disabled" if not self.config["laya"]["enabled"] else
                                    "degraded" if finding_counts.get("detector_unavailable", 0) else
                                    "active" if finding_counts.get("laya_scored", 0) else
                                    "ready" if self.detector else "not_loaded"),
                         "scored": finding_counts.get("laya_scored", 0),
                         "errors": finding_counts.get("detector_unavailable", 0)}}

    def events(self, session: str | None = None, limit: int = 100) -> list[dict]:
        with self._lock:
            if session:
                rows = self.db.execute("SELECT * FROM events WHERE session=? ORDER BY ts DESC LIMIT ?", (session, limit)).fetchall()
            else:
                rows = self.db.execute("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) | {"findings": json.loads(row["findings"])} for row in rows]
