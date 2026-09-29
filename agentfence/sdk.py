"""Execution wrappers. Callers must use these wrappers for enforcement."""

from __future__ import annotations

import subprocess
import os
import socket
import ipaddress
import uuid
from pathlib import Path
from urllib import request
from urllib.parse import urlsplit

from .core import Action, Decision, Engine


class Blocked(PermissionError):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"{decision.verdict}: {decision.rule}: {decision.reason}")


class Guard:
    def __init__(self, engine: Engine, session: str | None = None):
        self.engine = engine
        self.session = session or str(uuid.uuid4())
        self.turn = ""
        self.engine.observe("session.start", self.session)

    def close(self) -> None:
        self.engine.observe("session.end", self.session, turn=self.turn)

    def begin_turn(self, text: str = "") -> None:
        self.turn = str(uuid.uuid4())
        self._check("turn.before", Action("turn.input", text=text))

    def end_turn(self) -> None:
        self.engine.observe("turn.after", self.session, turn=self.turn)

    def ingest(self, text: str, source: str = "external") -> str:
        self._check("context.before", Action("context.ingest", text=text, source=source))
        if source != "trusted.operator":
            self.engine.mark_untrusted_seen(self.session)
        return text

    def model_request(self, text: str = "") -> None:
        self._check("model.before", Action("model.request", text=text))

    def model_response(self, text: str = "") -> None:
        self._check("model.after", Action("model.response", text=text))

    def release_output(self, text: str) -> str:
        self._check("output.before", Action("output.release", text=text))
        return text

    def _check(self, hook: str, action: Action, operation: str = "") -> Decision:
        decision = self.engine.decide(hook, self.session, action, turn=self.turn, operation=operation)
        if not decision.allowed:
            raise Blocked(decision)
        return decision

    def run(self, action: Action, invoke):
        operation = str(uuid.uuid4())
        self._check("tool.before", action, operation)
        try:
            result = invoke()
            self.engine.record_outcome(self.session, action, "executed", turn=self.turn, operation=operation)
            texts = []
            if isinstance(result, str):
                texts = [result]
            elif isinstance(result, bytes):
                texts = [result.decode("utf-8", errors="replace")]
            elif isinstance(result, subprocess.CompletedProcess):
                texts = [str(result.stdout or ""), str(result.stderr or "")]
            for output in texts:
                if not output:
                    continue
                label = self.engine.file_label(action.resource) if action.kind == "file.read" else None
                ignored = action.kind == "file.read" and self.engine.is_scan_ignored(action.resource)
                source = "scan_ignored" if ignored else (label["trust"] if label else action.kind)
                self._check("tool.after", Action("context.ingest", text=output, source=source), operation)
                self.engine.mark_untrusted_seen(self.session)
            return result
        except Blocked:
            raise
        except Exception as exc:
            self.engine.record_outcome(self.session, action, "failed", turn=self.turn,
                                       operation=operation, reason=type(exc).__name__)
            raise

    def read_text(self, path: str | Path) -> str:
        target = (self.engine.workspace / path).resolve()
        action = Action("file.read", str(target))
        return self.run(action, lambda: target.read_text(encoding="utf-8"))

    def write_text(self, path: str | Path, content: str) -> None:
        target = (self.engine.workspace / path).resolve()
        action = Action("file.write", str(target))
        self.run(action, lambda: target.write_text(content, encoding="utf-8"))
        self.engine.note_write(self.session, target, content)

    def execute(self, argv: list[str], cwd: str | Path | None = None) -> subprocess.CompletedProcess:
        if not argv:
            raise ValueError("Command requires an executable")
        working_dir = Path(cwd or self.engine.workspace).resolve()
        action = Action("process.execute", argv[0], arguments={"argv": argv, "cwd": str(working_dir)})
        timeout = self.engine.config["execution"]["timeout_seconds"]
        allowed_env = {key.casefold() for key in self.engine.config["execution"]["pass_env"]}
        child_env = {key: value for key, value in os.environ.items() if key.casefold() in allowed_env}
        return self.run(action, lambda: subprocess.run(argv, cwd=working_dir, env=child_env,
                                                        capture_output=True, text=True,
                                                        timeout=timeout, check=False))

    def send(self, url: str, data: bytes) -> bytes:
        action = Action("network.send", url)
        def invoke() -> bytes:
            parsed = urlsplit(url)
            addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
            if not addresses or (self.engine.config["network"]["deny_private"] and
                                 any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses)):
                raise PermissionError("Resolved destination is private or unavailable")
            class NoRedirect(request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    raise PermissionError("Redirects require a new policy decision")
            req = request.Request(url, data=data, method="POST")
            with request.build_opener(NoRedirect()).open(req, timeout=10) as response:
                return response.read(1024 * 1024)
        return self.run(action, invoke)
