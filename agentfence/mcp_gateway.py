"""Strict local stdio MCP gateway for mapped tools.

The gateway intentionally supports a bounded protocol surface. Unsupported operations
are returned as errors rather than passed through with a false protection claim.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
import uuid

from .core import Action, Engine
from .adapters import map_tool


class Gateway:
    def __init__(self, engine: Engine, command: list[str], client_in=None, client_out=None):
        if not command:
            raise ValueError("An upstream MCP command is required")
        self.engine = engine
        self.command = command
        self.client_in = client_in or sys.stdin
        self.client_out = client_out or sys.stdout
        self.session = str(uuid.uuid4())
        self.pending: dict[str, tuple[str, Action | None]] = {}
        self.tool_hashes: dict[str, str] = {}
        self._write_lock = threading.Lock()
        self._pending_lock = threading.Lock()

    def _emit(self, message: dict) -> None:
        with self._write_lock:
            self.client_out.write(json.dumps(message, separators=(",", ":")) + "\n")
            self.client_out.flush()

    def _error(self, request: dict, reason: str) -> None:
        if "id" in request:
            self._emit({"jsonrpc": "2.0", "id": request["id"],
                        "error": {"code": -32001, "message": reason}})

    def _map(self, params: dict) -> Action | None:
        return map_tool(self.engine.config, params.get("name"), params.get("arguments") or {}, "mcp")

    def _from_client(self, proc: subprocess.Popen) -> None:
        for line in self.client_in:
            if len(line) > 4_000_000:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            method = message.get("method", "")
            if method not in {"initialize", "notifications/initialized", "ping", "tools/list", "tools/call"}:
                self._error(message, f"Unsupported MCP method: {method}")
                continue
            if method == "tools/call":
                action = self._map(message.get("params") or {})
                if action is None:
                    self._error(message, "Tool has no trusted effect mapping")
                    continue
                decision = self.engine.decide("tool.before", self.session, action)
                if not decision.allowed:
                    self._error(message, f"AgentFence {decision.verdict}: {decision.rule}: {decision.reason}")
                    continue
                with self._pending_lock:
                    self.pending[str(message.get("id"))] = ("tools/call", action)
            elif method == "tools/list":
                with self._pending_lock:
                    self.pending[str(message.get("id"))] = ("tools/list", None)
            proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            proc.stdin.flush()
        proc.stdin.close()

    def _from_server(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:
            if len(line) > 4_000_000:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "method" in message and "id" in message:
                response = {"jsonrpc": "2.0", "id": message["id"],
                            "error": {"code": -32601, "message": "Client requests unsupported by AgentFence gateway"}}
                proc.stdin.write(json.dumps(response) + "\n")
                proc.stdin.flush()
                continue
            with self._pending_lock:
                pending = self.pending.pop(str(message.get("id")), None)
            if pending:
                kind, action = pending
                if kind == "tools/list" and "result" in message:
                    tools = message["result"].get("tools", [])
                    changed = False
                    for tool in tools:
                        name = tool.get("name", "")
                        digest = hashlib.sha256(json.dumps(tool, sort_keys=True).encode()).hexdigest()
                        previous = self.tool_hashes.get(name)
                        if previous and previous != digest:
                            changed = True
                        else:
                            self.tool_hashes[name] = digest
                    if changed:
                        self._error(message, "MCP tool definition changed during this gateway session")
                        continue
                    descriptions = "\n".join(str(tool.get("description", "")) for tool in tools)
                    if descriptions:
                        decision = self.engine.decide("context.before", self.session,
                                                      Action("context.ingest", text=descriptions, source="mcp.tools/list"))
                        if not decision.allowed:
                            self._error(message, f"Tool metadata withheld: {decision.rule}")
                            continue
                if kind == "tools/call" and action is not None:
                    outcome = "uncertain" if "error" in message or message.get("result", {}).get("isError") else "executed"
                    self.engine.record_outcome(self.session, action, outcome)
                    if "result" in message:
                        contents = message["result"].get("content", [])
                        texts = [item.get("text", "") for item in contents if isinstance(item, dict) and item.get("type") == "text"]
                        if texts:
                            decision = self.engine.decide("tool.after", self.session,
                                Action("context.ingest", text="\n".join(texts), source="mcp.tools/call"))
                            if not decision.allowed:
                                self._error(message, f"Tool result withheld: {decision.rule}")
                                continue
            self._emit(message)

    def run(self) -> int:
        self.engine.observe("session.start", self.session)
        proc = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=sys.stderr, text=True, encoding="utf-8", bufsize=1)
        incoming = threading.Thread(target=self._from_client, args=(proc,), daemon=True)
        incoming.start()
        try:
            self._from_server(proc)
            return proc.wait(timeout=5)
        finally:
            with self._pending_lock:
                outstanding = list(self.pending.values())
                self.pending.clear()
            for kind, action in outstanding:
                if kind == "tools/call" and action is not None:
                    self.engine.record_outcome(self.session, action, "uncertain", reason="Upstream ended before response")
            self.engine.observe("session.end", self.session)
            if proc.poll() is None:
                proc.terminate()
            if proc.stdout:
                proc.stdout.close()
