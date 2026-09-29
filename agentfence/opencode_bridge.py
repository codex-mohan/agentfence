"""Long-lived JSON-line policy bridge for an OpenCode plugin.

Only the plugin may write to this process's stdin. The bridge does not execute
tools; it decides whether the host may execute them and inspects returned text.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .core import Action, Engine


def map_action(engine: Engine, tool: str, arguments: dict) -> Action | None:
    if not isinstance(arguments, dict):
        return None
    path = arguments.get("path")
    if tool in {"read", "edit", "write"} and isinstance(path, str):
        target = str((engine.workspace / path).resolve())
        return Action("file.read" if tool == "read" else "file.write", target,
                      arguments=arguments, source="opencode")
    # Broad shell, patch, search, and third-party tools require a future trusted
    # effect mapping. Failing closed is safer than guessing their capabilities.
    return None


def handle(engine: Engine, request: dict) -> dict:
    event = request.get("event")
    session = str(request.get("session") or "opencode-unknown")
    if event == "session.start":
        engine.observe("session.start", session)
        return {"verdict": "observe"}
    if event == "turn.before":
        decision = engine.decide("turn.before", session,
                                 Action("turn.input", text=str(request.get("text") or ""), source="opencode"))
        return _result(decision)
    if event == "turn.after":
        engine.observe("turn.after", session)
        return {"verdict": "observe"}
    tool = str(request.get("tool") or "")
    arguments = request.get("input") or {}
    action = map_action(engine, tool, arguments)
    if event == "tool.before":
        if action is None:
            engine.observe("tool.before", session, Action("unmapped.tool", tool, source="opencode"),
                           reason="Tool has no trusted effect mapping")
            return {"verdict": "deny", "rule": "unmapped_tool", "reason": "Tool has no trusted effect mapping"}
        return _result(engine.decide("tool.before", session, action))
    if event == "tool.after":
        if action is None:
            return {"verdict": "deny", "rule": "unmapped_tool", "reason": "Tool has no trusted effect mapping"}
        status = request.get("status")
        engine.record_outcome(session, action, "executed" if status == "completed" else "failed")
        if status != "completed":
            return {"verdict": "observe"}
        if action.kind == "file.write":
            content = arguments.get("content")
            if isinstance(content, str):
                engine.note_write(session, Path(action.resource), content)
            return {"verdict": "allow"}
        output = str(request.get("output") or "")
        if not output:
            return {"verdict": "allow"}
        label = engine.file_label(action.resource)
        source = "scan_ignored" if engine.is_scan_ignored(action.resource) else (label["trust"] if label else "file.read")
        decision = engine.decide("tool.after", session,
                                 Action("context.ingest", resource=action.resource, text=output, source=source))
        if decision.allowed:
            engine.mark_untrusted_seen(session)
        return _result(decision)
    return {"verdict": "deny", "rule": "unknown_event", "reason": "Unknown bridge event"}


def _result(decision) -> dict:
    return {"verdict": decision.verdict, "rule": decision.rule,
            "reason": decision.reason, "score": decision.score,
            "findings": list(decision.findings), "event_id": decision.event_id}


def serve(engine: Engine) -> None:
    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = handle(engine, request)
        except Exception as exc:
            response = {"verdict": "deny", "rule": "bridge_error", "reason": type(exc).__name__}
        print(json.dumps(response), flush=True)
