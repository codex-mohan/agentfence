"""Claude Code lifecycle adapter for documented command hooks."""

from __future__ import annotations

import json
import sys
from .core import Action, Engine
from .adapters import map_tool


def handle(engine: Engine, data: dict) -> dict | None:
    event = data.get("hook_event_name", "")
    session = str(data.get("session_id") or "claude-unknown")
    tool = data.get("tool_name", "")
    inp = data.get("tool_input") or {}
    operation = str(data.get("tool_use_id") or "")
    if event == "SessionStart":
        engine.observe("session.start", session)
        return None
    if event == "SessionEnd":
        engine.observe("session.end", session)
        return None
    if event == "UserPromptSubmit":
        engine.observe("turn.before", session, Action("turn.input", source="claude"))
        return None
    if event == "Stop":
        engine.observe("turn.after", session)
        return None
    if event == "PostToolUse":
        action = _action(engine, tool, inp)
        if action:
            engine.record_outcome(session, action, "executed", operation=operation)
        return None
    if event != "PreToolUse":
        return None
    action = _action(engine, tool, inp)
    if action is None:
        verdict, reason = "deny", "Tool has no trusted AgentFence mapping"
    else:
        decision = engine.decide("tool.before", session, action, operation=operation)
        verdict, reason = decision.verdict, f"{decision.rule}: {decision.reason}"
    if verdict == "allow":
        return None  # Preserve Claude's normal permission flow.
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
            "permissionDecision": "ask" if verdict == "require_approval" else "deny",
            "permissionDecisionReason": reason}}


def _action(engine: Engine, tool: str, inp: dict) -> Action | None:
    return map_tool(engine.config, tool, inp, "claude")


def main(engine: Engine) -> None:
    try:
        data = json.load(sys.stdin)
        output = handle(engine, data)
        if output:
            print(json.dumps(output))
    except Exception as exc:
        event = data.get("hook_event_name") if "data" in locals() else ""
        if event == "PreToolUse":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                "permissionDecision": "deny", "permissionDecisionReason": f"AgentFence unavailable: {type(exc).__name__}"}}))
        else:
            print(f"AgentFence hook error: {type(exc).__name__}", file=sys.stderr)
