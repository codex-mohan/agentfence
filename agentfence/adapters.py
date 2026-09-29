"""Host adapters translate tool calls into the common policy action contract."""

from __future__ import annotations

from .core import Action


CAPABILITIES = {
    "sdk": {"session": "observed", "turn": "gated", "context": "gated", "model": "gated", "tool": "gated", "output": "gated"},
    "mcp": {"tool": "gated for mapped tools", "result": "gated before forwarding text results", "turn": "unsupported", "model": "unsupported"},
    "claude": {"tool": "gated for mapped tools", "turn": "observed", "result": "observed after execution", "model": "unsupported"},
}


def map_tool(config: dict, name: str, arguments: dict, host: str) -> Action | None:
    """Only operator-configured tools get an effect mapping."""
    if not isinstance(arguments, dict):
        return None
    if host == "claude":
        path = arguments.get("file_path")
        if name == "Read" and isinstance(path, str):
            return Action("file.read", path, arguments=arguments, source=host)
        if name in {"Write", "Edit"} and isinstance(path, str):
            return Action("file.write", path, arguments=arguments, source=host)
    rule = config["mcp"]["tool_rules"].get(name)
    if rule is None:
        return None
    resource = arguments.get(rule["resource_arg"])
    if not isinstance(resource, str):
        return None
    return Action(rule["kind"], resource, arguments=arguments, source=host)
