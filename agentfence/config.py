"""Trusted operator configuration. Project content must not modify this file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULTS: dict[str, Any] = {
    "version": 1,
    "workspace": ".",
    "database": ".agentfence/events.sqlite3",
    "filesystem": {
        "read_roots": ["."],
        "write_roots": ["."],
        "deny_read": [".env", ".env.*", "*.pem", "*.key", "**/credentials/**", "**/.agentfence/**"],
        "deny_write": [".env", ".env.*", "*.pem", "*.key", "**/.git/**", "**/.agentfence/**"],
        "allow_read_exceptions": [".env.example"],
        "allow_write_exceptions": [],
        "scan_ignore": ["**/node_modules/**", "**/.git/**"],
        "sensitive": [".env", ".env.*", "*.pem", "*.key", "**/credentials/**"],
    },
    "network": {"allowed_hosts": [], "allowed_schemes": ["https"], "allowed_ports": [443], "deny_private": True},
    "execution": {"allowed_programs": [], "allowed_argv": [], "pass_env": ["PATH", "SystemRoot", "TEMP", "TMP", "USERPROFILE", "HOME"], "deny_shells": True, "timeout_seconds": 15},
    "mcp": {"tool_rules": {}},
    "session": {"max_actions": 100, "repeat_limit": 5, "deny_network_after_sensitive_read": True},
    "laya": {
        "enabled": False,
        "backend": "local",
        "mode": "shadow",
        "model": "english",
        "device": "auto",
        "timeout_seconds": 3,
        "max_chars": 12000,
        "inspect_paths": [],
        "hooks": {"context.before": True, "tool.after": True, "model.after": False, "output.before": False},
        "threshold": 0.85,
        "on_finding": "require_approval",
        "on_error": "require_approval",
    },
}


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    config = json.loads(json.dumps(DEFAULTS))
    if path:
        file_path = Path(path).resolve()
        incoming = json.loads(file_path.read_text(encoding="utf-8"))
        if not isinstance(incoming, dict):
            raise ValueError("Configuration must be a JSON object")
        _merge(config, incoming)
        base = file_path.parent
    else:
        base = Path.cwd()
    workspace = (base / config["workspace"]).resolve()
    config["workspace"] = str(workspace)
    config["database"] = str((base / config["database"]).resolve())
    _validate(config)
    return config


def _merge(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    for key, value in incoming.items():
        if key not in target:
            raise ValueError(f"Unknown configuration key: {key}")
        if key == "tool_rules" and isinstance(target[key], dict):
            if not isinstance(value, dict):
                raise ValueError("tool_rules must be an object")
            target[key] = value
        elif isinstance(target[key], dict):
            if not isinstance(value, dict):
                raise ValueError(f"{key} must be an object")
            _merge(target[key], value)
        elif type(value) is not type(target[key]):
            raise ValueError(f"Wrong type for {key}")
        else:
            target[key] = value


def _validate(config: dict[str, Any]) -> None:
    if config["version"] != 1:
        raise ValueError("Unsupported configuration version")
    model = config["laya"]
    if model["backend"] not in {"local", "space_demo"}:
        raise ValueError("Invalid Laya backend")
    if model["backend"] == "space_demo" and model["model"] != "english":
        raise ValueError("The public Laya demo exposes only its English guard")
    if model["mode"] not in {"shadow", "enforce"}:
        raise ValueError("Invalid Laya mode")
    if model["on_finding"] not in {"deny", "require_approval"}:
        raise ValueError("Invalid Laya finding decision")
    if model["on_error"] not in {"deny", "require_approval"}:
        raise ValueError("Invalid Laya error decision")
    if not 0 <= model["threshold"] <= 1:
        raise ValueError("Laya threshold must be between 0 and 1")
    if model["timeout_seconds"] <= 0 or model["max_chars"] <= 0:
        raise ValueError("Invalid Laya resource limit")
    if not all(isinstance(pattern, str) for pattern in model["inspect_paths"]):
        raise ValueError("Laya inspect_paths must be path patterns")
    for hook in model["hooks"]:
        if hook not in {"context.before", "tool.after", "model.after", "output.before"}:
            raise ValueError(f"Unsupported Laya hook: {hook}")
    if config["session"]["max_actions"] < 1 or config["session"]["repeat_limit"] < 1:
        raise ValueError("Session limits must be positive")
    if any(not isinstance(item, list) or not item or not all(isinstance(part, str) for part in item)
           for item in config["execution"]["allowed_argv"]):
        raise ValueError("Execution allowed_argv entries must be nonempty string lists")
    if any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
           for port in config["network"]["allowed_ports"]):
        raise ValueError("Network ports must be integers between 1 and 65535")
    if any(scheme not in {"http", "https"} for scheme in config["network"]["allowed_schemes"]):
        raise ValueError("Only HTTP and HTTPS are supported")
    for name, rule in config["mcp"]["tool_rules"].items():
        if not isinstance(name, str) or not isinstance(rule, dict):
            raise ValueError("Invalid MCP tool rule")
        if set(rule) != {"kind", "resource_arg"} or rule["kind"] not in {"file.read", "file.write", "network.send", "process.execute"}:
            raise ValueError(f"Invalid MCP mapping for {name}")
