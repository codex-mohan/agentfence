"""Scripted policy fixtures. These are not live agent attack-success results."""

from __future__ import annotations

import copy
import json
import tempfile
import time
import uuid
from pathlib import Path

from .config import DEFAULTS
from .core import Action, Engine
from .sdk import Blocked, Guard


SCENARIOS = Path(__file__).resolve().parent / "scenarios.json"


def _table(engine: Engine) -> None:
    with engine._lock, engine.db:
        engine.db.execute("""CREATE TABLE IF NOT EXISTS evaluations (
            run_id TEXT, ts REAL, mode TEXT, scenario_id TEXT, family TEXT,
            attack INTEGER, verdict TEXT, effect_executed INTEGER, PRIMARY KEY(run_id, mode, scenario_id)
        )""")


def run(engine: Engine, scenarios_path: str | Path = SCENARIOS) -> dict:
    scenarios = json.loads(Path(scenarios_path).read_text(encoding="utf-8"))
    ids = [item["id"] for item in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate scenario ID")
    _table(engine)
    run_id = str(uuid.uuid4())
    rows = []
    with tempfile.TemporaryDirectory() as root:
        for mode in ("unprotected", "rules"):
            cfg = copy.deepcopy(DEFAULTS)
            cfg["workspace"] = root
            cfg["database"] = str(Path(root) / ("audit-" + mode + ".sqlite3"))
            cfg["network"]["allowed_hosts"] = ["example.com"]
            cfg["execution"]["allowed_programs"] = ["git"]
            cfg["execution"]["allowed_argv"] = [["git", "status"]]
            local = Engine(cfg)
            try:
                for item in scenarios:
                    resource = item["resource"]
                    if item["kind"].startswith("file."):
                        resource = str(Path(root) / resource)
                    arguments = {"argv": [resource, "status"]} if item["kind"] == "process.execute" else {}
                    action = Action(item["kind"], resource, arguments=arguments, source="fixture")
                    effects = []
                    if mode == "unprotected":
                        effects.append("executed")
                        verdict = "allow"
                    else:
                        guard = Guard(local, item["id"])
                        try:
                            guard.run(action, lambda: effects.append("executed"))
                            verdict = "allow"
                        except Blocked as exc:
                            verdict = exc.decision.verdict
                        finally:
                            guard.close()
                    rows.append({"run_id": run_id, "ts": time.time(), "mode": mode,
                                 "scenario_id": item["id"], "family": item["family"],
                                 "attack": int(item["attack"]), "verdict": verdict,
                                 "effect_executed": int(bool(effects))})
            finally:
                local.close()
    with engine._lock, engine.db:
        engine.db.executemany("""INSERT INTO evaluations
            (run_id,ts,mode,scenario_id,family,attack,verdict,effect_executed)
            VALUES (:run_id,:ts,:mode,:scenario_id,:family,:attack,:verdict,:effect_executed)""", rows)
    return summarize(rows) | {"run_id": run_id, "kind": "scripted policy fixtures"}


def summarize(rows: list[dict]) -> dict:
    results = []
    for mode in sorted({row["mode"] for row in rows}):
        current = [row for row in rows if row["mode"] == mode]
        attacks = [row for row in current if row["attack"]]
        benign = [row for row in current if not row["attack"]]
        results.append({
            "mode": mode,
            "attack_attempts": len(attacks),
            "attack_effects_prevented": sum(not row["effect_executed"] for row in attacks),
            "benign_attempts": len(benign),
            "benign_effects_completed": sum(row["effect_executed"] for row in benign),
        })
    return {"results": results, "scenarios": rows}


def latest(engine: Engine) -> dict:
    _table(engine)
    with engine._lock:
        recent = engine.db.execute("SELECT run_id FROM evaluations ORDER BY ts DESC LIMIT 1").fetchone()
        if not recent:
            return {"kind": "scripted policy fixtures", "results": [], "scenarios": []}
        rows = [dict(row) for row in engine.db.execute("SELECT * FROM evaluations WHERE run_id=? ORDER BY mode,scenario_id", (recent["run_id"],))]
    return summarize(rows) | {"run_id": recent["run_id"], "kind": "scripted policy fixtures"}
