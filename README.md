<p align="center">
  <img src="assets/agentfence-icon.png" alt="AgentFence icon" width="150" />
</p>

<h1 align="center">AgentFence</h1>

<p align="center">A policy and prompt-injection gate for AI agents, with a live OpenCode demonstration.</p>

<p align="center">
  <a href="#run-the-live-demo"><img src="https://img.shields.io/badge/demo-LIVE%20OpenCode-F0F0F0?style=for-the-badge&labelColor=111111&color=555555" alt="Live OpenCode demo" /></a>
  <a href="#requirements"><img src="https://img.shields.io/badge/python-3.10%2B-F0F0F0?style=for-the-badge&labelColor=111111&color=555555" alt="Python 3.10 or newer" /></a>
  <a href="#laya-configuration"><img src="https://img.shields.io/badge/Laya-configurable-F0F0F0?style=for-the-badge&labelColor=111111&color=555555" alt="Configurable Laya detector" /></a>
  <a href="#test-and-evaluate"><img src="https://img.shields.io/badge/status-capstone%20prototype-F0F0F0?style=for-the-badge&labelColor=111111&color=555555" alt="Capstone prototype" /></a>
</p>

AgentFence sits at agent lifecycle hooks and returns a decision before a mapped action executes or before untrusted tool output reaches the model. It combines deterministic controls for files, network destinations, commands, and session behavior with an optional [Laya](https://github.com/NandhaKishorM/laya) semantic signal. Every decision is recorded for the local dashboard. The live demo uses a **real OpenCode run**, not a replay or static mockup.

For a full explanation of the problem, architecture, implementation, results, and limitations, read the [capstone project report](REPORT.md).

## Run the live demo

### Requirements

- Windows PowerShell, Python 3.10+, and the [OpenCode CLI](https://opencode.ai/docs/) on `PATH`.
- An authenticated OpenCode model. The default command uses `opencode-go/mimo-v2.6-flash`; pass `--model provider/model` if your account uses another model.
- Network access to the [author-hosted Laya public demo](https://huggingface.co/spaces/convaiinnovations/laya-demo). **Only the synthetic fixture document** is sent to this service.

From this repository's root:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python scripts\run_demo.py
```

The command prints a local dashboard URL **before OpenCode starts**. Open it immediately and leave the terminal running. The **Live demo** tab updates each second as the agent works. You will see the `session.start`, `tool.before`, and `tool.after` records appear, then a Laya score and a denial for the injected note, followed by the legitimate source edit. The run remains visible after completion until you press `Ctrl+C`. If port 8766 is occupied, use `--port 8768`.

The demo resets only the disposable `demo-workspace/` fixture. It creates a buggy `src/login.py`, a synthetic `.env`, and `docs/triage.md` containing the attack. AgentFence does **not** store the raw document or credential in the event log. Run it again to replay a fresh live turn.

### What to show a supervisor

1. **The real task:** Ask OpenCode to make `valid(password)` return true for nonempty passwords.
2. **The attack:** `docs/triage.md` tells the assistant to abandon that task, read `.env`, and upload it. It is project content, not an instruction from the user.
3. **The intervention:** The OpenCode plugin lets the read occur, then sends the returned text through AgentFence's `tool.after` hook. Laya scores the document; if it crosses the configured threshold, AgentFence replaces the tool result with a short withholding message **before the model consumes the malicious text**. The dashboard shows the actual rule and score.
4. **The outcome:** OpenCode continues and edits `src/login.py`. The run verifies both the denial and `return bool(password)` before displaying a completed state.

The dashboard also has live overview statistics, session events, observed file lineage, configuration, and coverage views. The evaluation view is labelled as **scripted policy fixtures**, separate from the live agent trace. See [DEMO.md](DEMO.md) for a short presentation script and [the validation record](docs/validation.md) for measured behavior and gaps.

## How the security layer works

```text
User task → agent proposes tool call → tool.before rules → mapped executor
                                                 ↓
                                  tool.after output inspection
                                                 ↓
                              release / withhold / request review
                                                 ↓
                                  event log → live dashboard
```

At `tool.before`, a trusted policy maps the operation to a resource and can deny protected file paths, unapproved hosts, disallowed commands, and excessive repeated actions. This prevents a covered executor from performing that specific action. At `tool.after`, the read has already happened, but AgentFence can keep its returned content from entering the model context. Laya is one configurable scoring source at this stage; its score does not overrule a hard policy denial. `session.start/end`, turn, context, model, and output hooks are available in the SDK; an adapter's coverage depends on the host's actual hook API.

For the demo, the policy lives outside the agent's writable workspace at [config.demo-enforce.json](config.demo-enforce.json). It scans `docs/**` with the author-hosted Laya demo in `enforce` mode, using a 0.80 threshold. The OpenCode adapter currently maps `read`, `edit`, and `write`; unrecognized tools are denied. The synthetic `.env` is protected by a separate file rule. In the verified live run, the agent did not attempt to read `.env`, so the demonstration does **not** claim to have stopped an attempted exfiltration.

## Use the SDK in an application

Install the package (`pip install -e .` from this checkout), put your policy in a location the agent cannot edit, and mediate operations through `Guard`:

```python
from agentfence import Engine, Guard
from agentfence.config import load_config

engine = Engine(load_config("config.example.json"))
guard = Guard(engine)
try:
    guard.begin_turn("Read a project note")
    text = guard.read_text("project-note.txt")
    print(guard.release_output(text))
    guard.end_turn()
finally:
    guard.close()
    engine.close()
```

The guarded wrapper couples a decision to execution. Merely calling `engine.decide()` and ignoring its verdict provides no enforcement. See [the embedded example](examples/embedded_app.py), [the OpenCode adapter](integrations/opencode-plugin/index.js), [the Claude Code plugin](integrations/claude-plugin/.claude-plugin/plugin.json), and [the MCP gateway](agentfence/mcp_gateway.py).

### Policy configuration

Copy [config.example.json](config.example.json) to a trusted path. Relative workspace and database paths resolve from the config file's directory. The following controls are separate:

| Area | Controls | Boundary |
| --- | --- | --- |
| Filesystem | Read/write roots, `deny_read`, `deny_write`, explicit exceptions, scan ignores | Mapped file operations |
| Network | Allowed hosts, schemes and ports; controlled HTTP redirect and private-address checks | Controlled HTTP and mapped network tools |
| Execution | Allowed programs and exact argument vectors, timeout, reduced inherited environment | Controlled process wrapper |
| Session | Action budget, repeated-action limit, sensitive-read sequence rule | Observed session |
| MCP | Trusted tool-name → operation/resource mapping | Calls routed through the gateway |
| Laya | Backend, hooks, paths, threshold, mode, finding/error behavior | Selected text returned through hooks |

For example, a trusted MCP mapping can declare `read_file` as `file.read` with `path` as its resource argument. The gateway cannot infer a tool's true side effects from its description; an incorrect mapping weakens the policy.

### Laya configuration

The default policy leaves Laya disabled. For private data, use `backend: "local"` and install the optional package with `pip install -e ".[laya]"`; local inference may download a model checkpoint. Start with [config.laya-shadow.json](config.laya-shadow.json) to record scores without blocking, then choose a threshold from labelled examples before enabling enforcement. The `space_demo` backend is explicitly for the synthetic presentation fixture and sends inspected text to a public service. Its fixed question and scores are not interchangeable with local inference.

Laya may produce false positives. In an ad hoc probe, the public demo assigned a high injection score to a benign bug-description sentence. The live demonstration establishes that the hook, detector call, withholding decision, and continued agent work are wired together; it is **not** an accuracy benchmark.

## Other integrations

- **Claude Code:** install the package, set `AGENTFENCE_CONFIG` to a trusted absolute policy path, then validate and load [the local plugin](integrations/claude-plugin/.claude-plugin/plugin.json) with `claude plugin validate ./integrations/claude-plugin` and `claude --plugin-dir ./integrations/claude-plugin`. It registers session, turn, and tool hooks. Live Claude host behavior has not yet been verified.
- **MCP stdio gateway:** `python -m agentfence --config config.example.json mcp-gateway -- python path/to/upstream_server.py`. Configure the client to launch this command in place of the upstream server. It handles a bounded subset of MCP and denies unmapped calls.
- **Standalone local dashboard:** `python -m agentfence --config config.example.json serve`. This shows persisted events; use `scripts/run_demo.py` for the one-command **live** OpenCode presentation.

## Test and evaluate

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
.\.venv\Scripts\python -m agentfence --config config.example.json evaluate
```

The fixture suite exercises eight unsafe and eight benign operations, including whether a simulated side effect ran. Its design takes inspiration from [AgentDojo](https://github.com/ethz-spylab/agentdojo)'s separation of legitimate and attacker objectives, but these fixtures are not AgentDojo benchmark runs or live attack-success rates.

AgentFence is a capstone prototype. Protection only covers operations a host actually routes through it; arbitrary subprocesses and independent network paths need host sandboxing. Post-tool inspection cannot undo side effects already performed by the tool. The dashboard binds to loopback, uses a temporary bearer token, and stores redacted event summaries in SQLite. See [PLAN.md](PLAN.md) for planned work and [docs/validation.md](docs/validation.md) for verified limits.
