# Architecture and adapter contract

AgentFence's trust boundary is the **executor**: an adapter must ask the engine for a decision and apply that decision before invoking a covered operation. The engine cannot stop a host that ignores its answer or uses another execution path.

```text
Host event / developer call
  -> adapter builds Action(kind, resource, arguments, source)
  -> Engine.decide(hook, session, action)
  -> allow | deny | require_approval
  -> adapter enforces decision
  -> adapter reports actual outcome
  -> SQLite telemetry -> local dashboard
```

The common contracts live in `agentfence/core.py`. `Action.kind` identifies the effect the host is asking for. Supported kinds are file read/write/create/delete, network send, process execute, and lifecycle content actions. A new adapter maps its tool names and argument shapes to those kinds. Unknown effects are denied. The mapper in `agentfence/adapters.py` is the shared place for documented host mapping; trusted policy supplies MCP tool mappings. Tool metadata from an untrusted server is not an authorization source.

Lifecycle hook names are host-neutral: `session.start/end`, `turn.before/after`, `context.before`, `model.before/after`, `tool.before/after`, `output.before`, and error/cancellation events. They describe *when* a decision or observation occurs; `Action.kind` describes *what* may happen. An agent turn can contain several model and tool cycles. The SDK exposes all main boundaries, while a host adapter exposes only those available in that host. The dashboard coverage view records this distinction.

`Engine.decide` records the decision before returning it. Budget checks and decision records serialize on one local lock so parallel calls do not spend the same allowance. This prototype has lower throughput when model inference is slow. The hook adapter must stop the tool if the service or policy check fails. `Engine.record_outcome` records execution success/failure separately from authorization. A tool result may be withheld after a side effect has occurred; the log must still show that effect as executed.

The SDK's `Guard.run` checks at `tool.before`, invokes the supplied function only on allow, records the outcome, and passes textual results through `tool.after` before returning them. The controlled file, network, and process helpers demonstrate how to use it. A generic `Guard.run` callback is trusted developer code. Choosing the wrong `Action.kind` for that callback breaks enforcement.

The MCP stdio gateway currently proxies a narrow set of JSON-RPC methods and declines unsupported requests. It rejects unmapped tool calls, checks mapped calls before forwarding, inspects text results before forwarding them, and detects definition changes seen during a gateway session. It cannot know the user's turn or inspect other tools outside that connection. Full MCP compatibility and remote HTTP transport need further work.

The Claude Code adapter maps documented `PreToolUse` events to `tool.before` and returns `deny` or `ask` when necessary. On allow it returns no decision, preserving Claude's own permission checks. `PostToolUse` records an outcome after execution. Session and turn callbacks are observational. A shell command may use file or network resources in ways that cannot be inferred from its command string; the strict adapter denies unmapped shell tools rather than claiming containment.

Laya implements an optional semantic detector. The selected hook supplies bounded text and a fixed application-defined question. The model's score may add a finding or require review according to trusted configuration. It never turns a hard denial into allow. A model timeout, unavailable checkpoint, or incomplete inspection needs an explicit outcome. The current in-process provider does **not** forcibly interrupt a stuck inference call; this is an implementation gap before production use.

The SQLite store records decisions and redacted resource names. A session that consumes external text is marked conservatively. A later controlled write receives an `untrusted-derived` label, and the label persists for later sessions. This is session-level provenance, not exact byte-level dataflow. Raw tool content is not retained by default.

The dashboard is served on loopback, uses a temporary bearer token, and is read-only. The evaluation tab currently reports scripted fixture outcomes from `agentfence/scenarios.json`, with an explicit label preventing confusion with live agent attacks. The [full delivery plan](../PLAN.md) includes held-out live evaluation and AgentDojo integration targets.
