# AgentFence — capstone delivery plan

Status (September 29): the shared engine, Python SDK, bounded MCP gateway, Claude Code adapter, OpenCode v2 plugin, live OpenCode/Laya demonstration, local dashboard, and scripted policy fixtures exist. A local Laya checkpoint, live Claude validation, and AgentDojo benchmark results remain open; see README.md and DEMO.md for measured behavior and limits.

Original planning date: September 26, 2026. The September 28 target was missed for the complete original scope. The supervisor-ready OpenCode demonstration was completed on September 29; the remaining validation work is tracked in docs/validation.md.

## 1. Product and research question

AgentFence is a local agent-security runtime built around a host-neutral lifecycle middleware contract. Developers can embed it while building an app or agent harness; existing agents connect through plugins and adapters. It includes a developer SDK, an MCP gateway, a Claude Code adapter, and a live statistics dashboard. It combines explicit permissions, session history, data provenance, and a replaceable fast decision model.

Research question: Does adding session state and a local decision model improve attack resistance over static permissions while preserving legitimate task completion at acceptable latency?

Primary deliverable: a reproducible capstone prototype with real enforcement on documented paths, real experiment results, and clearly visible coverage limits. The deadline does not support production assurance or universal agent protection.

## 2. Decisions improved by research

- Use Laya as the first local semantic detector. Its output is evidence for policy, never authority to override a hard deny or create permissions.
- Choose a Python security core: Laya and AgentDojo are Python projects, so this removes unnecessary integration work. The current dashboard is bundled HTML/CSS/JavaScript over a local read-only API; the OpenCode plugin is JavaScript over a persistent Python bridge.
- Implement one shared decision engine and lifecycle contract. SDK, gateway, and hooks normalize events and enforce decisions; they do not duplicate security rules. Native host hooks map into the contract only where their timing and enforcement semantics actually match.
- Ship local stdio MCP support first. Remote MCP authentication and hosted ChatGPT delivery are stretch work, not dependencies for the submission.
- Make statistics and replay part of the initial vertical slice. They also provide the evidence needed for evaluation.
- Separate observed policy blocks from independently verified prevented attacks. Production telemetry cannot establish attacker intent or task success by itself.

## 3. Deadline scope

Required:

1. Python core and SDK with lifecycle middleware, safe execution wrappers, and a small instrumented reference harness/application.
2. Local security service with persistent SQLite state.
3. MCP stdio gateway protecting supported discovery, tool-call, and result paths.
4. Claude Code adapter for verified hook events; preserve host permission checks.
5. Laya integration, health status, measured latency, and shadow/enforcement modes.
6. Dashboard: overview, sessions, evaluations, and coverage/settings views.
7. A compact coding-agent evaluation suite inspired by AgentDojo.
8. Reproducible tests, setup guide, architecture documentation, evaluation report, and recorded demo.

Stretch, in this order:

1. Thin TypeScript SDK using the local engine, with an executable example.
2. Small direct AgentDojo integration and separately labelled results.
3. Additional model or agent comparison.
4. Remote HTTP MCP and a ChatGPT connection demonstration, only if authentication and account access are already available.

Deferred: universal shell containment, fine-tuning as a release requirement, automatic rollback of arbitrary effects, enterprise deployment, cloud accounts, multi-tenant administration, every coding-agent adapter, and a general vulnerability scanner.

## 4. Threat model and coverage

Protect against malicious instructions in tool results, repository text, tool metadata, and files written and reread by the agent. Protect configured resources against unauthorized reads/writes and outbound transfers through mediated tools. Detect bounded repeated-action patterns.

Trust the operator policy, installed runtime, adapter configuration, and credential owner. Keep policy and state outside agent-writable project directories where possible. The prototype does not defend against a compromised host administrator or guarantee containment when the agent can disable its own hooks.

An MCP gateway sees routed MCP traffic. It does not automatically observe native shell commands, independent network clients, or unrelated integrations. A malicious upstream server may already have performed side effects before returning a result. Result filtering does not reverse those effects.

Every adapter publishes capabilities: pre-call blocking, pre-delivery result inspection, metadata inspection, session continuity, filesystem observation, and network enforcement. Unsupported operations must be rejected in strict mode or explicitly reported as outside coverage. Do not silently proxy unsupported MCP features while claiming protection.

## 5. Runtime architecture

Agent or application -> adapter/SDK -> normalize and validate -> hard permission rules -> stateful rules -> Laya when applicable -> final policy decision -> adapter execution -> result inspection -> event store -> dashboard.

Canonical actions: file.read, file.write, process.execute, network.send, tool.discover, tool.call, tool.result, and session lifecycle events. Known tools have trusted mappings to effects and resources. Unknown tool semantics are explicitly unknown; a server's read-only annotation is insufficient evidence of safety.

Decisions: allow, deny, require_approval. Observation-only findings do not block. Every decision includes an ID, rule IDs, reasons, evidence references, policy version, detector version/status, and timing. The core produces data; adapters enforce it.

The service owns event persistence and session state. Use per-session serialization for security decisions and atomic budget reservations so concurrent calls cannot both spend the same remaining allowance. Record proposed, blocked, executed, failed, and uncertain outcomes distinctly.

SDK execution wraps both authorization and the actual invocation. A remote client still forms part of the trusted enforcement boundary. A decision endpoint alone cannot force an arbitrary caller to obey it.

### General lifecycle middleware

The public interface uses one versioned hook envelope and typed payloads. A hook describes a lifecycle boundary; an action describes the resource operation occurring at that boundary. This prevents tool names, SDK APIs, and host event names from becoming the policy language.

Example: `tool.before` is the boundary, `file.write` is the normalized action, and `claude` or `custom-harness` is the adapter identity. These fields serve different purposes and must remain separate.

Initial hook vocabulary:

| Hook | Boundary and intended use |
| --- | --- |
| session.start / session.end | Initialize or finalize scoped state, coverage, and audit records; ending a session does not erase persistent provenance |
| turn.before / turn.after | Before accepting a user turn: validate trusted identity, input envelope, policy and budgets; after completion: record outcome and unresolved effects |
| context.before | Before external content, memory, or assembled context reaches the model: inspect sources, labels, and permitted data use |
| model.before / model.after | Before a model request: check outbound model destination and context policy; after a response: inspect exposed output and proposed actions before dispatch |
| tool.before / tool.after | Before invocation: enforce effects and permissions; after invocation: record actual outcome and inspect returned data before its next consumer where supported |
| output.before | Before user-visible output is released: apply the configured output policy |
| operation.error / operation.cancelled | Record failures and partial or uncertain effects, close outstanding spans, and settle budgets appropriately |

An agent turn may contain many model/tool cycles. Tool calls run inside that turn and each gets its own operation/span ID. A response proposing three tool calls produces three independently authorized tool operations, with shared session budgets. A passed turn/model hook never pre-authorizes future tools.

`tool.after` cannot undo effects of the tool. It can withhold a result only when the adapter runs before that result reaches the model or caller. Likewise, `turn.after` is observational; output protection belongs at `output.before`, not after delivery. A failed or cancelled operation must report its terminal status and any known partial effects rather than fabricate a successful after-event.

Intermediate hooks refer to observable context additions, model requests/responses, tool attempts/results, and application events. They do not require access to hidden model reasoning. Reserve extension namespaces for stream chunks, compaction, memory writes, and delegation, but do not claim those integrations before they are implemented. Known persisted memory writes still pass through the normal tool/action rules.

### Gates, transformations, and observers

Use three explicit handler capabilities:

1. Gate: synchronously returns allow, deny, or require_approval before a protected boundary. Execution waits for the decision.
2. Transform: proposes an explicitly permitted, schema-valid replacement for content or arguments. For the deadline version, support only narrowly scoped content redaction/quarantine where needed, not arbitrary plugin rewrites. A replacement changes the payload hash, retains lineage, invalidates an old approval, and is rechecked before release or execution.
3. Observe: receives an audit event after the relevant transition. It can record findings but cannot retroactively claim enforcement.

Do not implement enforcement as asynchronous fire-and-forget event listeners. Durable security state and decision records precede protected dispatch; dashboard notification can be asynchronous. If security state cannot be committed, protected dispatch fails. Record an uncertain outcome when a crash leaves execution status unknown; do not automatically retry a write merely because a reply was lost.

Compose mandatory policy checks with deny taking precedence over approval-required, and approval-required taking precedence over allow. Detector signals inform configured rules; detectors do not grant access. Trusted host configuration chooses modules and their order. Untrusted repository content cannot install middleware, change thresholds, or disable mandatory checks. Custom in-process handlers are trusted code, not sandboxed extensions.

Every handler has an explicit timeout and failure policy. Required gate failure blocks that boundary; optional observer failure records degraded telemetry without reclassifying the action as safe. Avoid recursive self-inspection of the security runtime's own internal calls: only trusted runtime code marks those calls, never model-controlled input.

### Contract and developer integration

Hook envelope fields: schema version, event ID, hook name, phase, session ID, turn ID, operation/span ID, parent span ID, attempt number, sequence, adapter identity, source identity, payload or protected reference, payload hash, trust/sensitivity labels, and declared enforcement capabilities. Trusted adapters construct identity and provenance fields; tool text cannot assert them.

The SDK offers wrapped turn, model, and tool execution plus guarded context/output release. A low-level dispatch API supports custom harnesses, but returning a decision is insufficient unless the harness waits and applies it. Exceptions, cancellations, retries, nested calls, and async execution preserve correlation. Retries get distinct attempt IDs and fresh decisions when relevant state changes; duplicate event delivery does not double-count activity or repeat an external effect.

For development-time integration, ship a reference harness with one model loop and several tools, installed through one middleware attachment point. Ship a second minimal application example that protects input/context, a tool operation, and final output without requiring the app to become a coding agent. Both use the same engine and demonstrate the reusable contract.

Host adapters publish a per-hook support matrix: gate/transform/observe, exact timing, visibility, and cancellation support. Required but unavailable hooks cause strict-profile startup failure. Optional missing hooks remain visibly unsupported. The MCP gateway reports tool/protocol coverage; it must not invent user-turn or model-call events from isolated MCP messages. Full lifecycle coverage is demonstrated by the reference harness, not assumed for third-party hosts.

Streaming is explicit: the deadline version buffers protected output until `output.before` passes, with size/time bounds. Later chunk hooks may cancel future delivery but cannot retract released bytes. Do not claim output-leak prevention on an adapter that already streamed the content.

## 6. Security controls

### Permissions

Operator-defined readable/writable resources, outbound destinations, permitted tool identities, and action budgets. Normalize paths and address traversal and symlink cases at execution where controllable. Treat unrestricted shell execution as broader authority than parsed command text suggests. Keep arbitrary shell containment outside the initial guarantee.

### Layered resource policies

Implement a small, explicit policy vocabulary with separate filesystem, network, and process-execution rules. Evaluate the operation's effects across all relevant layers; an executable allow rule does not automatically allow its file or network effects. Every violation identifies the layer, matched rule, canonical resource, proposed operation, and enforcement point.

Filesystem policies distinguish read, create, modify, delete, and execute permissions. Support operator-defined roots, exact paths, and documented glob patterns; examples include `.env`, `.env.*`, private-key files, credential directories, and the runtime's own configuration/state. These are starter presets requiring project-specific exceptions, not a claim that every similarly named file is secret. An `.env.example` fixture can be explicitly permitted within the same trusted policy after review. Separate filename/path classification from optional content-based secret detection, and redact evidence rather than storing discovered secrets.

Resolve relative paths against the actual execution directory and enforce root containment. Match both the requested name and resolved target where relevant, with platform-aware case rules and separator handling. Test symlink/junction escapes and Windows-specific path aliases. For create operations, resolve the existing parent and validate the resulting destination. Path checking by itself does not eliminate check/use races; atomic or handle-based enforcement and OS restrictions are needed for stronger guarantees. The initial SDK controls its own file operations; third-party execution paths retain their documented limitations.

Keep three different concepts separate:

- `scan_ignore`: skip optional content inspection for a configured class of files, such as generated outputs. Resource permissions still apply. If a protection profile requires inspection before use, ignored content is uninspected and cannot silently pass that requirement.
- `access_deny`: prohibit configured operations on matching resources.
- `access_allow`: permit only specified operations within a bounded scope, subject to mandatory restrictions and other policy layers.

Do not import `.gitignore` as an access policy. A project-writable ignore file or security config cannot weaken operator policy. Mandatory denies cannot be overridden by project rules; exceptions to editable operator presets must be explicit in the trusted configuration. Avoid implicit “last match wins” semantics and report conflicts during validation.

Network policies describe scheme, canonical host, port, and, for known HTTP tools, method and path constraints. Separate public destinations from loopback, private networks, link-local addresses, and metadata services; allow explicit local development exceptions. Recheck each redirect and the actual resolved destination at connection time where the executor supports it. DNS aliases, IP literals, and alternate representations must not bypass host/IP rules. URL validation alone is advisory for opaque tools that perform their own network access. General subprocess egress containment requires an OS sandbox or enforced network proxy and is deferred from the initial guarantee.

Execution policies cover canonical executable identity/path, structured argument constraints, working directory, environment handling, wall-clock limits, and execution budgets. Prefer direct argv invocation over shell strings. Limit which environment variables and credentials enter controlled child processes. Recognize that allowing `python`, `node`, a shell, or a package manager can enable arbitrary code and install hooks; an executable name allowlist does not make such commands safe. Unknown shell constructions require approval or denial according to profile. Parsing a shell command can provide a finding but cannot prove all downstream effects are permitted.

Where AgentFence owns the executor, apply supported process timeouts and cancellation, and report remaining child processes or uncertain effects if termination is incomplete. Running an operation in a subprocess is not a sandbox. Never display “filesystem isolated” or “network contained” based solely on matching argument strings.

Deadline implementation: real path permissions for controlled tools, outbound destination checks for the controlled HTTP/fake-upload tools, structured process rules for the reference executor, and hook/gateway checks for known mapped tools. Dashboard coverage states whether each control is enforced by the executor, enforced at a host gate, advisory only, or unsupported. Full OS isolation is a subsequent layer, not a prerequisite silently added to the September 28 delivery.

The model cannot expand permissions. A host-native approval remains required wherever the host requires it. The adapter must not issue a blanket allow that bypasses existing host checks.

### MCP inspection

Snapshot server/tool identity and canonical schema/description hashes. Evaluate first registration and quarantine unexpected definition changes. Hashes establish change detection, not trustworthiness. Validate input against schemas and bound response size and processing time. Inspect supported results before forwarding them to the agent.

### Provenance and persistence

Keep trust and sensitivity as independent labels. Track observed source -> read -> write -> reread relationships using resource identity and content hashes. Scope labels to a project and session as appropriate; retain observed file lineage across sessions. Conservatively propagate labels when precise derivation is unavailable. Disclose that arbitrary model paraphrases and external writes prevent perfect lineage reconstruction.

### Outbound transfer controls

Combine destination policy, sensitivity labels, and explicit export grants. Test with synthetic secrets and a local fake upload sink. Do not depend on substring detection alone: transformed content may evade it. Restrict outbound destinations after sensitive access unless a narrowly scoped policy allows the operation.

### Loop controls

Use call fingerprints, repeated failure signatures, file-hash cycles, total actions, and elapsed-time budgets. Distinguish no-progress cycles from legitimate edit/test iterations. Never treat all repeated reads as malicious.

### Approval and failure behavior

Bind approval to the session, tool, canonical arguments, relevant resource version, and expiration. Recheck changed operations. Without a supported approval channel, return approval-required without executing. The dashboard is initially read-only and does not grant privileges.

If the security service is unavailable, adapters block protected operations. If Laya is unavailable, deterministic rules remain active, the system reports degraded status, and operations requiring semantic review stay blocked or require approval. Explicitly permitted low-risk operations may continue according to configured policy.

## 7. Laya integration

Laya is a configurable, optional provider behind the detector interface, not a hard-coded dependency of policy evaluation. Use one warmed checkpoint by default initially, pinned to a revision. Record software/model versions and retain license notices. Evaluate a small candidate set during the first implementation block rather than assuming the largest or multilingual checkpoint is best.

### Configuration contract

Provide validated operator configuration with global defaults and per-hook overrides. Support these settings in the initial implementation:

- Enable/disable the detector; select `laya` or `none` through the provider interface. Additional providers can implement the same interface later without implying they already exist.
- Mode: `shadow` records findings only; `enforce` allows configured detector findings to impose additional restrictions. Neither mode grants permissions or overrides hard denies.
- Model: checkpoint ID or local model path, pinned revision, device (`auto`, `cpu`, or an explicitly supported accelerator), and preload behavior. Report the resolved device rather than treating requested acceleration as confirmed.
- Hook selection: independently enable context, model-response, tool-result, or output inspection where the adapter supports the boundary. Use one checkpoint per runtime for the deadline version; per-hook settings do not imply multiple loaded models.
- Decision settings: application-controlled question-schema ID/version, per-class thresholds, and the response to findings (`require_approval`, `deny`, or observation in shadow mode). Validate threshold ranges and require evaluation before treating a threshold as calibrated. Ship shadow mode as the model default.
- Resource limits: inference timeout, input-token budget, chunk/total inspection budget, bounded inference concurrency, and cache capacity/expiry. Mark incomplete inspection explicitly.
- Failure behavior: require approval or deny when a protected operation needs semantic review and inference fails, times out, or cannot inspect the input. Required review cannot silently become allow. Optional shadow inspection may fail while existing deterministic policy remains in force, with a degraded status recorded.

Resolve effective settings from built-in defaults, a trusted operator configuration file, and permitted per-hook overrides. The operator defines which settings an application may override; request payloads and repository text cannot choose their own security configuration. Unknown fields, invalid values, unknown hook names, and unsupported required capabilities cause validation failure.

Record the effective configuration hash and model/question-schema versions on detector results. Cache keys include the effective detector settings and relevant input/context; configuration changes invalidate incompatible cached results. Require an explicit restart for changes in the deadline version so in-flight decisions are not silently evaluated under mixed settings. Configuration files contain secret references rather than credentials if a remote provider is added later.

Disabling Laya preserves hard permissions, stateful rules, provenance, and audit logging. If a selected protection profile requires semantic inspection, startup must reject a disabled or unavailable detector instead of claiming that profile is active. A rules-only profile is valid and appears explicitly in the dashboard and evaluation results.

Expose effective settings, configuration version, selected/resolved model and device, per-hook mode, health, and degraded status in the dashboard. Keep editing through trusted local configuration for the deadline release; a privileged settings editor is later work. Include documented example configurations for rules-only, Laya shadow, and Laya enforcement, with thresholds labelled provisional until evaluated.

Fixed question schemas should assess whether external content attempts to redirect the task, claims authority, or requests sensitive actions. Start with one compact categorical question; measure the cost and benefit of extra questions. Keep questions controlled by the application, with untrusted text supplied only as data.

Choose detectors per hook. Use Laya primarily on newly ingested context and selected exposed model outputs; use deterministic/stateful checks for resource permissions, budgets, and operation outcomes. Do not run inference at every lifecycle callback. Cache only equivalent detector inputs keyed by content, question schema, model revision, and relevant context; never reuse an authorization decision just because text matches. Expose invocation and cache-hit counts by hook.

Pass the candidate action, trusted task constraints, source labels, and bounded relevant history. Mark inputs that could not be fully inspected. Long content must be chunked with an explicit coverage budget or treated as incomplete; never silently truncate and label the whole result safe.

Laya outputs class probabilities and status, not final authorization. Abstain on errors, unsupported inputs, or incomplete inspection. Confidence alone does not detect unfamiliar attacks. Tune thresholds only on development data and report held-out performance; do not advertise scores as calibrated security probabilities without testing calibration on this task.

Run shadow mode first, then enable additional restrictions only if evaluation supports the tradeoff. If it performs poorly, ship its integration and measured results transparently while retaining deterministic enforcement. Training a custom checkpoint is a later research extension.

The upstream project presents Laya as a base that benefits from specialization. Its published latency depends on hardware, input length, and question count. We must measure local warm/cold and end-to-end latency rather than promise a marketing number. Sources: [repository](https://github.com/NandhaKishorM/laya), [model card](https://huggingface.co/convaiinnovations/laya), [benchmarks](https://github.com/NandhaKishorM/laya/blob/main/BENCHMARKS.md).

## 8. Statistics dashboard

Use a single local dashboard with four views and shared filters for time, adapter, session, policy version, and model version. Empty views must show no data, not invented activity. Fixture data is visibly labelled demonstration data.

### Overview

- Sessions and mediated calls.
- Allowed, denied, approval-required, failed, and uncertain calls.
- Findings by rule and attack-category hypothesis.
- Action volume and block rate over time.
- Decision latency p50/p95, separating model, policy, transport, and total overhead.
- Laya calls, abstentions, errors, inference coverage, and model availability.
- Latest suspicious sessions and integration coverage warnings.
- Per-hook event volume, enforcement decisions, p50/p95 latency, timeouts, and detector usage. Distinguish tool-call counts from total lifecycle-event counts.
- Findings and enforced decisions grouped by filesystem, network, execution, semantic content, and session behavior. Show the matched policy rule with redacted resource details.

### Sessions

Clickable event timeline: external source received -> resource read -> operation proposed -> decision -> observed result. Display redacted argument previews, evidence, rule IDs, and provenance edges. Distinguish observed ordering from proven causal influence. Include JSON export of redacted traces.

Group the timeline as session -> turn -> model/tool operations with correlated before/after/error events. Show whether each hook observed, blocked, required approval, or withheld content. Highlight incomplete spans and unsupported boundaries instead of implying full visibility.

### Evaluations

Compare configurations side by side using attack success, benign task success, attacked-task success, false blocks, escalations, errors, latency, and sample counts. Show model/checkpoint, policy, scenario version, run date, repetitions, and dataset split. Provide an attack-family heatmap and drill-down to failed cases.

### Coverage and settings

Show connected adapters, capability matrix, service/model health, active read-only policy, and missing coverage. Configuration changes occur through trusted local configuration in this release.

The capability matrix lists supported lifecycle hooks per adapter and their enforcement mode. A configured hook with no events is not evidence that every relevant operation was intercepted; adapter conformance tests establish the claimed coverage.

Metric definitions:

- Block rate = denied decisions / evaluated pre-call decisions. It is not attack prevention rate.
- Attack success rate = runs satisfying the independent attacker-goal predicate / eligible attack runs.
- Benign utility = benign runs satisfying the user-goal predicate / eligible benign runs.
- Attacked utility = attacked runs satisfying the user-goal predicate / eligible attack runs.
- False-block rate = legitimate labelled proposed actions incorrectly blocked / legitimate labelled proposed actions assessed.
- Show errors/timeouts separately, with exclusion rules and denominators. Do not count model failure as a security win.
- Confidence calibration is evaluation-only and needs ground-truth labels. Live confidence histograms do not prove accuracy.

Store redacted metadata by default. Avoid raw prompts, credentials, or tool content in ordinary logs. Render attacker-controlled text as inert text; never raw HTML. Bind the API to loopback with authenticated clients and explicit browser-origin checks. Use short polling initially to reduce implementation complexity.

## 9. Evaluation inspired by AgentDojo

Borrow the separation of environment, legitimate user task, attacker goal, injection placement, defense, and independently checked outcome. AgentDojo is an extensible environment for evaluating tool-using agents on untrusted data, rather than just a collection of malicious strings. Sources: [paper](https://arxiv.org/abs/2406.13352), [repository](https://github.com/ethz-spylab/agentdojo).

Build a small local coding workspace with synthetic files, tools, and fake network sinks. Each scenario specifies initial state, task, attack placement, permissions, user-success predicate, attacker-success predicate, and cleanup/reset behavior. Judges inspect final files, captured sends, and recorded effects instead of asking the agent whether it succeeded.

Target fixture set: eight attack families, two distinct variants per family, plus sixteen benign matched controls. Families: tool-result injection, tool-description poisoning, definition changes, secret-to-network transfer, unauthorized file writes, persistence across write/reread, fabricated authorization, and repeated-action cycles. Several are broader runtime-policy cases rather than pure prompt-injection cases; report their results separately.

Include benign security quotations, approved exports, useful repeated test runs, and normal file edits. Split by scenario family/template so near-duplicate payloads do not appear in tuning and final tests.

Deterministic verification: exercise all fixtures against the policy and adapter paths, including concurrent calls, service outage, model timeout, malformed metadata, duplicate request IDs, and changed approvals. These verify engineering behavior; they are not LLM attack-success measurements.

Lifecycle conformance tests additionally cover turn rejection before model invocation, context withholding before consumption, denial before tool side effects, result withholding before the next model step, output withholding before delivery, and accurate error/cancellation reporting. Test nested spans, repeated delivery, three parallel tool proposals sharing a budget, and an intentionally unsupported host hook. Verify that model or tool content cannot spoof trusted hook metadata.

Resource-policy tests cover filename patterns and explicit sample-file exceptions; scan-ignore versus access-deny separation; traversal and supported symlink/junction cases; redirect-to-denied-destination behavior in controlled HTTP tools; blocked process arguments; inherited-secret filtering; and interpreter/shell cases that must not be presented as contained. Assert actual effects and policy precedence, not just emitted alerts.

Live evaluation target: eight held-out attack scenarios and eight benign controls, across four configurations, three repetitions = 192 bounded runs. Start with a smoke subset and estimate provider cost/runtime before committing the full matrix. Reduce repetitions transparently if access or time is constrained.

Configurations: unprotected agent; static permissions; static permissions plus state/provenance; full system adding Laya. Freeze policy and thresholds before final runs. Use the same agent model, fixtures, budget, and task definitions across configurations. Record versions and seeds where supported. Show counts and uncertainty; a small suite does not establish universal effectiveness.

A direct AgentDojo subset is an optional additional experiment. Pin its version and keep those results separate from the custom suite. Label custom results “AgentDojo-inspired coding suite,” never “AgentDojo benchmark results.” Respect attribution and license requirements for any reused code or fixtures.

## 10. Code structure and stack

```text
agentfence/
  core/                 # Policies, decisions, session transitions
  contracts/            # Validated events and adapter capabilities
  lifecycle/            # Hook dispatch, gates, correlation, handler composition
  detectors/            # Laya provider and simple baseline signals
  storage/              # SQLite events, sessions, provenance
  service/              # Local API and dashboard queries
  adapters/
    mcp/                # Protocol proxy and result handling
    claude/             # Hook event mapping and enforcement
  sdk/                  # Python execution wrapper
examples/
  reference_harness/    # Full observable turn/model/tool lifecycle
  embedded_app/         # Development-time middleware integration
dashboard/              # React + TypeScript + Vite
clients/typescript/     # Thin client; stretch
evaluation/
  environments/
  scenarios/
  runners/
  judges/
tests/
docs/
```

Stack: Python, Pydantic, FastAPI, SQLite, official MCP SDK, Laya, pytest; React/TypeScript, Vite, and a small chart library for the dashboard. Pin compatible versions during implementation. Avoid additional infrastructure such as Redis, a graph database, or Kubernetes.

Principal records: Session, Turn, OperationSpan, Event, Decision, ToolSnapshot, ResourceLabel, EvaluationRun, ScenarioOutcome. Events include unique IDs, session sequence, timestamps, adapter identity, hook/phase, action/resource metadata, decision reference, execution outcome, redacted evidence, and timings. Dashboard counts derive from persisted records, with duplicate-event protection.

## 11. Delivery schedule and cut lines

September 26, remaining afternoon/evening:

- First 90 minutes: verify runtime tools, model download/access, local Laya inference, and target host hooks. Measure warm/cold inference on this machine.
- Build canonical lifecycle contracts, gate dispatcher, policy engine, SQLite event persistence, Python wrapper, and one synthetic tool in the reference harness.
- Deliver the first vertical slice: a real allowed call and a real blocked call visible in the dashboard.
- Gate: the model integration is isolated behind its provider interface even if installation or accuracy is problematic.

September 27, morning:

- Implement bounded MCP stdio gateway and Claude hook adapter.
- Verify actual pre-execution blocking and result-inspection coverage.
- Add metadata snapshots, session permissions, and initial outbound rules.
- Publish actual per-hook adapter coverage; exercise turn/model/context/output boundaries in the reference harness and embedded-app example.

September 27, afternoon/evening:

- Add Laya shadow scoring, stateful rules, observed write/reread labels, and repetition budgets.
- Finish dashboard overview and session timeline.
- Complete fixture harness and smoke live runs. Freeze release features by the end of the day.

September 28, morning:

- Complete evaluation view and coverage view.
- Run held-out experiments and correctness/failure-path tests.
- Fix defects; do not add new platforms or training pipelines.

September 28, afternoon to 20:00 IST:

- Reproduce setup from documented instructions.
- Export actual results; write limitations and architecture notes.
- Record a five-minute demo and retain a replay that works without external APIs.
- Package source, configuration examples, tests, reports, and recording.

After 20:00: contingency fixes and submission only. If delayed, drop the direct AgentDojo bridge, TypeScript client, additional models, and remote hosting first. Preserve real enforcement, the stats page, reproducible evaluation, and honest scope.

## 12. Acceptance criteria and demonstration

- SDK and gateway demonstrations block configured forbidden operations before the fake sink observes a side effect.
- The reference harness demonstrates turn, context, model, tool, output, and terminal lifecycle events using one middleware contract; the minimal embedded app uses the same contract.
- Gate ordering and before-consumption checks pass lifecycle conformance tests. Unsupported third-party hooks remain marked unsupported.
- A real Claude Code hook demonstration shows denial on a covered action; otherwise label that adapter unverified rather than claiming it works.
- At least one allowed legitimate task completes through each verified integration.
- A supported write/reread path preserves its recorded untrusted label across sessions.
- Loop budgets stop a defined no-progress cycle while a benign edit/test case passes.
- Laya predictions and actual timings appear in the dashboard, including a visible degraded/failure case.
- Detector configuration supports global defaults and per-hook overrides; rules-only and shadow modes preserve deterministic enforcement. Invalid configuration, an unavailable required detector, and unsupported required hooks fail visibly. Effective settings are displayed and recorded with decisions.
- Dashboard totals reconcile with stored events and exported results; experiment modes cannot be confused with live telemetry.
- All reported model-effectiveness results come from executed experiments. Scripted replay is visibly labelled replay.
- No unresolved failure permits a tested forbidden action through a claimed enforcement path. If one exists, disable that path or narrow the claim before release.
- Documentation includes setup, threat model, adapter coverage, evaluation method, limitations, and source attribution.

Demo sequence: complete a benign task; introduce a malicious tool result; show the proposed forbidden transfer blocked; open its event timeline and policy evidence; show a persistence/loop case; compare real evaluation results with and without Laya; end on coverage and latency. The claimed contribution is the integrated, measurable runtime design, not invention of prompt-injection detection or a claim that Laya is equivalent to JEV on security tasks.
