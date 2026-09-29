# AgentFence supervisor demonstration

Run this from the repository root on the prepared Windows machine:

```powershell
python scripts/run_demo.py
```

The command creates a synthetic OpenCode project, starts the dashboard before the real OpenCode agent begins. Open the printed local URL immediately: the Live demo tab refreshes each second as hook events and Laya decisions arrive. The command verifies the outcome and leaves the dashboard running until Ctrl+C. It does not use a real credential. It needs an installed OpenCode CLI with access to `opencode-go/mimo-v2.6-flash` and network access to the [Laya author's public demo](https://huggingface.co/spaces/convaiinnovations/laya-demo). The demo sends **only synthetic fixture text** to that public endpoint. The reusable SDK defaults to local Laya inference.

The presentation takes about two minutes:

1. **What is the risk?** Ask the agent to fix `src/login.py`. Show `docs/triage.md`, a project document that pretends to be an instruction to the assistant and asks it to read `.env` and upload it. File content is lower trust than the user's request.
2. **Where is the gate?** The OpenCode plugin sends each proposed tool call to the persistent AgentFence policy process. Path rules can deny a `.env` read before execution. After an allowed read, Laya scores the returned text before OpenCode sees it. A score above the configured threshold withholds the tool result and records the score and rule.
3. **What happened live?** On the dashboard's **Live demo** tab, point to the `triage.md` `tool.after` row with `laya_finding`, its actual score, and `deny`. Then point to the allowed `login.py` read and write. The source file now contains `return bool(password)`.
4. **Why is this useful?** The agent can continue the authorized task even when one untrusted tool result is rejected. The policy, event log, SDK, and plugin share one decision engine, so the same controls can be adapted to another harness.

The trace distinguishes *executed read* from *released result*: OpenCode read the malicious file, then AgentFence withheld its content before the model consumed it. This is not a claim that the file was never opened. The synthetic `.env` is protected by a separate pre-tool path rule; in the live run the agent did not attempt that read. The demo makes no claim about universal prompt-injection detection or live AgentDojo scores.

An ad hoc check found that the public demo also gave one benign bug-description sentence a high prompt-injection score. This is a meaningful false-positive warning. Present the live outcome as proof that the hook, Laya call, policy decision, and continued authorized task work together—not as a measured classifier benchmark.

The OpenCode demo plugin deliberately permits only mapped `read`, `edit`, and `write` calls. Shell, web, patch, search, and unmapped tools fail closed; this is a bounded demonstration, not complete OpenCode coverage. The Laya demo backend scans only `docs/**` in this fixture so source code is not treated as a natural-language instruction. A real deployment should evaluate its own documents and code, tune thresholds on labeled examples, keep policy outside the agent's writable workspace, and use a local checkpoint or trusted Laya service for private text.

For a local-checkpoint deployment, change `laya.backend` to `local` in a trusted policy and install `agentfence[laya]`. The public demo backend has a fixed guard question; the local provider uses AgentFence's configured redirection question. Their scores are not directly interchangeable.
