import { spawn } from "node:child_process"
import { createInterface } from "node:readline"
import { delimiter, resolve } from "node:path"
import { fileURLToPath } from "node:url"

// OpenCode v2 plugin. A persistent Python child keeps one Engine and one Laya
// checkpoint warm across tool calls. The child writes only JSON lines to stdout.
export default {
  id: "agentfence",
  async setup(ctx) {
    const python = process.env.AGENTFENCE_PYTHON
    const config = process.env.AGENTFENCE_CONFIG
    if (!python || !config) throw new Error("AgentFence needs AGENTFENCE_PYTHON and AGENTFENCE_CONFIG")
    const child = spawn(python, ["-u", "-m", "agentfence", "--config", config, "opencode-bridge"], {
      stdio: ["pipe", "pipe", "inherit"],
      windowsHide: true,
      env: { ...process.env, PYTHONPATH: [resolve(fileURLToPath(import.meta.url), "..", "..", ".."), process.env.PYTHONPATH].filter(Boolean).join(delimiter) },
    })
    const pending = []
    let closed = false
    createInterface({ input: child.stdout }).on("line", line => {
      const item = pending.shift()
      if (!item) return
      clearTimeout(item.timer)
      try { item.resolve(JSON.parse(line)) } catch (error) { item.reject(error) }
    })
    child.on("exit", () => {
      closed = true
      while (pending.length) {
        const item = pending.shift()
        clearTimeout(item.timer)
        item.reject(new Error("AgentFence policy process stopped"))
      }
    })
    const fail = error => {
      if (closed) return
      closed = true
      child.kill()
      while (pending.length) {
        const item = pending.shift()
        clearTimeout(item.timer)
        item.reject(error)
      }
    }
    const ask = (message) => new Promise((resolve, reject) => {
      if (closed) return reject(new Error("AgentFence policy process stopped"))
      const item = { resolve, reject, timer: setTimeout(() => {
        fail(new Error("AgentFence policy decision timed out"))
      }, 120000) }
      pending.push(item)
      child.stdin.write(JSON.stringify(message) + "\n", error => { if (error) fail(error) })
    })
    const sessions = new Set()
    const inputs = new Map()
    const key = event => `${event.sessionID || ""}:${event.callID || event.id || ""}`
    await ctx.tool.hook("execute.before", async event => {
      const session = String(event.sessionID || "opencode-unknown")
      if (!sessions.has(session)) {
        await ask({ event: "session.start", session })
        sessions.add(session)
      }
      const input = event.input || {}
      const tool = String(event.tool || "")
      const decision = await ask({ event: "tool.before", session, tool, input })
      if (decision.verdict !== "allow") throw new Error(`AgentFence ${decision.verdict}: ${decision.rule}: ${decision.reason}`)
      inputs.set(key(event), input)
    })
    await ctx.tool.hook("execute.after", async event => {
      const input = event.input || inputs.get(key(event)) || {}
      inputs.delete(key(event))
      const result = event.result || {}
      const output = typeof result === "string" ? result :
        typeof result.output === "string" ? result.output :
        typeof result.text === "string" ? result.text :
        typeof result.content === "string" ? result.content :
        Array.isArray(result.content) ? result.content.filter(x => x?.type === "text").map(x => x.text).join("\n") : ""
      const decision = await ask({ event: "tool.after", session: event.sessionID,
        tool: event.tool, input, status: event.status, output })
      if (decision.verdict !== "allow" && decision.verdict !== "observe") {
        const replacement = `[AgentFence withheld tool result: ${decision.rule}. ${decision.reason}]`
        event.result = { ...result, output: replacement,
          content: Array.isArray(result.content) ? [{ type: "text", text: replacement }] : replacement,
          metadata: { ...result.metadata, agentfence: decision } }
      }
    })
    return () => child.kill()
  },
}
