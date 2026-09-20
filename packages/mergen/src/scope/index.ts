import path from "path"
import fs from "fs/promises"
import { Instance } from "../project/instance"
import { Flag } from "@/flag/flag"
import { Log } from "@/util/log"
import { ScopeFirewall } from "./firewall"

// ============================================================
// SCOPE FIREWALL (loader + enforcement glue)
//
// Active only when a scope.json exists. Lookup order:
//   1. MERGEN_SCOPE_FILE (explicit path)
//   2. <project>/scope.json
//   3. <project>/.mergen/scope.json
// An unreadable/invalid file fails CLOSED (everything blocked)
// -- a pentest tool must never silently lose its scope.
// Disable entirely with MERGEN_DISABLE_SCOPE_FIREWALL=1.
// ============================================================

export namespace Scope {
  const log = Log.create({ service: "scope-firewall" })

  export interface State {
    /** undefined = firewall inactive (no scope file found) */
    config?: ScopeFirewall.Config
    mode: "block" | "warn"
    path?: string
    parseError?: string
  }

  export interface CheckResult {
    violations: ScopeFirewall.Violation[]
    mode: "block" | "warn"
    message: string
  }

  async function load(): Promise<State> {
    const mode = Flag.MERGEN_SCOPE_MODE
    if (Flag.MERGEN_DISABLE_SCOPE_FIREWALL) return { mode }

    const candidates = [
      Flag.MERGEN_SCOPE_FILE,
      path.join(Instance.directory, "scope.json"),
      path.join(Instance.directory, ".mergen", "scope.json"),
    ].filter((p): p is string => Boolean(p))

    for (const file of candidates) {
      if (!(await Bun.file(file).exists())) continue
      try {
        const raw = await Bun.file(file).json()
        const config = ScopeFirewall.Config.parse(raw)
        log.info("scope firewall active", { path: file, allow: config.allow.length, mode })
        return { config, mode: config.mode ?? mode, path: file }
      } catch (err) {
        // FAIL CLOSED: an unparseable scope file means nothing is verifiably in scope.
        log.error("invalid scope file -- failing closed", { path: file, error: String(err) })
        return { config: { allow: [] }, mode: "block", path: file, parseError: String(err) }
      }
    }
    return { mode }
  }

  const state = Instance.state(load, async () => {})

  /** Current firewall state; undefined config = inactive. */
  export async function current(): Promise<State> {
    return state()
  }

  async function audit(toolID: string, violations: ScopeFirewall.Violation[], action: "blocked" | "warned") {
    try {
      const file = path.join(Instance.directory, ".mergen", "firewall-audit.jsonl")
      await fs.mkdir(path.dirname(file), { recursive: true })
      const line = JSON.stringify({ time: new Date().toISOString(), tool: toolID, action, violations })
      await fs.appendFile(file, line + "\n", "utf8")
    } catch (err) {
      log.warn("audit log write failed", { error: String(err) })
    }
  }

  /** Check egress targets for a tool call. Returns undefined when the firewall
   *  is inactive; otherwise violations (possibly empty) + how to treat them. */
  export async function check(toolID: string, targets: (string | undefined)[]): Promise<CheckResult | undefined> {
    const s = await state()
    if (!s.config) return undefined

    const violations = ScopeFirewall.check(targets, s.config)
    const mode = s.parseError ? "block" : (s.config.mode ?? s.mode)

    if (s.parseError) {
      const message = [
        "SCOPE FIREWALL BLOCKED -- scope file is invalid, so NOTHING is verifiably in scope (fail-closed).",
        `File: ${s.path}`,
        `Error: ${s.parseError}`,
        "Fix the scope file, or disable the firewall with MERGEN_DISABLE_SCOPE_FIREWALL=1.",
      ].join("\n")
      return { violations: [{ host: "(any)", reason: "invalid scope file" }], mode: "block", message }
    }

    if (violations.length === 0) return { violations, mode, message: "" }

    const lines = [
      `SCOPE FIREWALL ${mode === "block" ? "BLOCKED" : "WARNING"} -- ${toolID} tried to reach out-of-scope host(s):`,
      ...violations.map((v) => `  - ${v.host} (${v.reason})`),
      "",
      `Allowed by ${s.path}:`,
      ...s.config.allow.map((rule) => `  ${rule}`),
      ...(s.config.deny?.length ? ["Denied:", ...s.config.deny.map((rule) => `  ${rule}`)] : []),
      "",
      "If this target IS authorized, add it to the scope file. Loopback (127.0.0.0/8, localhost) is always allowed for local PoC targets.",
      "Override: MERGEN_SCOPE_MODE=warn (log only) or MERGEN_DISABLE_SCOPE_FIREWALL=1 (off).",
    ]
    await audit(toolID, violations, mode === "block" ? "blocked" : "warned")
    return { violations, mode, message: lines.join("\n") }
  }
}