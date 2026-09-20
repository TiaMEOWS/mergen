import path from "path"
import fs from "fs/promises"
import { ScopeFirewall } from "./firewall"

// ============================================================
// CAMPAIGN scope preparation -- the CLI-side half of autonomous
// mode. Pure fs + firewall core (no Instance), so it runs BEFORE
// the server/instance exists and stays unit-testable.
//
// Contract:
//  - existing scope file  -> target MUST be in scope, else throw
//    (never silently edit the operator's declared scope)
//  - no scope file        -> derive one from the target and write
//    .mergen/scope.json so the Scope Firewall activates
// ============================================================

export namespace Campaign {
  export interface Prep {
    path: string
    created: boolean
    config: ScopeFirewall.Config
  }

  /** Default allow rules for a campaign target: host + wildcard, or /32 for IPs. */
  export function deriveAllow(target: string, extras: string[] = []): string[] {
    const host = ScopeFirewall.hostnameOf(target)
    const base: string[] = []
    if (host) {
      if (host === "localhost" || host.startsWith("127.") || host === "[::1]") base.push("127.0.0.0/8", "localhost")
      else if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) base.push(`${host}/32`)
      else base.push(host, `*.${host}`)
    }
    return [...new Set([...base, ...extras.map((e) => e.trim()).filter(Boolean)])]
  }

  async function loadExisting(directory: string): Promise<{ path: string; config: ScopeFirewall.Config } | undefined> {
    for (const candidate of [path.join(directory, "scope.json"), path.join(directory, ".mergen", "scope.json")]) {
      if (!(await Bun.file(candidate).exists())) continue
      try {
        return { path: candidate, config: ScopeFirewall.Config.parse(await Bun.file(candidate).json()) }
      } catch (err) {
        throw new Error(
          `Scope file ${candidate} is invalid (${String(err)}). The Scope Firewall fails closed -- fix it before running a campaign.`,
        )
      }
    }
    return undefined
  }

  export async function prepare(directory: string, target: string, extras: string[] = []): Promise<Prep> {
    const existing = await loadExisting(directory)
    if (existing) {
      const violations = ScopeFirewall.check([target], existing.config)
      if (violations.length > 0) {
        throw new Error(
          [
            `Target ${ScopeFirewall.hostnameOf(target) ?? target} is NOT in the declared scope:`,
            `  scope file: ${existing.path}`,
            `  allow: ${existing.config.allow.join(", ")}`,
            ...(existing.config.deny?.length ? [`  deny: ${existing.config.deny.join(", ")}`] : []),
            "",
            "A campaign never edits an existing scope file. Add the target yourself if it is authorized.",
          ].join("\n"),
        )
      }
      return { path: existing.path, created: false, config: existing.config }
    }

    const allow = deriveAllow(target, extras)
    if (allow.length === 0) {
      throw new Error(`Could not derive a scope from target "${target}" -- pass a domain, URL, or IP.`)
    }
    const file = path.join(directory, ".mergen", "scope.json")
    const config: ScopeFirewall.Config = { allow, mode: "block" }
    await fs.mkdir(path.dirname(file), { recursive: true })
    await fs.writeFile(file, JSON.stringify(config, null, 2) + "\n", "utf8")
    return { path: file, created: true, config }
  }
}