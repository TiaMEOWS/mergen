/**
 * McpGuard audits MCP server tool metadata for poisoning and dangerous
 * capability combinations *before* Mergen exposes the tools to the agent.
 *
 * Pattern set mirrors mcp-sentinel (https://github.com/TiaMEOWS/mcp-sentinel):
 * MS-P01..P08 poisoning indicators plus capability correlation (MS-D01/D06).
 */

import { Log } from "../util/log"

const log = Log.create({ service: "mcp-guard" })

export namespace McpGuard {
  export type Severity = "info" | "low" | "medium" | "high" | "critical"

  export interface Finding {
    id: string
    severity: Severity
    title: string
    detail: string
    tool?: string
    evidence?: string
  }

  export interface GuardedTool {
    name: string
    description?: string
    inputSchema?: unknown
    annotations?: unknown
  }

  interface Pattern {
    id: string
    regex: RegExp
    severity: Severity
    title: string
    detail: string
  }

  const INVISIBLE = /[\u200B\u200C\u200D\u2060\uFEFF\u202E]/

  const PATTERNS: Pattern[] = [
    {
      id: "MS-P01",
      regex: /\bignore\b[^\n.]{0,40}\b(previous|prior|above|earlier)\b/i,
      severity: "critical",
      title: "Instruction-override attempt",
      detail: "Tool metadata tells the model to ignore prior instructions.",
    },
    {
      id: "MS-P02",
      regex: /\b(do not|never)\b[^\n.]{0,30}\b(tell|inform|show|reveal|mention)\b[^\n.]{0,25}\b(user|human|operator|anyone)\b/i,
      severity: "critical",
      title: "Concealment instruction",
      detail: "Tool metadata instructs the model to hide actions from the user.",
    },
    {
      id: "MS-P03",
      regex: /\b(before|prior to)\b[^\n.]{0,40}\b(using|calling|invoking)\b[^\n.]{0,90}\b(must|always|first|required|need to)\b/i,
      severity: "high",
      title: "Pre-action injection",
      detail: "Description forces hidden actions before the tool may be used.",
    },
    {
      id: "MS-P04",
      regex: /\b(read|open|cat|load|dump|exfiltrate|send|upload|fetch)\b[^\n.]{0,60}(~[/\\]?\.ssh|id_rsa|\.env\b|credential|secret|password|passwd|api[_-]?key|private.?key|access.?token)/i,
      severity: "critical",
      title: "Sensitive-data access in description",
      detail: "Description references reading or sending credentials or secrets.",
    },
    {
      id: "MS-P05",
      regex: /<\s*\/?\s*(system|hidden|admin|internal|secret|debug)\s*>/i,
      severity: "high",
      title: "Hidden markup tags",
      detail: "Metadata contains hidden/system-style tags that smuggle instructions.",
    },
    {
      id: "MS-P07",
      regex: /\b[A-Za-z0-9+/]{80,}={0,2}\b/,
      severity: "medium",
      title: "Encoded blob in description",
      detail: "Long base64-looking blob may hide obfuscated instructions.",
    },
    {
      id: "MS-P08",
      regex: /https?:\/\/\S+/,
      severity: "info",
      title: "External URL in description",
      detail: "Review where agents may be told to send data.",
    },
  ]

  const SENSITIVE_PARAM = /(cmd|command|shell|exec|path|file|dir|url|uri|query|sql|host|domain|ip|script|code)/i
  const EXEC_CAPABILITY =
    /\b(exec|execute|shell|subprocess|run[_ ]?(a )?command|terminal|bash|powershell|cmd\.exe|os\.system)\b/i

  function snippet(text: string, match: RegExpMatchArray): string {
    const idx = match.index ?? 0
    const start = Math.max(0, idx - 30)
    const end = Math.min(text.length, idx + match[0].length + 30)
    return text.slice(start, end).replace(/\s+/g, " ").trim()
  }

  function unconstrainedStringParams(inputSchema: unknown): string[] {
    const props = (inputSchema as { properties?: Record<string, Record<string, unknown>> } | undefined)
      ?.properties
    if (!props) return []
    return Object.entries(props)
      .filter(([, spec]) => {
        if (!spec || spec.type !== "string") return false
        return !("maxLength" in spec || "minLength" in spec || "pattern" in spec || "enum" in spec || "format" in spec || "const" in spec)
      })
      .map(([name]) => name)
  }

  export function inspect(tools: GuardedTool[], server: string): Finding[] {
    const findings: Finding[] = []
    for (const tool of tools) {
      const text = [tool.name, tool.description ?? "", JSON.stringify(tool.annotations ?? {})].join("\n")

      for (const pattern of PATTERNS) {
        const match = text.match(pattern.regex)
        if (!match) continue
        findings.push({
          id: pattern.id,
          severity: pattern.severity,
          title: pattern.title,
          detail: pattern.detail,
          tool: tool.name,
          evidence: snippet(text, match),
        })
      }

      if (INVISIBLE.test(text)) {
        findings.push({
          id: "MS-P06",
          severity: "high",
          title: "Invisible Unicode characters",
          detail: "Zero-width or bidi-override characters can hide instructions from reviewers.",
          tool: tool.name,
        })
      }

      const risky = unconstrainedStringParams(tool.inputSchema).filter((name) => SENSITIVE_PARAM.test(name))
      if (risky.length > 0) {
        findings.push({
          id: "MS-S01",
          severity: "medium",
          title: "Injection-prone parameter without constraints",
          detail: "Command-like string params accept arbitrary input (no pattern/enum/maxLength).",
          tool: tool.name,
          evidence: risky.join(", "),
        })
      }

      const exec = EXEC_CAPABILITY.test(text)
      if (exec) {
        findings.push({
          id: "MS-D01",
          severity: "high",
          title: "Command execution capability",
          detail: "Tool can execute operating-system commands.",
          tool: tool.name,
        })
      }
      if (exec && risky.length > 0) {
        findings.push({
          id: "MS-D06",
          severity: "critical",
          title: "Potential command-injection surface",
          detail: "Exec capability plus an unconstrained command-like parameter.",
          tool: tool.name,
          evidence: risky.join(", "),
        })
      }
    }

    if (findings.length > 0) {
      log.warn("guard findings", { server, count: findings.length, ids: findings.map((f) => f.id) })
    }
    return findings
  }

  const ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

  export function worst(findings: Finding[]): Finding | undefined {
    return [...findings].sort((a, b) => ORDER[a.severity] - ORDER[b.severity])[0]
  }
}