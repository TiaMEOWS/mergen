import path from "path"
import fs from "fs/promises"
import z from "zod"
import { Tool } from "./tool"
import { Session } from "../session"
import { Vulnerability } from "../session/vulnerability"
import { Poc } from "../session/poc"
import { Instance } from "../project/instance"

type ExportMeta = {
  refused?: boolean
  candidate?: Vulnerability.Info["candidate"]
  exported?: { id: string; files: string[] }[]
  skipped?: string[]
}

const DESCRIPTION = `Export a confirmed finding as a REPLAYABLE PoC script (curl .sh and/or stdlib-python .py).

The script replays the exploit request -- extracted verbatim when the PoC contains curl commands, otherwise synthesized from the endpoint -- and greps the response for the recorded evidence markers. Exit 0 = reproduced, 1 = marker(s) missing. Attach it to the report or re-run it yourself before submitting.

Only CONFIRMED findings are exportable: candidates carry no executable evidence (confirm them via triage_vulnerability with execution_evidence first) and duplicates point at the original record.

Writes to .mergen/findings/<session>/poc/ under the project by default; override with out_dir.`

export const ExportPocTool = Tool.define("export_poc", {
  description: DESCRIPTION,
  parameters: z.object({
    id: z.string().optional().describe("Finding id from report_vulnerability. Omit to export every confirmed finding."),
    format: z.enum(["curl", "python", "both"]).default("both").describe("Script format(s) to generate"),
    out_dir: z.string().optional().describe("Output directory (default: .mergen/findings/<session>/poc)"),
  }),
  async execute(params, ctx) {
    const root = Session.root(ctx.sessionID)
    const all = Vulnerability.get(root)

    let targets: Vulnerability.Info[]
    if (params.id) {
      const finding = all.find((v) => v.id === params.id)
      if (!finding) {
        return { title: "Export error", output: `No finding ${params.id} in this session.`, metadata: {} }
      }
      if (finding.candidate != null) {
        return {
          title: `Refused: ${params.id} is an unconfirmed candidate`,
          output: `${params.id} is an UNCONFIRMED CANDIDATE -- no executable evidence was recorded, so there is nothing trustworthy to replay. Confirm it first: triage_vulnerability(id: "${params.id}", status: "approved", execution_evidence: "<observed proof>").`,
          metadata: { refused: true, candidate: finding.candidate } satisfies ExportMeta as ExportMeta,
        }
      }
      if (finding.status === "duplicate" || finding.duplicate_of) {
        return {
          title: `Skipped: ${params.id} is a duplicate`,
          output: `${params.id} is a duplicate of ${finding.duplicate_of ?? "another finding"} -- export the original instead.`,
          metadata: {},
        }
      }
      targets = [finding]
    } else {
      targets = all.filter((v) => v.candidate == null && v.status !== "duplicate" && !v.duplicate_of)
      if (targets.length === 0) {
        return {
          title: "Nothing to export",
          output:
            "No confirmed findings with replay material. Candidates must be confirmed with execution evidence before export.",
          metadata: {},
        }
      }
    }

    const base = params.out_dir ?? path.join(Instance.directory, ".mergen", "findings", root, "poc")
    const written: { id: string; files: string[]; scripts: Poc.Script[] }[] = []
    const skipped: string[] = []
    for (const vuln of targets) {
      const scripts = Poc.build(vuln, params.format)
      if (scripts.length === 0) {
        skipped.push(`${vuln.id}: ${vuln.title} (no curl commands in poc and no usable endpoint -- nothing replayable)`)
        continue
      }
      const files: string[] = []
      for (const script of scripts) {
        const filepath = path.join(base, script.filename)
        await fs.mkdir(path.dirname(filepath), { recursive: true })
        await fs.writeFile(filepath, script.content, "utf8")
        files.push(filepath)
      }
      written.push({ id: vuln.id!, files, scripts })
    }

    const lines: string[] = []
    if (params.id && written.length === 1) {
      lines.push(`Exported ${written[0].files.length} replayable script(s) for ${params.id}:`)
      for (const file of written[0].files) lines.push(`  ${file}`)
      for (const script of written[0].scripts) {
        lines.push("", `--- ${script.filename} (${script.language}) ---`, "```", script.content.trimEnd(), "```")
      }
    } else {
      lines.push(`Exported replayable PoC scripts for ${written.length} finding(s) to ${base}:`)
      for (const w of written) for (const file of w.files) lines.push(`  ${file}`)
    }
    if (skipped.length > 0) lines.push("", "Skipped (nothing replayable):", ...skipped.map((s) => `  ${s}`))
    lines.push(
      "",
      "Scripts exit 0 when every expected evidence marker is observed. Set TARGET=https://host or edit the script before replaying.",
    )

    const scriptCount = written.reduce((n, w) => n + w.files.length, 0)
    return {
      title: `PoC export: ${written.length} finding(s), ${scriptCount} script(s)`,
      output: lines.join("\n"),
      metadata: { exported: written.map((w) => ({ id: w.id, files: w.files })), skipped } satisfies ExportMeta as ExportMeta,
    }
  },
})