import { Vulnerability } from "./vulnerability"

// ============================================================
// REPORT EXPORT -- findings leave Mergen in two machine shapes:
//
//   Sarif.build -> SARIF 2.1.0 JSON for GitHub Code Scanning and
//                  any SARIF viewer. Rules are deduped per CWE /
//                  title; only confirmed, non-duplicate findings
//                  are emitted (candidates carry no evidence --
//                  exporting them would poison the scanner).
//
//   Pdf.build   -> dependency-free PDF writer (Type1 Helvetica,
//                  WinAnsi). Enough for a human-readable report
//                  artifact; markdown markup is flattened to text.
// ============================================================

export namespace Sarif {
  const LEVEL: Record<string, string> = {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "note",
    info: "note",
  }

  const SCORE: Record<string, string> = {
    critical: "9.5",
    high: "8.0",
    medium: "5.5",
    low: "2.5",
    info: "0.0",
  }

  export interface Options {
    toolVersion?: string
    informationUri?: string
  }

  function slug(text: string): string {
    const s = text
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 60)
    return s || "finding"
  }

  function ruleID(v: Vulnerability.Info): string {
    return v.cwe_id?.toUpperCase().match(/^CWE-\d+$/) ? v.cwe_id.toUpperCase() : slug(v.title)
  }

  function cweUri(cwe?: string): string | undefined {
    const num = cwe?.match(/(\d+)/)?.[1]
    return num ? `https://cwe.mitre.org/data/definitions/${num}.html` : undefined
  }

  function locationOf(v: Vulnerability.Info): Record<string, unknown> | undefined {
    if (v.file) {
      return {
        physicalLocation: {
          artifactLocation: { uri: v.file.replace(/\\/g, "/") },
          ...(v.line_start ? { region: { startLine: v.line_start, ...(v.line_end ? { endLine: v.line_end } : {}) } } : {}),
        },
      }
    }
    if (v.endpoint) {
      const path = v.endpoint.trim().replace(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/i, "")
      if (path) return { physicalLocation: { artifactLocation: { uri: path } } }
    }
    return undefined
  }

  export function build(findings: Vulnerability.Info[], opts: Options = {}): string {
    const eligible = findings.filter((v) => v.candidate == null && v.status !== "duplicate" && !v.duplicate_of)

    const rules = new Map<string, Record<string, unknown>>()
    for (const v of eligible) {
      const id = ruleID(v)
      if (rules.has(id)) continue
      rules.set(id, {
        id,
        name: v.cwe_id ?? v.title.slice(0, 80),
        shortDescription: { text: v.title.slice(0, 120) },
        ...(cweUri(v.cwe_id) ? { helpUri: cweUri(v.cwe_id) } : {}),
        properties: {
          "security-severity": SCORE[v.severity] ?? "5.5",
          tags: ["security", v.severity, ...(v.cwe_id ? [v.cwe_id.toUpperCase()] : [])],
        },
      })
    }

    const results = eligible.map((v) => ({
      ruleId: ruleID(v),
      level: LEVEL[v.severity] ?? "warning",
      message: {
        text: [v.title, v.description?.split("\n").find((l) => l.trim())?.trim()].filter(Boolean).join(" -- "),
      },
      ...(locationOf(v) ? { locations: [locationOf(v)] } : {}),
      partialFingerprints: { "mergen/findingId": v.id ?? slug(v.title) },
      properties: { severity: v.severity, status: v.status, ...(v.endpoint ? { endpoint: v.endpoint } : {}) },
    }))

    return JSON.stringify(
      {
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [
          {
            tool: {
              driver: {
                name: "Mergen",
                ...(opts.toolVersion ? { version: opts.toolVersion } : {}),
                informationUri: opts.informationUri ?? "https://github.com/TiaMEOWS/mergen",
                rules: [...rules.values()],
              },
            },
            results,
          },
        ],
      },
      null,
      2,
    )
  }
}

export namespace Pdf {
  const PAGE_W = 595
  const PAGE_H = 842
  const MARGIN = 56
  const FONT_SIZE = 9
  const LEADING = 12.5
  const TITLE_SIZE = 15
  const LINES_PER_PAGE = 56
  const WRAP = 95

  /** Flatten markdown to WinAnsi-safe plain text (Type1 core fonts know nothing else). */
  export function sanitizeLine(line: string): string {
    const text = line
      .replace(/<!--.*?-->/g, "")
      .replace(/^#{1,6}\s*/, "")
      .replace(/\*\*([^*]+)\*\*/g, "$1")
      .replace(/__([^_]+)__/g, "$1")
      .replace(/`([^`]*)`/g, "$1")
    let out = ""
    for (const ch of text) {
      const code = ch.codePointAt(0) ?? 63
      if (code === 9) out += "    "
      else if (code >= 32 && code <= 255) out += ch
      else out += "?"
    }
    return out
  }

  function wrap(line: string): string[] {
    if (line.length <= WRAP) return [line]
    const out: string[] = []
    let rest = line
    while (rest.length > WRAP) {
      let cut = rest.lastIndexOf(" ", WRAP)
      if (cut < 40) cut = WRAP
      out.push(rest.slice(0, cut))
      rest = rest.slice(cut).trimStart()
    }
    out.push(rest)
    return out
  }

  function esc(text: string): string {
    return text.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)")
  }

  /** Minimal valid single-font PDF: A4, Helvetica, fixed leading, paginated. */
  export function build(title: string, markdown: string): Buffer {
    const lines: string[] = []
    for (const raw of markdown.split(/\r?\n/)) {
      const clean = sanitizeLine(raw)
      if (/^-{3,}\s*$/.test(clean)) {
        lines.push("")
        continue
      }
      lines.push(...wrap(clean))
    }

    const pages: string[][] = []
    for (let i = 0; i < lines.length; i += LINES_PER_PAGE) pages.push(lines.slice(i, i + LINES_PER_PAGE))
    if (pages.length === 0) pages.push([])

    const pageCount = pages.length
    const fontRegular = 3 + pageCount * 2
    const fontBold = fontRegular + 1
    const objects: string[] = []

    objects[0] = "<< /Type /Catalog /Pages 2 0 R >>"
    objects[1] = `<< /Type /Pages /Kids [${pages.map((_, i) => `${3 + i * 2} 0 R`).join(" ")}] /Count ${pageCount} >>`

    pages.forEach((pageLines, i) => {
      const pageObj = 3 + i * 2
      const contentObj = pageObj + 1
      objects[pageObj - 1] =
        `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
        `/Resources << /Font << /F1 ${fontRegular} 0 R /F2 ${fontBold} 0 R >> >> /Contents ${contentObj} 0 R >>`
      const parts: string[] = []
      let y = PAGE_H - 54
      if (i === 0) {
        parts.push(`BT /F2 ${TITLE_SIZE} Tf ${MARGIN} ${y} Td (${esc(sanitizeLine(title))}) Tj ET`)
        y -= 26
      }
      parts.push(`BT /F1 ${FONT_SIZE} Tf ${MARGIN} ${y} Td ${LEADING} TL`)
      for (const line of pageLines) parts.push(`(${esc(line)}) Tj T*`)
      parts.push("ET")
      const stream = parts.join("\n")
      objects[contentObj - 1] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`
    })

    objects[fontRegular - 1] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    objects[fontBold - 1] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"

    let out = "%PDF-1.4\n%" + String.fromCharCode(0xe2, 0xe3, 0xcf, 0xd3) + "\n"
    const offsets: number[] = []
    objects.forEach((body, i) => {
      offsets.push(out.length)
      out += `${i + 1} 0 obj\n${body}\nendobj\n`
    })
    const xrefStart = out.length
    out += `xref\n0 ${objects.length + 1}\n`
    out += "0000000000 65535 f \n"
    for (const off of offsets) out += `${off.toString().padStart(10, "0")} 00000 n \n`
    out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`
    return Buffer.from(out, "latin1")
  }
}