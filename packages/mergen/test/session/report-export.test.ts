import { describe, expect, test } from "bun:test"
import { Sarif, Pdf } from "../../src/session/report-export"
import type { Vulnerability } from "../../src/session/vulnerability"

function finding(over: Partial<Vulnerability.Info> = {}): Vulnerability.Info {
  return {
    id: "vuln-1",
    severity: "high",
    title: "SQL injection in login",
    description: "The username parameter is concatenated into the query.\nSecond line.",
    cwe_id: "CWE-89",
    endpoint: "POST /api/login",
    status: "open",
    ...over,
  } as Vulnerability.Info
}

describe("sarif export", () => {
  test("emits SARIF 2.1.0 with rules deduped by cwe", () => {
    const sarif = JSON.parse(Sarif.build([finding(), finding({ id: "vuln-2" }), finding({ id: "vuln-3", cwe_id: undefined, title: "Open redirect" })]))
    expect(sarif.version).toBe("2.1.0")
    expect(sarif.$schema).toContain("sarif-2.1.0")
    const driver = sarif.runs[0].tool.driver
    expect(driver.name).toBe("Mergen")
    const ruleIds = driver.rules.map((r: { id: string }) => r.id)
    expect(ruleIds).toEqual(["CWE-89", "open-redirect"])
    expect(driver.rules[0].helpUri).toBe("https://cwe.mitre.org/data/definitions/89.html")
    expect(driver.rules[0].properties["security-severity"]).toBe("8.0")
    expect(sarif.runs[0].results).toHaveLength(3)
  })

  test("maps severity to SARIF levels", () => {
    const sarif = JSON.parse(
      Sarif.build([
        finding({ id: "a", severity: "critical" }),
        finding({ id: "b", severity: "medium" }),
        finding({ id: "c", severity: "info" }),
      ]),
    )
    const levels = sarif.runs[0].results.map((r: { level: string }) => r.level)
    expect(levels).toEqual(["error", "warning", "note"])
  })

  test("candidates and duplicates are excluded from the run", () => {
    const sarif = JSON.parse(
      Sarif.build([
        finding({ id: "ok" }),
        finding({ id: "cand", candidate: "medium" as Vulnerability.Info["severity"] }),
        finding({ id: "dup", duplicate_of: "ok" }),
        finding({ id: "dup2", status: "duplicate" as Vulnerability.Info["status"] }),
      ]),
    )
    const ids = sarif.runs[0].results.map((r: { partialFingerprints: Record<string, string> }) => r.partialFingerprints["mergen/findingId"])
    expect(ids).toEqual(["ok"])
  })

  test("endpoint becomes the artifact location, file+line wins when present", () => {
    const sarif = JSON.parse(
      Sarif.build([
        finding({ id: "ep" }),
        finding({ id: "fl", endpoint: undefined, file: "src\\routes\\login.ts", line_start: 42, line_end: 45 }),
      ]),
    )
    const [ep, fl] = sarif.runs[0].results
    expect(ep.locations[0].physicalLocation.artifactLocation.uri).toBe("/api/login")
    expect(fl.locations[0].physicalLocation.artifactLocation.uri).toBe("src/routes/login.ts")
    expect(fl.locations[0].physicalLocation.region.startLine).toBe(42)
    expect(fl.locations[0].physicalLocation.region.endLine).toBe(45)
  })

  test("finding without file or endpoint omits locations", () => {
    const sarif = JSON.parse(Sarif.build([finding({ endpoint: undefined })]))
    expect(sarif.runs[0].results[0].locations).toBeUndefined()
  })
})

describe("pdf export", () => {
  test("produces a structurally valid single-page PDF", () => {
    const buf = Pdf.build("Test Report", "Hello world\n\n**Bold** finding in `login.ts`")
    const text = buf.toString("latin1")
    expect(text.startsWith("%PDF-1.4")).toBe(true)
    expect(text.trimEnd().endsWith("%%EOF")).toBe(true)
    expect(text).toContain("/Type /Catalog")
    expect(text).toContain("/Pages")
    expect(text.match(/\/Type \/Page[^s]/g)).toHaveLength(1)
    expect(text).toContain("xref")
    expect(text).toContain("startxref")
    expect(text).toContain("Hello world")
    expect(text).toContain("Bold finding in login.ts")
  })

  test("paginates long reports and escapes parens/backslashes", () => {
    const longBody = Array.from({ length: 130 }, (_, i) => `line ${i} (with parens) and \\ backslash`).join("\n")
    const buf = Pdf.build("Long", longBody)
    const text = buf.toString("latin1")
    expect(text.match(/\/Type \/Page[^s]/g)!.length).toBeGreaterThanOrEqual(3)
    expect(text).toContain("\\(with parens\\)")
    expect(text).toContain("\\\\ backslash")
  })

  test("non-latin1 characters degrade to ? instead of corrupting offsets", () => {
    const buf = Pdf.build("Unicode", "Turkish: şğü ok -- emoji: \u{1F600} end")
    const text = buf.toString("latin1")
    expect(text).toContain("Turkish: ??ü ok -- emoji: ? end")
    expect(text.trimEnd().endsWith("%%EOF")).toBe(true)
  })

  test("wraps long lines at word boundaries", () => {
    const long = "word ".repeat(40).trim()
    const buf = Pdf.build("Wrap", long)
    const text = buf.toString("latin1")
    const shown = text.match(/\(word[^)]*\) Tj/g) ?? []
    expect(shown.length).toBeGreaterThan(1)
    for (const s of shown) expect(s.length).toBeLessThanOrEqual(100)
  })
})