import { describe, expect, test } from "bun:test"
import path from "path"
import os from "os"
import fs from "fs/promises"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Vulnerability } from "../../src/session/vulnerability"
import { TriageVulnerabilityTool } from "../../src/tool/triage-vulnerability"
import { ExportPocTool } from "../../src/tool/export-poc"

const projectRoot = path.join(__dirname, "../..")

function ctx(sessionID: string) {
  return {
    sessionID,
    messageID: "",
    callID: "",
    agent: "mergen",
    abort: new AbortController().signal,
    messages: [],
    metadata: () => {},
    ask: async () => {},
  }
}

/** Runs fn inside an Instance with a real session row (vulnerability has a session FK). */
async function withSession(run: (sessionID: string) => Promise<void>) {
  await Instance.provide({
    directory: projectRoot,
    fn: async () => {
      const session = await Session.create({})
      await run(session.id)
    },
  })
}

describe("evidence-bound triage gate", () => {
  test("candidate approval without evidence is refused; with evidence restores claimed severity", async () => {
    await withSession(async (sessionID) => {
      const added = Vulnerability.add({
        sessionID,
        data: {
          severity: "medium",
          title: `${Vulnerability.CANDIDATE_PREFIX}Reflected XSS in search`,
          description: "Reflection observed, execution unconfirmed.",
          candidate: "high",
          endpoint: "GET /search",
        },
      })
      const tool = await TriageVulnerabilityTool.init()

      const refused = await tool.execute({ id: added.id, status: "approved" }, ctx(sessionID))
      expect((refused.metadata as any).refused).toBe(true)
      expect(refused.output).toContain("execution_evidence")
      let stored = Vulnerability.get(sessionID).find((v) => v.id === added.id)!
      expect(stored.candidate).toBe("high")
      expect(stored.severity).toBe("medium")

      const confirmed = await tool.execute(
        { id: added.id, status: "approved", execution_evidence: 'alert("XSS") fired in headless check' },
        ctx(sessionID),
      )
      expect((confirmed.metadata as any).confirmed).toBe(true)
      expect((confirmed.metadata as any).restored_severity).toBe("high")
      stored = Vulnerability.get(sessionID).find((v) => v.id === added.id)!
      expect(stored.candidate).toBeUndefined()
      expect(stored.severity).toBe("high")
      expect(stored.status).toBe("approved")
      expect(stored.title.startsWith(Vulnerability.CANDIDATE_PREFIX)).toBe(false)
      expect(stored.description).toContain("execution evidence supplied]")
    })
  })

  test("non-candidate findings triage exactly as before", async () => {
    await withSession(async (sessionID) => {
      const first = Vulnerability.add({
        sessionID,
        data: { severity: "low", title: "Verbose error banner on /status", description: "Stack trace.", endpoint: "GET /status" },
      })
      const second = Vulnerability.add({
        sessionID,
        data: { severity: "low", title: "Verbose error banner on /status", description: "Same trace.", endpoint: "GET /status" },
      })
      const tool = await TriageVulnerabilityTool.init()

      const dup = await tool.execute({ id: second.id, status: "duplicate", duplicate_of: first.id }, ctx(sessionID))
      expect(dup.output).toContain("duplicate")
      const stored = Vulnerability.get(sessionID).find((v) => v.id === second.id)!
      expect(stored.status).toBe("duplicate")
      expect(stored.duplicate_of).toBe(first.id)

      const ok = await tool.execute({ id: first.id, status: "approved" }, ctx(sessionID))
      expect(ok.output).toContain("approved")
      expect(Vulnerability.get(sessionID).find((v) => v.id === first.id)!.status).toBe("approved")
    })
  })
})

describe("export_poc tool", () => {
  test("refuses candidates and duplicates, writes replay scripts for confirmed findings", async () => {
    await withSession(async (sessionID) => {
      const candidate = Vulnerability.add({
        sessionID,
        data: {
          severity: "medium",
          title: `${Vulnerability.CANDIDATE_PREFIX}SSTI in template name`,
          description: "Unconfirmed.",
          candidate: "critical",
          endpoint: "GET /render",
        },
      })
      const confirmed = Vulnerability.add({
        sessionID,
        data: {
          severity: "high",
          title: "IDOR on order totals",
          description:
            'Any order readable.\n\n[Candidate confirmed -- execution evidence supplied]\nresponse contained "order_total": 0',
          endpoint: "GET /api/orders/{id}",
        },
      })
      const tool = await ExportPocTool.init()
      const outDir = path.join(os.tmpdir(), `mergen-poc-test-${Date.now()}`)

      const refused = await tool.execute({ id: candidate.id, format: "both", out_dir: outDir }, ctx(sessionID))
      expect((refused.metadata as any).refused).toBe(true)

      const exported = await tool.execute({ id: confirmed.id, format: "both", out_dir: outDir }, ctx(sessionID))
      const files = (exported.metadata as any).exported[0].files as string[]
      expect(files).toHaveLength(2)
      const sh = await fs.readFile(files.find((f) => f.endsWith(".sh"))!, "utf8")
      const py = await fs.readFile(files.find((f) => f.endsWith(".py"))!, "utf8")
      expect(sh).toContain("$TARGET/api/orders/1")
      expect(sh).toContain("order_total")
      expect(py).toContain('"/api/orders/1"')
      expect(py).toContain('["order_total"]')
    })
  })

  test("skips findings with nothing replayable when exporting all", async () => {
    await withSession(async (sessionID) => {
      const bare = Vulnerability.add({
        sessionID,
        data: { severity: "info", title: "Server header discloses version", description: "nginx/1.25 seen." },
      })
      const tool = await ExportPocTool.init()
      const outDir = path.join(os.tmpdir(), `mergen-poc-test-all-${Date.now()}`)
      const result = await tool.execute({ format: "both", out_dir: outDir }, ctx(sessionID))
      const skipped = (result.metadata as any).skipped as string[]
      expect(skipped.some((s) => s.includes(bare.id))).toBe(true)
    })
  })
})