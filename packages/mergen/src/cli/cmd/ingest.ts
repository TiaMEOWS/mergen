import path from "path"
import fs from "fs/promises"
import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { bootstrap } from "../bootstrap"
import { UI } from "../ui"
import { Session } from "../../session"
import { Request } from "../../session/request"
import { Traffic } from "../../session/traffic"

// `mergen ingest` -- pull recorded HTTP traffic (HAR from browser devtools,
// Burp Suite XML export) into a session's Request table so the agent works
// from REAL observed traffic instead of guessing endpoints. Dedup is
// structural (key_hash conflict): re-importing the same capture is a no-op.

export const IngestCommand = cmd({
  command: "ingest <file>",
  describe: "import HTTP traffic (HAR / Burp XML) into a session for analysis",
  builder: (yargs: Argv) => {
    return yargs
      .positional("file", { describe: "path to a .har or Burp XML export", type: "string", demandOption: true })
      .option("session", { type: "string", alias: ["s"], describe: "existing session id (default: create a new one)" })
      .option("title", { type: "string", describe: "title for the created session" })
  },
  handler: async (args) => {
    const text = await fs.readFile(args.file, "utf8").catch(() => undefined)
    if (text === undefined) {
      UI.error(`File not found: ${args.file}`)
      process.exitCode = 1
      return
    }

    const format = Traffic.detect(args.file, text)
    if (!format) {
      UI.error(`Unrecognized format: ${args.file} -- expected a HAR (JSON) or Burp XML export.`)
      process.exitCode = 1
      return
    }

    let entries: Traffic.Entry[]
    try {
      entries = format === "har" ? Traffic.parseHAR(text) : Traffic.parseBurp(text)
    } catch (err) {
      UI.error(`Failed to parse ${args.file}: ${err instanceof Error ? err.message : String(err)}`)
      process.exitCode = 1
      return
    }
    if (entries.length === 0) {
      UI.error("No HTTP requests found in the file.")
      process.exitCode = 1
      return
    }

    await bootstrap(process.cwd(), async () => {
      let sessionID = args.session
      if (sessionID) {
        const existing = await Session.get(sessionID).catch(() => undefined)
        if (!existing) {
          UI.error(`Session not found: ${sessionID}`)
          process.exitCode = 1
          return
        }
      } else {
        const session = await Session.create({ title: args.title ?? `ingest: ${path.basename(args.file)}` })
        sessionID = session.id
      }

      let added = 0
      let dupes = 0
      let skipped = 0
      for (const entry of entries) {
        const input = Traffic.toRowInput(entry, sessionID)
        if (!input) {
          skipped++
          continue
        }
        const row = Request.add(input)
        if (row) added++
        else dupes++
      }

      UI.println(
        UI.Style.TEXT_SUCCESS_BOLD + ">> " + UI.Style.TEXT_NORMAL +
          `ingested ${added} request(s) into session ${sessionID}` +
          (dupes > 0 ? ` (${dupes} structural duplicate(s) skipped)` : "") +
          (skipped > 0 ? ` (${skipped} unsupported row(s) skipped)` : ""),
      )
      UI.println(
        UI.Style.TEXT_INFO_BOLD + "~  " + UI.Style.TEXT_NORMAL +
          `next: mergen run --session ${sessionID} "map the attack surface from the imported traffic, then test it"`,
      )
    })
  },
})