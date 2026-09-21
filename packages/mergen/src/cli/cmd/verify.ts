import path from "path"
import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { UI } from "../ui"
import { Verify } from "../../session/verify"

// `mergen verify` -- the fix-regression gate. Replays every exported PoC
// against a (re)deployment and reports which findings still fire. Exit 1
// when anything reproduces, so CI can gate a deploy on the fix holding.

const STYLE: Record<Verify.Status, string> = {
  reproduced: UI.Style.TEXT_DANGER_BOLD,
  fixed: UI.Style.TEXT_SUCCESS_BOLD,
  error: UI.Style.TEXT_WARNING_BOLD,
}

export const VerifyCommand = cmd({
  command: "verify [path]",
  describe: "replay exported PoC scripts and report which findings still reproduce",
  builder: (yargs: Argv) => {
    return yargs
      .positional("path", {
        describe: "PoC file/dir or findings root (default: .mergen/findings)",
        type: "string",
      })
      .option("target", {
        type: "string",
        alias: ["t"],
        describe: "base URL to replay against (sets TARGET for every script)",
      })
      .option("timeout", {
        type: "number",
        describe: "per-script timeout in ms (default: 30000)",
      })
      .option("verbose", { type: "boolean", default: false, describe: "print full script output" })
  },
  handler: async (args) => {
    const root = args.path ? path.resolve(args.path) : path.join(process.cwd(), ".mergen", "findings")
    const files = await Verify.discover(root)
    if (files.length === 0) {
      UI.error(`No PoC scripts found under ${root} -- run export_poc in a session first.`)
      process.exitCode = 2
      return
    }

    const scripts = (await Promise.all(files.map((f) => Verify.load(f)))).filter((s): s is Verify.Script => s !== undefined)
    const target = args.target ?? scripts.find((s) => s.defaultTarget)?.defaultTarget
    if (!target) {
      UI.println(
        UI.Style.TEXT_WARNING_BOLD + "!  " + UI.Style.TEXT_NORMAL +
          "no --target given and scripts carry no recorded target -- passing TARGET is up to you (env).",
      )
    }

    UI.println(
      UI.Style.TEXT_INFO_BOLD + "~  " + UI.Style.TEXT_NORMAL +
        `replaying ${scripts.length} PoC script(s)${target ? ` against ${target}` : ""} ...`,
    )

    const results = await Verify.run(scripts, { target, timeoutMs: args.timeout })

    for (const r of results) {
      const style = STYLE[r.verdict.status]
      UI.println(
        `${style}${r.verdict.status.toUpperCase().padEnd(10)}${UI.Style.TEXT_NORMAL} ${r.script.filename} -- ${r.verdict.detail}`,
      )
      if (args.verbose && r.output.trim()) {
        UI.println(UI.Style.TEXT_DIM + r.output.trimEnd() + UI.Style.TEXT_NORMAL)
      }
    }

    const counts = Verify.summarize(results)
    UI.println("")
    UI.println(
      `verify: ${counts.reproduced} reproduced, ${counts.fixed} fixed, ${counts.error} error(s) out of ${results.length} script(s)`,
    )
    if (counts.reproduced > 0) {
      UI.println(UI.Style.TEXT_DANGER_BOLD + ">> " + UI.Style.TEXT_NORMAL + "regression gate FAILED -- fix did not hold")
    }
    process.exitCode = Verify.exitCode(results)
  },
})