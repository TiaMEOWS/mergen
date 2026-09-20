import path from "path"
import { cmd } from "./cmd"
import { RunCommand } from "./run"
import { UI } from "../ui"
import { Campaign } from "../../scope/campaign"
import type { Argv } from "yargs"

// CAMPAIGN MODE -- fully autonomous, scope-bound engagement. One target, no human
// in the loop: permissions auto-allow, the question tool stays denied, and the
// Scope Firewall is the hard boundary. Scope discipline is never bypassed:
// existing scope files are enforced as-is, new ones are derived from the target.

function directive(target: string, scopePath: string): string {
  return [
    "CAMPAIGN MODE -- autonomous, authorized security engagement.",
    "",
    `PRIMARY TARGET: ${target}`,
    `SCOPE: hard-enforced by the Scope Firewall (${scopePath}). If a host is blocked, it is out of scope -- log it as an assumption and move on. NEVER attempt to bypass or weaken the firewall.`,
    "",
    "OPERATING RULES:",
    "1. No human is present and the question tool is disabled. Make reasonable assumptions, record them for the final report, and keep going.",
    "2. Work the methodology phases IN ORDER: recon -> attack-surface mapping (add_intel) -> vulnerability testing per applicable skill classes (update_vrt_check as you complete checks) -> evidence-backed confirmation -> reporting.",
    "3. Prefer dedicated tools over raw shell: hackbrowser for crawling, http_replay / inject_probe for exploitation, attack_script for known modules.",
    "4. Execution-dependent findings MUST be observed firing before being filed at high/critical: report via report_vulnerability with execution_evidence (the observed alert/flag/output, not a narrative). Unconfirmed findings stay candidates -- that is by design.",
    "5. Triage immediately: whenever report_vulnerability lists similar findings, resolve them with triage_vulnerability before moving on.",
    "6. Persistence over speed: after 3 failed attempts on one vector, record the attempt and pivot -- never loop.",
    "",
    "FINISH (mandatory, in this order):",
    "- generate_report with ALL sections",
    "- export_poc for every confirmed finding",
    "- close with a short operator summary: findings by severity, coverage %, PoC export paths, open assumptions.",
    "",
    "Begin recon on the primary target now.",
  ].join("\n")
}

export const CampaignCommand = cmd({
  command: "campaign <target>",
  describe: "run a fully autonomous pentest campaign against an in-scope target",
  builder: (yargs: Argv) => {
    return yargs
      .positional("target", {
        describe: "primary target (domain, URL, or IP)",
        type: "string",
        demandOption: true,
      })
      .option("scope", {
        type: "string",
        array: true,
        describe: "extra in-scope items (only used when a new scope file is created)",
      })
      .option("model", { type: "string", alias: ["m"], describe: "model to use (provider/model)" })
      .option("agent", { type: "string", describe: "agent to run the campaign as" })
      .option("format", { type: "string", choices: ["default", "json"], default: "default" })
      .option("title", { type: "string", describe: "session title" })
      .option("attach", { type: "string", describe: "attach to a running mergen server" })
      .option("dir", { type: "string", describe: "directory to run in" })
      .option("port", { type: "number", describe: "port for the local server" })
  },
  handler: async (args) => {
    const directory = args.dir ? path.resolve(args.dir) : process.cwd()

    let prep: Campaign.Prep
    try {
      prep = await Campaign.prepare(directory, args.target, args.scope ?? [])
    } catch (err) {
      UI.error(err instanceof Error ? err.message : String(err))
      process.exit(1)
    }

    UI.println(UI.Style.TEXT_SUCCESS_BOLD + ">> " + UI.Style.TEXT_NORMAL + `campaign target: ${args.target}`)
    if (prep.created) {
      UI.println(
        UI.Style.TEXT_WARNING_BOLD + "!  " +
          UI.Style.TEXT_NORMAL +
          `no scope file existed -- wrote ${prep.path} (mode: block). Review it; the Scope Firewall enforces it.`,
      )
    } else {
      UI.println(UI.Style.TEXT_INFO_BOLD + "~  " + UI.Style.TEXT_NORMAL + `scope verified against ${prep.path}`)
    }

    // Autonomy: allow every permission (the Scope Firewall remains the hard boundary),
    // keep the question tool denied (session rule in run.ts). An operator running
    // `campaign` has explicitly authorized the engagement.
    process.env.MERGEN_PERMISSION = JSON.stringify({ "*": "allow" })

    const message = directive(args.target, prep.path)
    await RunCommand.handler({
      _: [],
      "--": [],
      message: [message],
      command: undefined,
      continue: false,
      session: undefined,
      fork: false,
      share: false,
      model: args.model,
      agent: args.agent,
      format: args.format,
      file: [],
      title: args.title ?? `campaign: ${args.target}`,
      attach: args.attach,
      dir: args.dir,
      port: args.port,
      variant: undefined,
      thinking: false,
    } as any)
  },
})