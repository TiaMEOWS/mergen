import { spawn } from "child_process"
import fs from "fs/promises"
import path from "path"

// ============================================================
// VERIFY -- fix-regression gate for exported PoCs. Discovers the
// replayable scripts written by export_poc (.mergen/findings/**
// /poc/*.sh|*.py), replays them against a target deployment, and
// turns each script's self-checking exit code into a verdict:
//
//   exit 0  -> REPRODUCED  (every evidence marker observed:
//                            the finding still fires -- NOT fixed)
//   exit 1  -> FIXED       (marker(s) missing: no longer fires)
//   other   -> ERROR       (timeout / spawn failure: inconclusive)
//
// Parsing and verdicts are pure; only the runner touches a
// process. `mergen verify` exits 1 when anything reproduces, so
// it slots into CI as a regression gate on the fix.
// ============================================================

export namespace Verify {
  export type Language = "curl" | "python"
  export type Status = "reproduced" | "fixed" | "error"

  export interface Script {
    path: string
    filename: string
    language: Language
    markers: string[]
    defaultTarget?: string
  }

  /** Bash template: EXPECTED_MARKERS=('a' 'b c') with '\''-escaped quotes. */
  export function parseShMarkers(content: string): string[] {
    const block = content.match(/^EXPECTED_MARKERS=\((.*)\)\s*$/m)
    if (!block) return []
    const SENTINEL = String.fromCharCode(1)
    const masked = block[1].replace(/'\\''/g, SENTINEL)
    const markers: string[] = []
    for (const m of masked.matchAll(/'([^']*)'/g)) {
      markers.push(m[1].replaceAll(SENTINEL, "'"))
    }
    return markers
  }

  /** Python template: EXPECTED_MARKERS = ["a", "b"] (JSON-serialized). */
  export function parsePyMarkers(content: string): string[] {
    const match = content.match(/^EXPECTED_MARKERS\s*=\s*(\[.*\])\s*$/m)
    if (!match) return []
    try {
      const parsed: unknown = JSON.parse(match[1])
      if (!Array.isArray(parsed)) return []
      return parsed.filter((m): m is string => typeof m === "string")
    } catch {
      return []
    }
  }

  /** TARGET="${TARGET:-https://host}" from the bash template. */
  export function parseShTarget(content: string): string | undefined {
    return content.match(/TARGET="\$\{TARGET:-([^}]*)\}"/)?.[1]
  }

  /** TARGET = os.environ.get("TARGET", "https://host") from the python template. */
  export function parsePyTarget(content: string): string | undefined {
    return content.match(/os\.environ\.get\("TARGET",\s*"([^"]*)"\)/)?.[1]
  }

  const PLACEHOLDER_TARGET = "https://changeme.example.com"

  /** Load a script from disk: language by extension, markers + default target parsed. */
  export async function load(filepath: string): Promise<Script | undefined> {
    const content = await fs.readFile(filepath, "utf8").catch(() => undefined)
    if (content === undefined) return undefined
    const ext = path.extname(filepath).toLowerCase()
    if (ext === ".sh") {
      const target = parseShTarget(content)
      return {
        path: filepath,
        filename: path.basename(filepath),
        language: "curl",
        markers: parseShMarkers(content),
        defaultTarget: target && target !== PLACEHOLDER_TARGET ? target : undefined,
      }
    }
    if (ext === ".py") {
      const target = parsePyTarget(content)
      return {
        path: filepath,
        filename: path.basename(filepath),
        language: "python",
        markers: parsePyMarkers(content),
        defaultTarget: target && target !== PLACEHOLDER_TARGET ? target : undefined,
      }
    }
    return undefined
  }

  /** Collect PoC scripts: a single file, a poc dir, or a findings root (walked recursively). */
  export async function discover(root: string): Promise<string[]> {
    const stat = await fs.stat(root).catch(() => undefined)
    if (!stat) return []
    if (stat.isFile()) return /\.(sh|py)$/i.test(root) ? [root] : []
    const found: string[] = []
    const walk = async (dir: string) => {
      const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => [])
      for (const entry of entries) {
        const full = path.join(dir, entry.name)
        if (entry.isDirectory()) await walk(full)
        else if (/\.(sh|py)$/i.test(entry.name)) found.push(full)
      }
    }
    await walk(root)
    return found.sort()
  }

  export interface RunResult {
    exitCode: number | null
    timedOut: boolean
    error?: string
    output: string
  }

  export type Runner = (script: Script, opts: { target?: string; timeoutMs: number }) => Promise<RunResult>

  /** Shell out: bash for .sh, python(3) for .py. TARGET is passed via env, never interpolated. */
  export const defaultRunner: Runner = (script, opts) =>
    new Promise<RunResult>((resolve) => {
      const bin = script.language === "python" ? (process.platform === "win32" ? "python" : "python3") : "bash"
      const proc = spawn(bin, [script.path], {
        env: { ...process.env, ...(opts.target ? { TARGET: opts.target } : {}) },
        stdio: ["ignore", "pipe", "pipe"],
      })
      let output = ""
      let timedOut = false
      let settled = false
      const done = (result: RunResult) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(result)
      }
      const timer = setTimeout(() => {
        timedOut = true
        proc.kill("SIGKILL")
      }, opts.timeoutMs)
      proc.stdout?.on("data", (chunk) => (output += chunk.toString()))
      proc.stderr?.on("data", (chunk) => (output += chunk.toString()))
      proc.on("error", (err) =>
        done({ exitCode: null, timedOut: false, error: `failed to start ${bin}: ${err.message}`, output }),
      )
      proc.on("exit", (code) => done({ exitCode: code, timedOut, output: output.slice(0, 4000) }))
    })

  export interface Verdict {
    status: Status
    detail: string
  }

  /** Exit-code -> verdict. The scripts self-check evidence markers; we trust the contract. */
  export function verdict(result: RunResult): Verdict {
    if (result.error) return { status: "error", detail: result.error }
    if (result.timedOut) return { status: "error", detail: "replay timed out -- target unreachable or hung" }
    if (result.exitCode === 0)
      return { status: "reproduced", detail: "all expected evidence markers observed -- STILL VULNERABLE" }
    if (result.exitCode === 1) return { status: "fixed", detail: "expected marker(s) missing -- no longer reproducible" }
    return { status: "error", detail: `unexpected exit code ${result.exitCode}` }
  }

  export interface FindingResult {
    script: Script
    verdict: Verdict
    output: string
  }

  /** Replay scripts sequentially -- a verify run should never hammer the target in parallel. */
  export async function run(
    scripts: Script[],
    opts: { target?: string; timeoutMs?: number; runner?: Runner } = {},
  ): Promise<FindingResult[]> {
    const runner = opts.runner ?? defaultRunner
    const timeoutMs = opts.timeoutMs ?? 30_000
    const results: FindingResult[] = []
    for (const script of scripts) {
      const target = opts.target ?? script.defaultTarget
      const result = await runner(script, { target, timeoutMs })
      results.push({ script, verdict: verdict(result), output: result.output })
    }
    return results
  }

  /** Process exit code for CI: 1 when anything reproduces (gate failed), else 0. */
  export function exitCode(results: FindingResult[]): number {
    return results.some((r) => r.verdict.status === "reproduced") ? 1 : 0
  }

  export function summarize(results: FindingResult[]): Record<Status, number> {
    const counts: Record<Status, number> = { reproduced: 0, fixed: 0, error: 0 }
    for (const r of results) counts[r.verdict.status]++
    return counts
  }
}