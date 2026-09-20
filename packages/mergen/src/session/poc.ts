import { Vulnerability } from "./vulnerability"

// ============================================================
// REPLAYABLE PoC EXPORT -- turns a confirmed finding into a
// standalone, re-runnable verification script (curl / python).
// Pure functions: no DB, no Instance state. Candidate findings
// are refused at the tool layer (evidence-bound rule): only a
// confirmed finding carries executable evidence worth replaying.
// ============================================================

export namespace Poc {
  export interface Script {
    filename: string
    language: "curl" | "python"
    content: string
  }

  /** Tail marker of the evidence block appended by the report/triage upgrade paths. */
  const EVIDENCE_NEEDLE = "execution evidence supplied]"

  export function slugify(title: string): string {
    const slug = title
      .replace(/\[unconfirmed candidate\]\s*/i, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 60)
    return slug || "finding"
  }

  function safeID(id?: string): string {
    return (id ?? "finding").replace(/[^a-zA-Z0-9_-]/g, "-")
  }

  /** The executable-evidence block recorded when the finding was confirmed. */
  export function extractEvidence(vuln: Vulnerability.Info): string | undefined {
    const text = vuln.description ?? ""
    const idx = text.lastIndexOf(EVIDENCE_NEEDLE)
    if (idx < 0) return undefined
    const body = text.slice(idx + EVIDENCE_NEEDLE.length).trim()
    return body || undefined
  }

  /** Short literal markers to grep for on replay: quoted strings from the evidence
   *  block (max 3). Falls back to the first evidence line when nothing is quoted. */
  export function evidenceMarkers(evidence?: string): string[] {
    if (!evidence) return []
    const quoted = [...evidence.matchAll(/["'`]([^"'`\n]{3,80})["'`]/g)].map((m) => m[1])
    const unique = [...new Set(quoted)].slice(0, 3)
    if (unique.length > 0) return unique
    const firstLine = evidence
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line.length >= 3)
    return firstLine ? [firstLine.slice(0, 80)] : []
  }

  /** curl commands found in free text: fenced blocks that contain curl, plus bare curl lines. */
  export function extractCurlCommands(...texts: (string | undefined)[]): string[] {
    const commands: string[] = []
    for (const text of texts) {
      if (!text) continue
      for (const fence of text.matchAll(/```[a-z]*\s*\n([\s\S]*?)```/g)) {
        const block = fence[1].trim()
        if (/(^|\n)\s*curl\s/i.test(block) && !commands.includes(block)) commands.push(block)
      }
      for (const line of text.split("\n")) {
        const trimmed = line.trim()
        if (/^curl\s/i.test(trimmed) && !commands.some((cmd) => cmd.includes(trimmed))) commands.push(trimmed)
      }
    }
    return commands
  }

  export interface Endpoint {
    method: string
    path: string
  }

  /** "GET /api/orders/{id}" -> { method: "GET", path: "/api/orders/1" } (concrete placeholder). */
  export function parseEndpoint(endpoint?: string): Endpoint | undefined {
    if (!endpoint) return undefined
    const trimmed = endpoint.trim()
    const match = trimmed.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)$/i)
    const method = (match?.[1] ?? "GET").toUpperCase()
    const rawPath = (match?.[2] ?? trimmed).split(/\s/)[0]
    if (!rawPath.startsWith("/")) return undefined
    return { method, path: rawPath.replace(/\{[^}]+\}/g, "1") }
  }

  function shellSingle(value: string): string {
    return `'${value.replace(/'/g, `'\\''`)}'`
  }

  function header(vuln: Vulnerability.Info, comment: string): string[] {
    const title = vuln.title.replace(Vulnerability.CANDIDATE_PREFIX, "")
    return [
      `${comment} Mergen replayable PoC -- ${title}`,
      `${comment} Finding: ${vuln.id ?? "unknown"} | Severity: ${vuln.severity.toUpperCase()}${vuln.cwe_id ? ` | ${vuln.cwe_id}` : ""}`,
      ...(vuln.endpoint ? [`${comment} Endpoint: ${vuln.endpoint}`] : []),
      `${comment} Review before running. Only ever replay against targets you are authorized to test.`,
      `${comment} Exit 0 = every expected marker observed (reproduces). Exit 1 = marker(s) missing.`,
    ]
  }

  export function buildCurl(vuln: Vulnerability.Info): Script | undefined {
    const extracted = extractCurlCommands(vuln.poc, vuln.steps_to_reproduce)
    const endpoint = parseEndpoint(vuln.endpoint)
    if (extracted.length === 0 && !endpoint) return undefined
    const markers = evidenceMarkers(extractEvidence(vuln))

    const replay =
      extracted.length > 0
        ? extracted
        : [`curl -i -s -X ${endpoint!.method} "$TARGET${endpoint!.path}" -H "User-Agent: mergen-poc-replay"`]

    const lines = [
      "#!/usr/bin/env bash",
      ...header(vuln, "#"),
      "set -euo pipefail",
      "",
      'TARGET="${TARGET:-https://changeme.example.com}"  # override: TARGET=https://host ./poc.sh',
      `EXPECTED_MARKERS=(${markers.map(shellSingle).join(" ")})`,
      "",
      "replay() {",
      ...replay.map((cmd) => `  ${cmd}`),
      "}",
      "",
      'OUTPUT="$(replay)"',
      'printf \'%s\n\' "$OUTPUT"',
      "",
      "missing=0",
      'if [ "${#EXPECTED_MARKERS[@]}" -gt 0 ]; then',
      '  for marker in "${EXPECTED_MARKERS[@]}"; do',
      '    if ! grep -qF -- "$marker" <<<"$OUTPUT"; then',
      '      echo "MISSING expected marker: $marker" >&2',
      "      missing=1",
      "    fi",
      "  done",
      '  if [ "$missing" -eq 0 ]; then echo "REPRODUCED: all expected markers observed"; fi',
      "else",
      '  echo "No evidence markers recorded -- verify the response above manually."',
      "fi",
      'exit "$missing"',
      "",
    ]
    return {
      filename: `${safeID(vuln.id)}-${slugify(vuln.title)}.sh`,
      language: "curl",
      content: lines.join("\n"),
    }
  }

  export function buildPython(vuln: Vulnerability.Info): Script | undefined {
    const endpoint = parseEndpoint(vuln.endpoint)
    if (!endpoint) return undefined
    const markers = evidenceMarkers(extractEvidence(vuln))

    const lines = [
      "#!/usr/bin/env python3",
      '"""',
      ...header(vuln, "#"),
      '"""',
      "import os",
      "import sys",
      "import urllib.error",
      "import urllib.request",
      "",
      'TARGET = os.environ.get("TARGET", "https://changeme.example.com").rstrip("/")',
      `URL = TARGET + ${JSON.stringify(endpoint.path)}`,
      `METHOD = ${JSON.stringify(endpoint.method)}`,
      'HEADERS = {"User-Agent": "mergen-poc-replay"}',
      "BODY = None  # set bytes here if the exploit needs a request body",
      `EXPECTED_MARKERS = ${JSON.stringify(markers)}`,
      "",
      "",
      "def main() -> int:",
      '    req = urllib.request.Request(URL, method=METHOD, headers=HEADERS, data=BODY)',
      "    try:",
      "        with urllib.request.urlopen(req, timeout=15) as resp:",
      '            body = resp.read().decode("utf-8", "replace")',
      "            status = resp.status",
      "    except urllib.error.HTTPError as exc:",
      '        body = exc.read().decode("utf-8", "replace")',
      "        status = exc.code",
      '    print(f"HTTP {status} -- {len(body)} bytes from {URL}")',
      "    missing = [marker for marker in EXPECTED_MARKERS if marker not in body]",
      "    for marker in missing:",
      '        print(f"MISSING expected marker: {marker}", file=sys.stderr)',
      "    if not EXPECTED_MARKERS:",
      '        print("No evidence markers recorded -- verify the response above manually.")',
      "        return 0",
      "    if missing:",
      "        return 1",
      '    print("REPRODUCED: all expected markers observed")',
      "    return 0",
      "",
      "",
      'if __name__ == "__main__":',
      "    sys.exit(main())",
      "",
    ]
    return {
      filename: `${safeID(vuln.id)}-${slugify(vuln.title)}.py`,
      language: "python",
      content: lines.join("\n"),
    }
  }

  /** Every replay format available for a finding (empty when nothing is replayable). */
  export function build(vuln: Vulnerability.Info, format: "curl" | "python" | "both" = "both"): Script[] {
    const scripts: Script[] = []
    if (format === "curl" || format === "both") {
      const script = buildCurl(vuln)
      if (script) scripts.push(script)
    }
    if (format === "python" || format === "both") {
      const script = buildPython(vuln)
      if (script) scripts.push(script)
    }
    return scripts
  }
}