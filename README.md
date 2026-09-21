<p align="center">
  <img src="assets/banner.svg" alt="Mergen" width="100%"/>
</p>

<p align="center">
  <b>Named after Mergen, the divine archer of Turkic mythology — the one who never misses.</b><br/>
  AI-powered offensive security harness: an agentic TUI that arrives with a battle-tested
  attack knowledge base and the discipline to use it on authorized targets.
</p>

<p align="center">
  <i>The only AI harness that can't leave scope, can't load poisoned tools, and can't claim what it can't prove.</i>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License"/></a>
  <img src="https://img.shields.io/badge/runtime-bun%201.3-black" alt="bun"/>
  <img src="https://img.shields.io/badge/attack_skills-40%2B-e8b14b" alt="skills"/>
  <img src="https://img.shields.io/badge/knowledge_files-7.7K-c9742e" alt="knowledge"/>
</p>

---

## What is Mergen?

Mergen is an **agentic offensive-security harness**: an AI operator (TUI + web) that
reads targets, plans attack chains, and executes authorized pentest workflows —
guided by a large curated knowledge base of real techniques.

<p align="center"><img src="assets/demo.gif" alt="Mergen detecting a poisoned MCP server on startup" width="820"/></p>

*MCP Guard in action: Mergen connects to a configured MCP server, and before the agent sees any tool, the guard flags a poisoned `read_notes` description trying to exfiltrate `~/.ssh/id_rsa`.*

- **40+ attack disciplines** as structured skills: SSRF, SSTI, XXE, request
  smuggling, race conditions, subdomain takeover, JWT, GraphQL, prototype
  pollution, CORS, host-header, IDOR automation, WebSocket, cache poisoning,
  rate-limit bypass — plus **MCP/LLM security** (`.mergen/skill/mcp-security`).
- **Full-spectrum knowledge base** (~7,700 files): MITRE ATT&CK (Enterprise,
  ICS, Mobile), OWASP WSTG, CIS benchmarks, cloud post-exploitation
  (AWS/Azure/GCP), K8s, AD/Kerberos, Linux/Windows/macOS post-exploitation.
- **Methodology + memory**: engagement workflows, per-target memory, and
  chain-of-attack reasoning instead of one-shot payloads.
- **MCP Guard** *(unique)*: Mergen audits every configured MCP server's tool metadata
  for poisoning, hidden instructions, and command-injection surface **before** the
  agent is allowed to use it — the same detection engine as
  [mcp-sentinel](https://github.com/TiaMEOWS/mcp-sentinel), embedded in the harness.
    Disable with `MERGEN_DISABLE_MCP_GUARD=1`.
- **Evidence-bound findings** *(unique)*: an execution-dependent finding filed without
  executable evidence is recorded as an `UNCONFIRMED CANDIDATE` capped at medium — and it
  can never leave that state until real proof (observed alert/flag/checker output) is
  supplied, via either `report_vulnerability` upgrade or `triage_vulnerability` with
  `execution_evidence`. No evidence, no severity.
- **Replayable PoC export** *(unique)*: `export_poc` turns every confirmed finding into a
  standalone re-runnable script (curl `.sh` + stdlib-python `.py`) that replays the exploit
  request and greps for the recorded evidence markers — exit 0 means it reproduces.
    Candidates and duplicates are refused.
- **`mergen verify` -- fix-regression gate** *(unique)*: replays every exported PoC
  against a (re)deployment and reports REPRODUCED / FIXED / ERROR per finding.
  Exit code 1 when anything still fires -- drop it into CI and a "fixed"
  vulnerability that isn't fixed fails the pipeline.
- **Scope Firewall** *(unique)*: drop a `scope.json` in the project root (see
  `scope.example.json`) and every network-capable tool — bash, webfetch, hackbrowser,
  http_replay, inject_probe, attack_script — is hard-blocked from touching an
  out-of-scope host. Deny rules beat allow rules, loopback stays open for local PoC
  targets, an invalid scope file fails closed, and every block is audit-logged to
    `.mergen/firewall-audit.jsonl`. Disable with `MERGEN_DISABLE_SCOPE_FIREWALL=1`.
- **Campaign mode** *(autonomous)*: `mergen campaign <target>` drives a full
  engagement with no human in the loop — recon, mapping, per-class testing,
  evidence-bound confirmation, then report + PoC export. Scope is derived (or
  verified) before the first packet; the firewall stays the hard boundary.
- **Scan depth modes**: `mergen campaign <target> --mode quick|standard|deep` --
  high-signal sweep, full methodology, or exhaustive audit (fuzzing, chaining,
  role matrices) with explicit coverage targets the agent is held to.
- **SARIF + PDF report export**: `generate_report` can also emit `report.sarif`
  (SARIF 2.1.0 -- GitHub Code Scanning ready, CWE-keyed rules, severity-mapped
  levels) and a dependency-free `report.pdf`. Only confirmed, non-duplicate
  findings enter the SARIF run.
- **Traffic ingest**: `mergen ingest capture.har` (or a Burp XML export) loads
  real observed traffic into the session's request table -- structural dedup,
  path templating, response capture -- so the agent tests what the app actually
  does instead of guessing endpoints.
- **Docker sandbox**: `MERGEN_SANDBOX=docker` runs every bash command in a
  throwaway hardened container (caps dropped, no-new-privileges, pid/memory
  limits, project mounted at /work). Fail-closed: no daemon, no execution.
  `MERGEN_SANDBOX_IMAGE`, `MERGEN_SANDBOX_NETWORK=bridge|none|host`.
- **HackBrowser**: capture and replay real browser traffic during engagements.
- **Brand-new look**: the "Steppe Night" theme — deep charcoal blues with the
  golden-amber of Mergen's bow.

## Why Mergen?

| | Mergen | Typical AI pentest harnesses | Prompt-wrapper scripts |
|---|---|---|---|
| MCP supply-chain audit (MCP Guard) | ✅ blocks poisoned tools before the agent sees them | — | — |
| Rug-pull detection (baseline diff) | ✅ | — | — |
| Evidence-bound findings (no proof, no severity) | ✅ candidates can't be confirmed without executable evidence | — | — |
| Replayable PoC export per finding | ✅ curl + python, evidence-marker verified | — | — |
| Scope firewall (technical egress enforcement) | ✅ out-of-scope hosts blocked at the tool layer | — | — |
| Autonomous campaign mode | ✅ one command, scope-enforced end to end | — | — |
| Hosted gateway / paywall | none — BYOK only | Zen credits | varies |
| Phones home | never — local-first | proxied to hosted domain | varies |
| Attack skill library | 40+ disciplines, 7.6K files | varies | prompt snippets |
| Engagement reporting | full report + H1/Intigriti submission drafts | full report | — |
| Replayable PoC export + `mergen verify` fix-regression gate | exit-code gated CI check on the fix | — | — |
| SARIF 2.1.0 + PDF report export | GitHub Code Scanning ready | — | — |
| HAR / Burp traffic ingest | real observed traffic as ground truth | — | — |
| Sandboxed execution (docker) | hardened throwaway containers, fail-closed | — | — |
| Scan depth modes (quick/standard/deep) | explicit coverage targets | — | — |
| `mcp audit` CI command | ✅ exit-code gated | — | — |

## Platform support

CI-tested on Linux. Windows runs fine for real usage; parts of the upstream
test suite still assume POSIX path semantics (known limitation — help welcome).

## Quick start

Requires [Bun](https://bun.sh) 1.3+.

```bash
git clone https://github.com/TiaMEOWS/mergen.git
cd mergen
bun install
bun run dev        # TUI
bun run dev:web    # web app
```

### Campaign mode (autonomous)

```bash
mergen campaign https://target.example.com            # scope derived + enforced automatically
mergen campaign 10.0.0.5 --scope 10.0.0.0/24          # extra scope items
mergen campaign https://target.example.com --mode deep # exhaustive audit (default: standard)
```

One command, no human in the loop: permissions auto-allow, the question tool stays
off, and the Scope Firewall is the hard boundary. If a `scope.json` already exists,
the target must be in it -- campaigns never edit an existing scope. The run ends
with a full report plus exported replayable PoCs under `.mergen/findings/`.

### Verify a fix (CI regression gate)

```bash
mergen verify                                  # replay everything under .mergen/findings/**/poc
mergen verify --target https://staging.example.com
mergen verify .mergen/findings/<session>/poc/vuln-7-sqli.sh -t https://localhost:3000
```

Every exported PoC self-checks its recorded evidence markers: exit 0 means the
finding still reproduces (the fix did NOT hold), exit 1 means the markers are
gone. `mergen verify` aggregates the verdicts and exits 1 when anything
reproduces -- wire it into a pipeline and a "fixed" vulnerability that still
fires fails the build.

### Import real traffic

```bash
mergen ingest capture.har                      # browser devtools export
mergen ingest burp-export.xml                  # Burp Suite "save items" XML
mergen ingest capture.har --session ses_abc    # append to an existing session
```

Requests land in the session's request table with structural dedup (re-importing
the same capture is a no-op) and light tier-1 normalization (numeric/UUID path
segments templated to `{id}`), ready for surface mapping and testing.

## Responsible use

Mergen is built for **authorized** security work: your own systems, signed
pentest engagements, in-scope bug bounty programs, and training labs. It is not
a toy and not a weapon — you are responsible for staying in scope and in law.

## License

Licensed under **AGPL-3.0** — see [LICENSE](LICENSE). Original upstream
copyright notices are preserved as required.

