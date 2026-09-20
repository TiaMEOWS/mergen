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
```

One command, no human in the loop: permissions auto-allow, the question tool stays
off, and the Scope Firewall is the hard boundary. If a `scope.json` already exists,
the target must be in it -- campaigns never edit an existing scope. The run ends
with a full report plus exported replayable PoCs under `.mergen/findings/`.

## Responsible use

Mergen is built for **authorized** security work: your own systems, signed
pentest engagements, in-scope bug bounty programs, and training labs. It is not
a toy and not a weapon — you are responsible for staying in scope and in law.

## License

Licensed under **AGPL-3.0** — see [LICENSE](LICENSE). Original upstream
copyright notices are preserved as required.

