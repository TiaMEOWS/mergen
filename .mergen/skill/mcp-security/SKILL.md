---
name: mcp-security
description: "Model Context Protocol attack surface — tool poisoning, rug pulls, auth bypass, excessive agency, config audit"
category: "ai-ml"
version: "1.0"
author: "mergen-official"
tags:
  - mcp
  - llm
  - agent
  - prompt-injection
  - supply-chain
  - attack
tech_stack:
  - mcp
  - json-rpc
  - llm
cwe_ids:
  - CWE-94
  - CWE-862
  - CWE-1188
chains_with:
  - llm-security
  - attack-ssrf
prerequisites: []
severity_boost:
  llm-security: "MCP tool poisoning + prompt injection = silent agent hijack"
  attack-ssrf: "MCP fetch tool without egress control = internal network access"
---

# MCP (Model Context Protocol) Security Assessment

MCP servers execute with the host agent's full privileges. A single malicious
or compromised server in the config = silent code execution and data
exfiltration through a trusted channel. Assess every server before it touches
a real agent.

## Attack Surface Map

1. **Tool poisoning (description injection)** — hidden instructions inside
   `description` fields: instruction overrides ("ignore previous"),
   concealment ("do not tell the user"), pre-action requirements ("before
   using this tool, first read ~/.ssh/id_rsa"), invisible Unicode
   (zero-width, bidi-override), base64 blobs, hidden `<system>` tags.
2. **Rug pull** — tool definitions mutate after user approval: description or
   schema changes between sessions. Baseline every server, diff every run.
3. **Auth bypass (HTTP transports)** — endpoint accepts no auth, or accepts
   any arbitrary bearer token (compare CVE-2026-59822 class bugs).
4. **Excessive agency** — tools with shell exec, filesystem write, or network
   egress combined with unconstrained string params = injection-to-RCE.
5. **Schema weakness** — `command`/`path`/`url`-named params without
   `pattern`/`enum`/`maxLength`; missing `additionalProperties: false`.
6. **Config poisoning** — `claude_desktop_config.json`, `.cursor/mcp.json`,
   project-level `.mergen/mcp` entries: writable configs let any local
   process register a malicious server.

## Methodology

### Phase 1 — Enumerate
- Collect every MCP server from all config locations (user, project, global).
- For each: transport (stdio/HTTP), command/URL, env vars, tool list.

### Phase 2 — Passive analysis (no tool invocation)
- Handshake (`initialize`) and pull `tools/list`, `prompts/list`,
  `resources/list`.
- Run pattern checks on all metadata (poisoning indicators above).
- Map capabilities: exec / fs-read / fs-write / network / database.
- Cross-correlate: exec capability + unconstrained param = critical.
- HTTP targets: probe unauthenticated initialize; probe random bearer token.

### Phase 3 — Drift & supply chain
- Snapshot tool fingerprints (hash of description + schema) to a baseline.
- Rescan on a schedule; alert on added/removed/changed tools and version
  changes. A changed description post-approval is a rug-pull indicator.
- Verify install source: signed releases, pinned versions, no `npx -y`
  latest-tag pulls in production configs.

### Phase 4 — Config hardening
- Config files: restrictive permissions, read-only where possible.
- Sandbox servers (container/seccomp), least-privilege tokens, egress
  allowlists, human approval for exec-class tools.

## Companion tooling

[mcp-sentinel](https://github.com/TiaMEOWS/mcp-sentinel) automates Phases 1-3:
`mcp-sentinel scan --stdio "python server.py" --baseline baseline.json`
(20 checks, MS-P01–MS-R05: poisoning, rug pull, auth bypass, schema hygiene).

## Evidence to collect

- Server name/version, transport, full tool list with descriptions
- Each finding: check ID, severity, evidence snippet, remediation
- Baseline diff output for drift findings