import z from "zod"

// ============================================================
// SCOPE FIREWALL (core) -- pure matching + host extraction.
// No Instance, no DB, no fs: fully unit-testable. The loader /
// enforcement glue lives in ./index.ts; the tool wrapper in
// tool/registry.ts.
//
// Opt-in: the firewall is INACTIVE unless a scope.json exists
// (project root or .mergen/scope.json). When active, network-
// capable tools (bash, webfetch, hackbrowser, http_replay*,
// inject_probe, attack_script) cannot emit a single byte to a
// host outside the declared scope -- deny rules beat allow
// rules, and an invalid scope file fails CLOSED.
// ============================================================

export namespace ScopeFirewall {
  export const Config = z.object({
    /** Domains ("example.com" also covers subdomains), wildcards ("*.example.com"),
     *  IPv4 CIDRs ("10.0.0.0/8"), or regex rules ("re:^api-.*\\.example\\.com$"). */
    allow: z.array(z.string()).min(1),
    /** Checked first -- a deny match overrides any allow match. Same syntax. */
    deny: z.array(z.string()).optional(),
    /** "block" (default) refuses the tool call; "warn" lets it through with a loud notice. */
    mode: z.enum(["block", "warn"]).optional(),
  })
  export type Config = z.infer<typeof Config>

  export interface MatchResult {
    allowed: boolean
    matchedBy?: string
  }

  export interface Violation {
    host: string
    reason: string
  }

  // Loopback is ALWAYS allowed: local PoC targets (Juice Shop, DVWA, a flask test server)
  // are how findings get validated -- blocking 127.0.0.1 would break the core workflow.
  // RFC1918 ranges beyond loopback proper must be scoped explicitly.
  const LOOPBACK_V4 = "127.0.0.0/8"
  const LOOPBACK_HOSTS = new Set(["localhost", "::1", "[::1]", "0.0.0.0"])

  /** Normalize a host or URL-ish target to a bare lowercase hostname. */
  export function hostnameOf(target: string): string | undefined {
    let text = target.trim()
    if (!text) return undefined
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
      try {
        return new URL(text).hostname.toLowerCase() || undefined
      } catch {
        return undefined
      }
    }
    // strip userinfo, port, path for bare host[:port][/path] forms
    text = text.replace(/^[^/@\s]+@/, "").split("/")[0]
    if (text.startsWith("[")) {
      const end = text.indexOf("]")
      return end > 0 ? text.slice(0, end + 1).toLowerCase() : undefined
    }
    const host = text.split(":")[0].toLowerCase().replace(/\.$/, "")
    return host || undefined
  }

  function ipToNum(ip: string): number | undefined {
    const parts = ip.split(".")
    if (parts.length !== 4) return undefined
    let num = 0
    for (const part of parts) {
      if (!/^\d{1,3}$/.test(part)) return undefined
      const octet = Number(part)
      if (octet > 255) return undefined
      num = (num << 8) + octet
    }
    return num >>> 0
  }

  export function ipInCIDR(ip: string, cidr: string): boolean {
    const [range, bitsRaw] = cidr.split("/")
    const bits = Number(bitsRaw)
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false
    const ipNum = ipToNum(ip)
    const rangeNum = ipToNum(range)
    if (ipNum === undefined || rangeNum === undefined) return false
    const mask = bits === 0 ? 0 : (~((1 << (32 - bits)) - 1)) >>> 0
    return (ipNum & mask) === (rangeNum & mask)
  }

  function ruleMatches(host: string, rule: string): boolean {
    const r = rule.trim().toLowerCase()
    if (!r) return false

    // regex rule: re:<pattern> (tested against the bare host)
    if (r.startsWith("re:")) {
      try {
        return new RegExp(r.slice(3), "i").test(host)
      } catch {
        return false
      }
    }

    // CIDR rule (host must be a literal IPv4)
    if (/^\d+\.\d+\.\d+\.\d+\/\d{1,2}$/.test(r)) return ipInCIDR(host, r)

    // URL-ish rule: match on its host part
    const ruleHost = r.includes("://") || r.includes("/") ? (hostnameOf(r) ?? r) : r

    // wildcard: *.example.com covers the root and every subdomain
    if (ruleHost.startsWith("*.")) {
      const domain = ruleHost.slice(2)
      return host === domain || host.endsWith("." + domain)
    }

    // bare domain: bug-bounty convention -- "example.com" in scope covers its subdomains
    return host === ruleHost || host.endsWith("." + ruleHost)
  }

  /** Core decision: is this host allowed to receive traffic? Deny rules win. */
  export function matchHost(host: string, config: Config): MatchResult {
    const normalized = host.toLowerCase().replace(/\.$/, "")
    if (LOOPBACK_HOSTS.has(normalized) || ipInCIDR(normalized, LOOPBACK_V4)) {
      return { allowed: true, matchedBy: "loopback (always allowed)" }
    }
    for (const deny of config.deny ?? []) {
      if (ruleMatches(normalized, deny)) return { allowed: false, matchedBy: `deny: ${deny}` }
    }
    for (const allow of config.allow) {
      if (ruleMatches(normalized, allow)) return { allowed: true, matchedBy: allow }
    }
    return { allowed: false }
  }

  /** Check raw targets (URLs, hosts, host:port); returns only the violations. */
  export function check(targets: (string | undefined)[], config: Config): Violation[] {
    const violations: Violation[] = []
    const seen = new Set<string>()
    for (const target of targets) {
      if (!target) continue
      const host = hostnameOf(target)
      if (!host || seen.has(host)) continue
      seen.add(host)
      const result = matchHost(host, config)
      if (!result.allowed) {
        violations.push({
          host,
          reason: result.matchedBy ?? `not covered by any of the ${config.allow.length} allow rule(s)`,
        })
      }
    }
    return violations
  }

  // --- command-line egress extraction -------------------------------------

  /** Binaries whose arguments represent network egress. Dev tooling (git, npm,
   *  gh, pip...) is deliberately EXCLUDED -- the firewall guards engagement
   *  traffic to targets, not package registries or VCS hosts. */
  const NET_TOOLS = new Set([
    "curl", "wget", "http", "https", "nc", "ncat", "netcat", "socat",
    "nmap", "masscan", "rustscan", "zmap", "unicornscan", "hping3", "nping",
    "ssh", "telnet", "ftp", "sftp", "smbclient", "rpcclient", "ldapsearch", "snmpwalk",
    "dig", "host", "nslookup", "ping", "ping6", "traceroute", "mtr",
    "httpx", "httprobe", "nuclei", "ffuf", "gobuster", "feroxbuster", "dirb", "dirsearch",
    "wfuzz", "sqlmap", "hydra", "medusa", "whatweb", "wpscan", "nikto", "zap-cli",
    "openssl", "testssl.sh", "sslyze", "enum4linux", "crackmapexec", "netexec", "nxc",
    "responder", "mitm6", "bettercap", "xsstrike", "dalfox", "commix",
  ])

  /** Flags whose VALUE is not a target host (output files, headers, data...). */
  const VALUE_FLAGS = new Set([
    "-o", "-on", "-ox", "-oa", "-og", "-il", "-i", "-h", "-a", "-d", "-e", "-w", "-x",
    "-b", "-u", "-k", "-t", "-f", "-H", "-A",
    "--header", "--output", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode",
    "--wordlist", "--proxy", "--cookie", "--user", "--user-agent", "--referer", "--resolve",
    "--connect-to", "--cacert", "--cert", "--key", "--config", "--form", "--request", "--auth",
    "--rate", "--threads", "--timeout", "--delay", "--filter-status", "--filter-size",
  ])

  const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/
  const BARE_DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i

  function binaryOf(token: string): string {
    const base = token.replace(/^["']|["']$/g, "").split(/[\\/]/).pop() ?? ""
    return base.replace(/\.(exe|bat|cmd|sh|py)$/i, "").toLowerCase()
  }

  /** Rough shell tokenization: splits on whitespace, keeps quoted segments whole. */
  function tokenize(command: string): string[] {
    const tokens: string[] = []
    for (const match of command.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)) {
      tokens.push(match[1] ?? match[2] ?? match[3])
    }
    return tokens
  }

  /** Every egress host a shell command would touch. Scans each subcommand whose
   *  binary is a known network tool: URL arguments, IPv4 literals, and bare
   *  domains (unless the token is the value of a known non-target flag). */
  export function hostsFromCommand(command: string): string[] {
    const hosts = new Set<string>()
    const subcommands = command.split(/\|\||&&|[|;\n]/)
    for (const sub of subcommands) {
      const tokens = tokenize(sub).filter((t) => t.length > 0)
      if (tokens.length === 0) continue
      // skip leading env assignments (FOO=bar curl ...)
      let i = 0
      while (i < tokens.length && /^\w+=/.test(tokens[i])) i++
      if (i >= tokens.length) continue
      const binary = binaryOf(tokens[i])
      if (!NET_TOOLS.has(binary)) continue
      for (let j = i + 1; j < tokens.length; j++) {
        const token = tokens[j]
        if (VALUE_FLAGS.has(token.toLowerCase())) {
          // the flag value is normally not a target -- but ffuf-style `-u https://t/FUZZ`
          // hides the URL there, so still check values that carry an explicit scheme
          const value = tokens[j + 1]
          if (value && /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
            const host = hostnameOf(value)
            if (host) hosts.add(host)
          }
          j++
          continue
        }
        if (token.startsWith("-")) continue
        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) {
          const host = hostnameOf(token)
          if (host) hosts.add(host)
          continue
        }
        const bare = token.replace(/^["']|["']$/g, "").split("/")[0].split(":")[0]
        if (IPV4.test(bare) || BARE_DOMAIN.test(bare)) hosts.add(bare.toLowerCase())
      }
    }
    return [...hosts]
  }

  /** Egress hosts in a free-form argument list (attack_script args, etc.). */
  export function hostsFromArgs(args: string[]): string[] {
    const hosts = new Set<string>()
    for (const arg of args) {
      const bare = arg.trim().replace(/^["']|["']$/g, "")
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(bare)) {
        const host = hostnameOf(bare)
        if (host) hosts.add(host)
        continue
      }
      const head = bare.split("/")[0].split(":")[0]
      if (IPV4.test(head) || BARE_DOMAIN.test(head)) hosts.add(head.toLowerCase())
    }
    return [...hosts]
  }
}