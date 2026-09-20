import { describe, expect, test } from "bun:test"
import path from "path"
import os from "os"
import fs from "fs/promises"
import { ScopeFirewall } from "../../src/scope/firewall"
import { Scope } from "../../src/scope"
import { Instance } from "../../src/project/instance"

const CONFIG: ScopeFirewall.Config = {
  allow: ["*.example.com", "10.0.0.0/8", "re:^api-\\d+\\.target\\.io$"],
  deny: ["internal.example.com"],
}

describe("firewall.hostnameOf", () => {
  test("URLs, host:port, userinfo, ipv6", () => {
    expect(ScopeFirewall.hostnameOf("https://user:pw@Example.COM:8443/a/b?x=1")).toBe("example.com")
    expect(ScopeFirewall.hostnameOf("example.com:8080/path")).toBe("example.com")
    expect(ScopeFirewall.hostnameOf("[::1]:3000/")).toBe("[::1]")
    expect(ScopeFirewall.hostnameOf("  ")).toBeUndefined()
  })
})

describe("firewall.matchHost", () => {
  test("bare domain covers subdomains, wildcard covers root+subs", () => {
    expect(ScopeFirewall.matchHost("api.example.com", CONFIG).allowed).toBe(true)
    expect(ScopeFirewall.matchHost("example.com", CONFIG).allowed).toBe(true)
    expect(ScopeFirewall.matchHost("deep.api.example.com", CONFIG).allowed).toBe(true)
  })

  test("deny overrides allow", () => {
    const result = ScopeFirewall.matchHost("internal.example.com", CONFIG)
    expect(result.allowed).toBe(false)
    expect(result.matchedBy).toContain("deny")
  })

  test("CIDR and regex rules", () => {
    expect(ScopeFirewall.matchHost("10.20.30.40", CONFIG).allowed).toBe(true)
    expect(ScopeFirewall.matchHost("11.0.0.1", CONFIG).allowed).toBe(false)
    expect(ScopeFirewall.matchHost("api-42.target.io", CONFIG).allowed).toBe(true)
    expect(ScopeFirewall.matchHost("api-x.target.io", CONFIG).allowed).toBe(false)
  })

  test("loopback is always allowed even with an unrelated scope", () => {
    expect(ScopeFirewall.matchHost("127.0.0.1", CONFIG).allowed).toBe(true)
    expect(ScopeFirewall.matchHost("localhost", CONFIG).allowed).toBe(true)
  })

  test("unmatched hosts are denied", () => {
    expect(ScopeFirewall.matchHost("evil.com", CONFIG).allowed).toBe(false)
  })
})

describe("firewall.ipInCIDR", () => {
  test("edges", () => {
    expect(ScopeFirewall.ipInCIDR("10.0.0.1", "10.0.0.0/8")).toBe(true)
    expect(ScopeFirewall.ipInCIDR("10.0.0.1", "10.0.0.1/32")).toBe(true)
    expect(ScopeFirewall.ipInCIDR("10.0.0.2", "10.0.0.1/32")).toBe(false)
    expect(ScopeFirewall.ipInCIDR("1.2.3.4", "0.0.0.0/0")).toBe(true)
    expect(ScopeFirewall.ipInCIDR("999.1.1.1", "10.0.0.0/8")).toBe(false)
  })
})

describe("firewall.check", () => {
  test("dedupes and reports only violations", () => {
    const violations = ScopeFirewall.check(
      ["https://api.example.com/a", "https://evil.com/x", "evil.com:443", undefined],
      CONFIG,
    )
    expect(violations).toHaveLength(1)
    expect(violations[0].host).toBe("evil.com")
  })
})

describe("firewall.hostsFromCommand", () => {
  test("curl URL argument", () => {
    expect(ScopeFirewall.hostsFromCommand("curl -i https://api.example.com/x?y=1")).toEqual(["api.example.com"])
  })

  test("nmap bare IP, and -oN value is not treated as a host", () => {
    expect(ScopeFirewall.hostsFromCommand("nmap -sV -oN report.txt 10.0.0.5")).toEqual(["10.0.0.5"])
  })

  test("ffuf hides the target behind -u (flag value with scheme still checked)", () => {
    expect(ScopeFirewall.hostsFromCommand("ffuf -u https://target.example.com/FUZZ -w words.txt")).toEqual([
      "target.example.com",
    ])
  })

  test("Host header is not egress; the URL host is", () => {
    expect(ScopeFirewall.hostsFromCommand('curl -H "Host: evil.com" https://ok.example.com')).toEqual([
      "ok.example.com",
    ])
  })

  test("dev tooling and non-net commands are ignored", () => {
    expect(ScopeFirewall.hostsFromCommand("git clone https://github.com/x/y && cat file.txt")).toEqual([])
  })

  test("env assignments and pipes across subcommands", () => {
    expect(ScopeFirewall.hostsFromCommand("FOO=1 curl -s http://a.bc | jq .x; wget downloads.cdn.net/f")).toEqual([
      "a.bc",
      "downloads.cdn.net",
    ])
  })
})

describe("firewall.hostsFromArgs", () => {
  test("mixed args", () => {
    expect(ScopeFirewall.hostsFromArgs(["https://t.example.com/x", "10.1.2.3", "--threads", "50"])).toEqual([
      "t.example.com",
      "10.1.2.3",
    ])
  })
})

describe("scope loader (integration)", () => {
  test("inactive without scope.json; active + blocking with one", async () => {
    const dir1 = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-scope-none-"))
    await Instance.provide({
      directory: dir1,
      fn: async () => {
        const state = await Scope.current()
        expect(state.config).toBeUndefined()
        expect(await Scope.check("bash", ["https://evil.com"])).toBeUndefined()
      },
    })

    const dir2 = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-scope-on-"))
    await fs.writeFile(
      path.join(dir2, "scope.json"),
      JSON.stringify({ allow: ["*.example.com"], deny: ["internal.example.com"] }),
    )
    await Instance.provide({
      directory: dir2,
      fn: async () => {
        const clean = await Scope.check("webfetch", ["https://api.example.com"])
        expect(clean?.violations).toHaveLength(0)

        const blocked = await Scope.check("bash", ["https://internal.example.com", "https://nope.org"])
        expect(blocked?.violations.map((v) => v.host)).toEqual(["internal.example.com", "nope.org"])
        expect(blocked?.mode).toBe("block")
        expect(blocked?.message).toContain("SCOPE FIREWALL BLOCKED")
      },
    })
  })

  test("invalid scope file fails closed", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-scope-bad-"))
    await fs.writeFile(path.join(dir, "scope.json"), "{ not json")
    await Instance.provide({
      directory: dir,
      fn: async () => {
        const result = await Scope.check("bash", ["https://api.example.com"])
        expect(result?.mode).toBe("block")
        expect(result?.message).toContain("fail-closed")
      },
    })
  })
})