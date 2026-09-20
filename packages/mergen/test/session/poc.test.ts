import { describe, expect, test } from "bun:test"
import { Poc } from "../../src/session/poc"
import { Vulnerability } from "../../src/session/vulnerability"

function vuln(overrides: Partial<Vulnerability.Info> = {}): Vulnerability.Info {
  return {
    id: "vln_test1",
    severity: "high",
    title: "Reflected XSS in search",
    description: "The q parameter is reflected without encoding.",
    status: "approved",
    ...overrides,
  }
}

describe("poc.extractEvidence", () => {
  test("returns the block appended by an evidence upgrade", () => {
    const v = vuln({
      description:
        'Base description.\n\n[Candidate confirmed -- execution evidence supplied]\nalert("XSS") fired in headless check',
    })
    expect(Poc.extractEvidence(v)).toBe('alert("XSS") fired in headless check')
  })

  test("undefined when no evidence block exists", () => {
    expect(Poc.extractEvidence(vuln())).toBeUndefined()
  })
})

describe("poc.evidenceMarkers", () => {
  test("prefers quoted strings, max 3, deduped", () => {
    const markers = Poc.evidenceMarkers('saw "order_total": 0 and "admin_role" then "order_total": 0 again, plus `flag{x}`')
    expect(markers).toEqual(["order_total", "admin_role", "flag{x}"])
  })

  test("falls back to the first line when nothing is quoted", () => {
    expect(Poc.evidenceMarkers("reflected payload observed in body")).toEqual(["reflected payload observed in body"])
  })

  test("empty without evidence", () => {
    expect(Poc.evidenceMarkers(undefined)).toEqual([])
  })
})

describe("poc.extractCurlCommands", () => {
  test("pulls curl from fenced blocks and bare lines", () => {
    const poc = "Try this:\n```bash\ncurl -i 'https://t.example.com/search?q=<svg>'\n```\nand then\ncurl -X POST https://t.example.com/login"
    const commands = Poc.extractCurlCommands(poc)
    expect(commands).toHaveLength(2)
    expect(commands[0]).toContain("search?q=<svg>")
    expect(commands[1]).toContain("POST")
  })

  test("empty when no curl present", () => {
    expect(Poc.extractCurlCommands("no commands here", undefined)).toEqual([])
  })
})

describe("poc.parseEndpoint", () => {
  test("method plus path with concrete placeholder", () => {
    expect(Poc.parseEndpoint("GET /api/orders/{id}")).toEqual({ method: "GET", path: "/api/orders/1" })
  })

  test("defaults to GET for a bare path", () => {
    expect(Poc.parseEndpoint("/health")).toEqual({ method: "GET", path: "/health" })
  })

  test("undefined for garbage", () => {
    expect(Poc.parseEndpoint("not a path")).toBeUndefined()
    expect(Poc.parseEndpoint(undefined)).toBeUndefined()
  })
})

describe("poc.buildCurl", () => {
  test("uses extracted curl commands verbatim and records markers", () => {
    const v = vuln({
      poc: "```\ncurl -i 'https://t.example.com/s?q=xss'\n```",
      description: 'd\n\n[Candidate confirmed -- execution evidence supplied]\nobserved "alert(1)" in response',
    })
    const script = Poc.buildCurl(v)!
    expect(script.filename).toBe("vln_test1-reflected-xss-in-search.sh")
    expect(script.content).toContain("curl -i 'https://t.example.com/s?q=xss'")
    expect(script.content).toContain("'alert(1)'")
    expect(script.content).toContain("set -euo pipefail")
  })

  test("synthesizes a request from the endpoint when no curl exists", () => {
    const script = Poc.buildCurl(vuln({ endpoint: "GET /api/orders/{id}" }))!
    expect(script.content).toContain('$TARGET/api/orders/1')
    expect(script.content).toContain("-X GET")
  })

  test("undefined when there is nothing replayable", () => {
    expect(Poc.buildCurl(vuln())).toBeUndefined()
  })

  test("strips the candidate prefix from the header title", () => {
    const script = Poc.buildCurl(
      vuln({ title: `${Vulnerability.CANDIDATE_PREFIX}Reflected XSS in search`, endpoint: "GET /s" }),
    )!
    expect(script.content).not.toContain("UNCONFIRMED CANDIDATE")
  })
})

describe("poc.buildPython", () => {
  test("stdlib replay with markers and exit codes", () => {
    const v = vuln({
      endpoint: "POST /api/orders/{id}",
      description: 'd\n\n[Candidate confirmed -- execution evidence supplied]\n"order_total": 0',
    })
    const script = Poc.buildPython(v)!
    expect(script.filename).toBe("vln_test1-reflected-xss-in-search.py")
    expect(script.content).toContain('"/api/orders/1"')
    expect(script.content).toContain('"POST"')
    expect(script.content).toContain('["order_total"]')
    expect(script.content).toContain("urllib.request")
    expect(script.content).not.toContain("requests")
  })

  test("undefined without an endpoint", () => {
    expect(Poc.buildPython(vuln({ poc: "curl https://t.example.com" }))).toBeUndefined()
  })
})

describe("poc.build", () => {
  test("both formats when possible, respects format filter", () => {
    const v = vuln({ endpoint: "GET /s" })
    expect(Poc.build(v).map((s) => s.language)).toEqual(["curl", "python"])
    expect(Poc.build(v, "curl").map((s) => s.language)).toEqual(["curl"])
    expect(Poc.build(v, "python").map((s) => s.language)).toEqual(["python"])
  })
})