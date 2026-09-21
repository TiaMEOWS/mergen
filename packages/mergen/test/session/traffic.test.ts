import { describe, expect, test } from "bun:test"
import { Traffic } from "../../src/session/traffic"

const HAR = JSON.stringify({
  log: {
    entries: [
      {
        request: {
          method: "GET",
          url: "https://shop.example.com/api/orders/123?expand=items&expand=user",
          headers: [
            { name: "Host", value: "shop.example.com" },
            { name: "Cookie", value: "sid=abc" },
          ],
        },
        response: {
          status: 200,
          headers: [{ name: "Content-Type", value: "application/json" }],
          content: { text: '{"order":123}', encoding: undefined },
        },
      },
      {
        request: {
          method: "POST",
          url: "https://shop.example.com/api/login",
          headers: [{ name: "Content-Type", value: "application/json" }],
          postData: { text: '{"user":"a"}' },
        },
        response: {
          status: 403,
          headers: [],
          content: { text: Buffer.from("forbidden").toString("base64"), encoding: "base64" },
        },
      },
      { request: { method: "GET", url: "wss://shop.example.com/socket" } },
    ],
  },
})

const BURP_REQ = Buffer.from("GET /rest/products/search?q=apple HTTP/1.1\r\nHost: juice.local:3000\r\nAccept: */*\r\n\r\n").toString("base64")
const BURP_RES = Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"products\":[]}").toString("base64")
const BURP = `<?xml version="1.0"?>
<items burpVersion="2024.1" exportTime="today">
  <item>
    <time>Mon 01 2026</time>
    <url><![CDATA[https://juice.local:3000/rest/products/search?q=apple]]></url>
    <host ip="127.0.0.1">juice.local</host>
    <port>3000</port>
    <protocol>https</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/rest/products/search?q=apple]]></path>
    <request base64="true">${BURP_REQ}</request>
    <status>200</status>
    <responselength>15</responselength>
    <response base64="true">${BURP_RES}</response>
  </item>
</items>`

describe("traffic.detect", () => {
  test("by extension, then by content sniff", () => {
    expect(Traffic.detect("capture.har", "")).toBe("har")
    expect(Traffic.detect("burp.xml", "")).toBe("burp")
    expect(Traffic.detect("capture.txt", HAR)).toBe("har")
    expect(Traffic.detect("capture.txt", BURP)).toBe("burp")
    expect(Traffic.detect("notes.txt", "hello")).toBeUndefined()
  })
})

describe("traffic.parseHAR", () => {
  test("parses entries, decodes base64 response bodies, skips non-http schemes later", () => {
    const entries = Traffic.parseHAR(HAR)
    expect(entries).toHaveLength(3)
    expect(entries[0].method).toBe("GET")
    expect(entries[0].status).toBe(200)
    expect(entries[1].reqBody).toBe('{"user":"a"}')
    expect(entries[1].resBody).toBe("forbidden")
  })

  test("throws on a non-HAR json", () => {
    expect(() => Traffic.parseHAR("{}")).toThrow()
  })
})

describe("traffic.parseBurp", () => {
  test("decodes base64 request/response and merges tags", () => {
    const entries = Traffic.parseBurp(BURP)
    expect(entries).toHaveLength(1)
    const e = entries[0]
    expect(e.method).toBe("GET")
    expect(e.url).toBe("https://juice.local:3000/rest/products/search?q=apple")
    expect(e.status).toBe(200)
    expect(e.resHeaders?.["content-type"]).toBe("application/json")
    expect(e.resBody).toBe('{"products":[]}')
  })

  test("throws when <items> is absent", () => {
    expect(() => Traffic.parseBurp("<html></html>")).toThrow()
  })
})

describe("traffic.toRowInput", () => {
  test("maps a HAR entry to a structural request row", () => {
    const [entry] = Traffic.parseHAR(HAR)
    const row = Traffic.toRowInput(entry, "ses-1")
    expect(row).toBeDefined()
    expect(row!.method).toBe("GET")
    expect(row!.normalizedPath).toBe("/api/orders/{id}")
    expect(row!.host).toBe("shop.example.com")
    expect(row!.scheme).toBe("https")
    expect(row!.port).toBe(443)
    expect(row!.origin).toBe("https://shop.example.com")
    expect(row!.queryHash).toBeDefined()
    expect(row!.keyHash).toMatch(/^[0-9a-f]{16}$/)
    expect(row!.rawRequest).toContain("GET /api/orders/123?expand=items&expand=user HTTP/1.1")
    expect(row!.rawRequest).toContain("cookie: sid=abc")
    expect(row!.response?.status).toBe(200)
    expect(row!.response?.body).toBe('{"order":123}')
  })

  test("key_hash is stable across re-imports and differs per shape", () => {
    const [a] = Traffic.parseHAR(HAR)
    const rowA = Traffic.toRowInput(a, "ses-1")!
    const rowB = Traffic.toRowInput(a, "ses-1")!
    expect(rowA.keyHash).toBe(rowB.keyHash)
    const other = Traffic.toRowInput({ method: "GET", url: "https://shop.example.com/api/orders/999" }, "ses-1")!
    expect(other.keyHash).not.toBe(rowA.keyHash) // concrete id differs from query shape? no -- path templates both to {id}; query differs
  })

  test("rejects unsupported methods and non-http urls", () => {
    expect(Traffic.toRowInput({ method: "CONNECT", url: "https://x.example.com" }, "s")).toBeUndefined()
    expect(Traffic.toRowInput({ method: "GET", url: "wss://x.example.com/socket" }, "s")).toBeUndefined()
    expect(Traffic.toRowInput({ method: "GET", url: "not a url" }, "s")).toBeUndefined()
  })

  test("templates numeric and uuid path segments", () => {
    expect(Traffic.templatePath("/api/orders/123/items")).toBe("/api/orders/{id}/items")
    expect(Traffic.templatePath("/u/550e8400-e29b-41d4-a716-446655440000/profile")).toBe("/u/{id}/profile")
    expect(Traffic.templatePath("/api/v2/search")).toBe("/api/v2/search")
    expect(Traffic.templatePath("/")).toBe("/")
  })
})