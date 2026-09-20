import { describe, expect, test } from "bun:test"
import path from "path"
import os from "os"
import fs from "fs/promises"
import { Campaign } from "../../src/scope/campaign"

describe("campaign.deriveAllow", () => {
  test("domain derives host plus wildcard", () => {
    expect(Campaign.deriveAllow("https://Example.com/app")).toEqual(["example.com", "*.example.com"])
  })

  test("IP derives a /32", () => {
    expect(Campaign.deriveAllow("10.0.0.5")).toEqual(["10.0.0.5/32"])
  })

  test("loopback derives the loopback range", () => {
    expect(Campaign.deriveAllow("http://127.0.0.1:3000")).toEqual(["127.0.0.0/8", "localhost"])
  })

  test("extras are appended and deduped", () => {
    expect(Campaign.deriveAllow("example.com", ["api.other.com", "example.com"])).toEqual([
      "example.com",
      "*.example.com",
      "api.other.com",
    ])
  })
})

describe("campaign.prepare", () => {
  test("creates .mergen/scope.json when none exists", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-campaign-new-"))
    const prep = await Campaign.prepare(dir, "https://target.example.com")
    expect(prep.created).toBe(true)
    const written = JSON.parse(await fs.readFile(prep.path, "utf8"))
    expect(written.allow).toEqual(["target.example.com", "*.target.example.com"])
    expect(written.mode).toBe("block")
  })

  test("accepts an in-scope target against an existing scope file", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-campaign-ok-"))
    await fs.writeFile(path.join(dir, "scope.json"), JSON.stringify({ allow: ["*.example.com"] }))
    const prep = await Campaign.prepare(dir, "https://api.example.com")
    expect(prep.created).toBe(false)
    expect(prep.path).toBe(path.join(dir, "scope.json"))
  })

  test("refuses an out-of-scope target and never edits the file", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-campaign-oos-"))
    const file = path.join(dir, "scope.json")
    await fs.writeFile(file, JSON.stringify({ allow: ["*.example.com"] }))
    await expect(Campaign.prepare(dir, "https://evil.com")).rejects.toThrow("NOT in the declared scope")
    const after = JSON.parse(await fs.readFile(file, "utf8"))
    expect(after.allow).toEqual(["*.example.com"])
  })

  test("invalid scope file fails closed", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-campaign-bad-"))
    await fs.writeFile(path.join(dir, "scope.json"), "{ nope")
    await expect(Campaign.prepare(dir, "https://api.example.com")).rejects.toThrow("fails closed")
  })

  test("unparseable target without extras throws", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-campaign-empty-"))
    await expect(Campaign.prepare(dir, "   ")).rejects.toThrow("Could not derive a scope")
  })
})