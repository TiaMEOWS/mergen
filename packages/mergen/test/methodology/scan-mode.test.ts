import { describe, expect, test } from "bun:test"
import { ScanMode } from "../../src/methodology/scan-mode"

describe("scan-mode.coerce", () => {
  test("accepts exact modes case-insensitively", () => {
    expect(ScanMode.coerce("quick")).toBe("quick")
    expect(ScanMode.coerce("DEEP")).toBe("deep")
    expect(ScanMode.coerce("Standard")).toBe("standard")
  })

  test("falls back to standard for anything else", () => {
    expect(ScanMode.coerce(undefined)).toBe("standard")
    expect(ScanMode.coerce("")).toBe("standard")
    expect(ScanMode.coerce("ludicrous")).toBe("standard")
  })
})

describe("scan-mode profiles", () => {
  test("coverage and checklist targets rise monotonically with depth", () => {
    const q = ScanMode.profile("quick")
    const s = ScanMode.profile("standard")
    const d = ScanMode.profile("deep")
    expect(q.coverageTarget).toBeLessThan(s.coverageTarget)
    expect(s.coverageTarget).toBeLessThan(d.coverageTarget)
    expect(q.checklistTarget).toBeLessThan(s.checklistTarget)
    expect(s.checklistTarget).toBeLessThan(d.checklistTarget)
    expect(d.checklistTarget).toBe(100)
  })

  test("every profile carries operational rules", () => {
    for (const mode of ScanMode.MODES) {
      expect(ScanMode.profile(mode).rules.length).toBeGreaterThan(0)
    }
  })
})

describe("scan-mode.directive", () => {
  test("names the mode and its targets", () => {
    const d = ScanMode.directive("deep")
    expect(d).toContain("SCAN MODE: DEEP")
    expect(d).toContain("95%")
    expect(d).toContain("100%")
    expect(d).toContain("update_vrt_check")
  })

  test("quick mode forbids fuzzing, deep mode requires chaining", () => {
    expect(ScanMode.directive("quick")).toContain("no fuzzing")
    expect(ScanMode.directive("deep")).toContain("Chaining required")
  })
})