import { describe, expect, test } from "bun:test"
import path from "path"
import fs from "fs/promises"
import os from "os"
import { Verify } from "../../src/session/verify"

describe("verify marker parsing", () => {
  test("parses bash EXPECTED_MARKERS with spaces and escaped quotes", () => {
    const content = [
      "#!/usr/bin/env bash",
      `EXPECTED_MARKERS=('alert(1) fired' 'uid=33(www-data)' 'it'\\''s')`,
      "",
    ].join("\n")
    expect(Verify.parseShMarkers(content)).toEqual(["alert(1) fired", "uid=33(www-data)", "it's"])
  })

  test("parses empty bash marker list", () => {
    expect(Verify.parseShMarkers("EXPECTED_MARKERS=()\n")).toEqual([])
  })

  test("parses python EXPECTED_MARKERS as JSON", () => {
    const content = 'EXPECTED_MARKERS = ["root:x:0:0", "uid=0(root)"]\n'
    expect(Verify.parsePyMarkers(content)).toEqual(["root:x:0:0", "uid=0(root)"])
  })

  test("returns [] for malformed python markers", () => {
    expect(Verify.parsePyMarkers("EXPECTED_MARKERS = not json\n")).toEqual([])
  })
})

describe("verify target parsing", () => {
  test("extracts the bash default target", () => {
    const content = 'TARGET="${TARGET:-https://staging.example.com}"  # override\n'
    expect(Verify.parseShTarget(content)).toBe("https://staging.example.com")
  })

  test("extracts the python default target", () => {
    const content = 'TARGET = os.environ.get("TARGET", "https://api.example.com").rstrip("/")\n'
    expect(Verify.parsePyTarget(content)).toBe("https://api.example.com")
  })

  test("load drops the changeme placeholder target", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-verify-load-"))
    const file = path.join(dir, "poc.sh")
    await fs.writeFile(file, 'TARGET="${TARGET:-https://changeme.example.com}"\nEXPECTED_MARKERS=(\'x\')\n')
    const script = await Verify.load(file)
    expect(script?.language).toBe("curl")
    expect(script?.defaultTarget).toBeUndefined()
    expect(script?.markers).toEqual(["x"])
  })
})

describe("verify discover", () => {
  test("walks a findings root and finds poc scripts sorted", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-verify-disc-"))
    const pocA = path.join(dir, "ses-a", "poc")
    const pocB = path.join(dir, "ses-b", "poc")
    await fs.mkdir(pocA, { recursive: true })
    await fs.mkdir(pocB, { recursive: true })
    await fs.writeFile(path.join(pocA, "b.sh"), "#!/usr/bin/env bash\n")
    await fs.writeFile(path.join(pocB, "a.py"), "# py\n")
    await fs.writeFile(path.join(pocB, "notes.txt"), "not a script\n")
    const found = await Verify.discover(dir)
    expect(found.map((f) => path.basename(f))).toEqual(["b.sh", "a.py"])
  })

  test("accepts a single script file", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mergen-verify-one-"))
    const file = path.join(dir, "poc.py")
    await fs.writeFile(file, "# py\n")
    expect(await Verify.discover(file)).toEqual([file])
  })

  test("missing root discovers nothing", async () => {
    expect(await Verify.discover(path.join(os.tmpdir(), "mergen-verify-nope-xyz"))).toEqual([])
  })
})

describe("verify verdicts", () => {
  test("exit 0 -> reproduced, exit 1 -> fixed, others -> error", () => {
    expect(Verify.verdict({ exitCode: 0, timedOut: false, output: "" }).status).toBe("reproduced")
    expect(Verify.verdict({ exitCode: 1, timedOut: false, output: "" }).status).toBe("fixed")
    expect(Verify.verdict({ exitCode: 7, timedOut: false, output: "" }).status).toBe("error")
    expect(Verify.verdict({ exitCode: null, timedOut: true, output: "" }).status).toBe("error")
    expect(Verify.verdict({ exitCode: null, timedOut: false, error: "spawn bash ENOENT", output: "" }).status).toBe(
      "error",
    )
  })

  test("gate exit code is 1 exactly when something reproduces", () => {
    const script: Verify.Script = { path: "/x/poc.sh", filename: "poc.sh", language: "curl", markers: [] }
    const mk = (status: Verify.Status): Verify.FindingResult => ({ script, verdict: { status, detail: "" }, output: "" })
    expect(Verify.exitCode([mk("fixed"), mk("error")])).toBe(0)
    expect(Verify.exitCode([mk("fixed"), mk("reproduced")])).toBe(1)
  })
})

describe("verify run", () => {
  test("uses the injected runner, prefers --target over the script default, sequentially", async () => {
    const script: Verify.Script = {
      path: "/x/poc.sh",
      filename: "poc.sh",
      language: "curl",
      markers: ["m"],
      defaultTarget: "https://old.example.com",
    }
    const seen: (string | undefined)[] = []
    const results = await Verify.run([script, script], {
      target: "https://new.example.com",
      runner: async (_s, opts) => {
        seen.push(opts.target)
        return { exitCode: 1, timedOut: false, output: "" }
      },
    })
    expect(seen).toEqual(["https://new.example.com", "https://new.example.com"])
    expect(results.every((r) => r.verdict.status === "fixed")).toBe(true)
  })

  test("falls back to the script default target when --target is absent", async () => {
    const script: Verify.Script = {
      path: "/x/poc.py",
      filename: "poc.py",
      language: "python",
      markers: [],
      defaultTarget: "https://recorded.example.com",
    }
    let seen: string | undefined
    await Verify.run([script], {
      runner: async (_s, opts) => {
        seen = opts.target
        return { exitCode: 0, timedOut: false, output: "" }
      },
    })
    expect(seen).toBe("https://recorded.example.com")
  })
})