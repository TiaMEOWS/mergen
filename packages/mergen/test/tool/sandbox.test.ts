import { describe, expect, test } from "bun:test"
import path from "path"
import { Sandbox } from "../../src/tool/sandbox"

describe("sandbox.dockerArgs", () => {
  const base = {
    command: "nmap -sV example.com",
    workdir: path.join("D:", "proj", "sub"),
    projectRoot: path.join("D:", "proj"),
    image: "alpine:latest",
    network: "bridge",
    name: "mergen-sbx-1-x",
  }

  test("builds a hardened throwaway container invocation", () => {
    const args = Sandbox.dockerArgs(base)
    expect(args.slice(0, 3)).toEqual(["run", "--rm", "--init"])
    expect(args).toContain("--cap-drop")
    expect(args).toContain("ALL")
    expect(args).toContain("no-new-privileges")
    expect(args).toContain("--pids-limit")
    expect(args).toContain("--memory")
    expect(args).toContain("bridge")
    expect(args[args.indexOf("--name") + 1]).toBe("mergen-sbx-1-x")
  })

  test("command is passed verbatim to sh -lc, never shell-interpolated by us", () => {
    const args = Sandbox.dockerArgs(base)
    const idx = args.indexOf("-lc")
    expect(args[idx - 1]).toBe("sh")
    expect(args[idx + 1]).toBe("nmap -sV example.com")
    expect(args[args.length - 4]).toBe("alpine:latest")
  })

  test("project root is mounted at /work, subdir workdir maps inside it", () => {
    const args = Sandbox.dockerArgs(base)
    expect(args[args.indexOf("-v") + 1]).toBe(`${base.projectRoot}:/work`)
    expect(args[args.indexOf("-w") + 1]).toBe("/work/sub")
  })
})

describe("sandbox.workdirInside", () => {
  const root = path.join("D:", "proj")

  test("project root maps to /work", () => {
    expect(Sandbox.workdirInside(root, root)).toBe("/work")
  })

  test("nested dir maps below /work", () => {
    expect(Sandbox.workdirInside(path.join(root, "a", "b"), root)).toBe("/work/a/b")
  })

  test("outside paths land at /work (never leak host layout)", () => {
    expect(Sandbox.workdirInside(path.join("C:", "elsewhere"), root)).toBe("/work")
  })
})

describe("sandbox.network", () => {
  test("rejects unknown network modes back to bridge", () => {
    // Flag is read at module load; network() must clamp whatever arrives.
    expect(Sandbox.NETWORKS as readonly string[]).toContain(Sandbox.network())
  })
})