import { spawn } from "child_process"
import path from "path"
import { Flag } from "@/flag/flag"

// ============================================================
// SANDBOX -- optional hard isolation for the bash tool. With
// MERGEN_SANDBOX=docker every shell command runs inside a
// throwaway container: project mounted at /work, capabilities
// dropped, no-new-privileges, pids + memory capped. Fail-closed:
// an unreachable docker daemon refuses the command instead of
// silently executing on the host.
// ============================================================

export namespace Sandbox {
  export type Mode = "off" | "docker"

  export const DEFAULT_IMAGE = "alpine:latest"
  export const NETWORKS = ["bridge", "none", "host"] as const

  export function mode(): Mode {
    return Flag.MERGEN_SANDBOX === "docker" ? "docker" : "off"
  }

  export function image(): string {
    return Flag.MERGEN_SANDBOX_IMAGE ?? DEFAULT_IMAGE
  }

  export function network(): string {
    const value = Flag.MERGEN_SANDBOX_NETWORK ?? "bridge"
    return (NETWORKS as readonly string[]).includes(value) ? value : "bridge"
  }

  export function containerName(): string {
    return `mergen-sbx-${process.pid}-${Date.now().toString(36)}`
  }

  /** Host workdir -> in-container path. Project root mounts at /work; paths outside it land at /work. */
  export function workdirInside(workdir: string, projectRoot: string): string {
    const rel = path.relative(projectRoot, workdir)
    if (rel === "") return "/work"
    if (rel.startsWith("..") || path.isAbsolute(rel)) return "/work"
    return "/work/" + rel.split(path.sep).join("/")
  }

  export function dockerArgs(opts: {
    command: string
    workdir: string
    projectRoot: string
    image: string
    network: string
    name: string
  }): string[] {
    return [
      "run",
      "--rm",
      "--init",
      "--name",
      opts.name,
      "--network",
      opts.network,
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--pids-limit",
      "256",
      "--memory",
      "2g",
      "-v",
      `${opts.projectRoot}:/work`,
      "-w",
      workdirInside(opts.workdir, opts.projectRoot),
      opts.image,
      "sh",
      "-lc",
      opts.command,
    ]
  }

  let cached: Promise<boolean> | undefined

  /** One-shot availability probe: is a docker daemon answering? */
  export function dockerAvailable(): Promise<boolean> {
    cached ??= new Promise<boolean>((resolve) => {
      const proc = spawn("docker", ["version", "--format", "{{.Server.Version}}"], { stdio: ["ignore", "pipe", "pipe"] })
      proc.on("error", () => resolve(false))
      proc.on("exit", (code) => resolve(code === 0))
    })
    return cached
  }

  /** Force-remove the throwaway container -- killing the docker client alone can orphan it. */
  export function removeContainer(name: string): void {
    try {
      spawn("docker", ["rm", "-f", name], { stdio: "ignore", detached: process.platform !== "win32" }).unref()
    } catch {}
  }
}