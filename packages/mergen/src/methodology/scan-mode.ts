// ============================================================
// SCAN MODE -- engagement depth profiles. A pentest is a time /
// coverage tradeoff: quick is a high-signal sweep, standard works
// the full methodology, deep is an exhaustive audit (fuzzing +
// chaining + role matrices). The profile is injected into the
// campaign directive so the agent plans against explicit coverage
// targets instead of an implicit "do everything".
// ============================================================

export namespace ScanMode {
  export const MODES = ["quick", "standard", "deep"] as const
  export type Mode = (typeof MODES)[number]

  export function coerce(value?: string): Mode {
    const v = (value ?? "").toLowerCase()
    return (MODES as readonly string[]).includes(v) ? (v as Mode) : "standard"
  }

  export interface Profile {
    mode: Mode
    label: string
    /** Minimum % of discovered attack surface that must see at least one pass. */
    coverageTarget: number
    /** Minimum % of applicable VRT checklist items resolved via update_vrt_check. */
    checklistTarget: number
    rules: string[]
  }

  const PROFILES: Record<Mode, Profile> = {
    quick: {
      mode: "quick",
      label: "high-signal sweep",
      coverageTarget: 40,
      checklistTarget: 60,
      rules: [
        "Prioritize high-signal classes only: authn/authz breaks, reflected/stored injection on obvious parameters, IDOR on numeric ids, SSRF on url-like parameters, known-CVE fingerprinting, security misconfiguration (headers, TLS, exposed files).",
        "One solid attempt per vector: if a quick probe fails, record the attempt and move on -- no fuzzing, no brute force.",
        "Skip time sinks: no password spraying beyond defaults, no wide subdomain bruteforce, no long-running crawls.",
      ],
    },
    standard: {
      mode: "standard",
      label: "full methodology",
      coverageTarget: 70,
      checklistTarget: 85,
      rules: [
        "Work the complete methodology in phase order; every applicable skill class gets at least one testing pass.",
        "Fuzz only where a quick probe signals something worth chasing.",
      ],
    },
    deep: {
      mode: "deep",
      label: "exhaustive audit",
      coverageTarget: 95,
      checklistTarget: 100,
      rules: [
        "Exhaustive: every parameter of every endpoint gets the full applicable VRT checklist -- no class skipped for time.",
        "Fuzzing is in scope: parameter fuzzing, verb tampering, content-type confusion, second-order injection (stored input revisited at every sink).",
        "Chaining required: attempt to chain low/medium findings into higher-impact exploit paths; when a chain fails, document why.",
        "Re-test authorization matrices with every discovered role/credential, not just the first one.",
      ],
    },
  }

  export function profile(mode: Mode): Profile {
    return PROFILES[mode]
  }

  /** Prompt block injected into the campaign directive. */
  export function directive(mode: Mode): string {
    const p = profile(mode)
    return [
      `SCAN MODE: ${p.mode.toUpperCase()} (${p.label})`,
      `Engagement targets: >=${p.coverageTarget}% attack-surface coverage, >=${p.checklistTarget}% of applicable VRT checks resolved via update_vrt_check before reporting.`,
      ...p.rules.map((r) => `- ${r}`),
    ].join("\n")
  }
}