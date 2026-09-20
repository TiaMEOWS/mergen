function truthy(key: string) {
  const value = process.env[key]?.toLowerCase()
  return value === "true" || value === "1"
}

export namespace Flag {
  export const MERGEN_AUTO_SHARE = truthy("MERGEN_AUTO_SHARE")
  export const MERGEN_GIT_BASH_PATH = process.env["MERGEN_GIT_BASH_PATH"]
  export const MERGEN_CONFIG = process.env["MERGEN_CONFIG"]
  export declare const MERGEN_CONFIG_DIR: string | undefined
  export const MERGEN_CONFIG_CONTENT = process.env["MERGEN_CONFIG_CONTENT"]
  export const MERGEN_DISABLE_AUTOUPDATE = truthy("MERGEN_DISABLE_AUTOUPDATE")
  export const MERGEN_DISABLE_PRUNE = truthy("MERGEN_DISABLE_PRUNE")
  export const MERGEN_DISABLE_TERMINAL_TITLE = truthy("MERGEN_DISABLE_TERMINAL_TITLE")
  export const MERGEN_PERMISSION = process.env["MERGEN_PERMISSION"]
  export const MERGEN_DISABLE_DEFAULT_PLUGINS = truthy("MERGEN_DISABLE_DEFAULT_PLUGINS")
  export const MERGEN_DISABLE_LSP_DOWNLOAD = truthy("MERGEN_DISABLE_LSP_DOWNLOAD")
  export const MERGEN_ENABLE_EXPERIMENTAL_MODELS = truthy("MERGEN_ENABLE_EXPERIMENTAL_MODELS")
  export const MERGEN_DISABLE_AUTOCOMPACT = truthy("MERGEN_DISABLE_AUTOCOMPACT")
  export const MERGEN_DISABLE_MODELS_FETCH = truthy("MERGEN_DISABLE_MODELS_FETCH")
  export const MERGEN_DISABLE_CLAUDE_CODE = truthy("MERGEN_DISABLE_CLAUDE_CODE")
  export const MERGEN_DISABLE_CLAUDE_CODE_PROMPT =
    MERGEN_DISABLE_CLAUDE_CODE || truthy("MERGEN_DISABLE_CLAUDE_CODE_PROMPT")
  export const MERGEN_DISABLE_CLAUDE_CODE_SKILLS =
    MERGEN_DISABLE_CLAUDE_CODE || truthy("MERGEN_DISABLE_CLAUDE_CODE_SKILLS")
  export const MERGEN_DISABLE_EXTERNAL_SKILLS =
    MERGEN_DISABLE_CLAUDE_CODE_SKILLS || truthy("MERGEN_DISABLE_EXTERNAL_SKILLS")
  export declare const MERGEN_DISABLE_PROJECT_CONFIG: boolean
  export const MERGEN_FAKE_VCS = process.env["MERGEN_FAKE_VCS"]
  export declare const MERGEN_CLIENT: string
  export const MERGEN_SERVER_PASSWORD = process.env["MERGEN_SERVER_PASSWORD"]
  export const MERGEN_SERVER_USERNAME = process.env["MERGEN_SERVER_USERNAME"]

  // Experimental
  export const MERGEN_EXPERIMENTAL = truthy("MERGEN_EXPERIMENTAL")
  export const MERGEN_EXPERIMENTAL_FILEWATCHER = truthy("MERGEN_EXPERIMENTAL_FILEWATCHER")
  export const MERGEN_EXPERIMENTAL_DISABLE_FILEWATCHER = truthy("MERGEN_EXPERIMENTAL_DISABLE_FILEWATCHER")
  export const MERGEN_EXPERIMENTAL_ICON_DISCOVERY =
    MERGEN_EXPERIMENTAL || truthy("MERGEN_EXPERIMENTAL_ICON_DISCOVERY")

  const copy = process.env["MERGEN_EXPERIMENTAL_DISABLE_COPY_ON_SELECT"]
  export const MERGEN_EXPERIMENTAL_DISABLE_COPY_ON_SELECT =
    copy === undefined ? process.platform === "win32" : truthy("MERGEN_EXPERIMENTAL_DISABLE_COPY_ON_SELECT")
  export const MERGEN_DISABLE_MCP_GUARD = truthy("MERGEN_DISABLE_MCP_GUARD")
  export const MERGEN_ENABLE_EXA =
    truthy("MERGEN_ENABLE_EXA") || MERGEN_EXPERIMENTAL || truthy("MERGEN_EXPERIMENTAL_EXA")
  export const MERGEN_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS = number(
    "MERGEN_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS",
  )
  export const MERGEN_EXPERIMENTAL_OUTPUT_TOKEN_MAX = number("MERGEN_EXPERIMENTAL_OUTPUT_TOKEN_MAX")
  export const MERGEN_EXPERIMENTAL_OXFMT = MERGEN_EXPERIMENTAL || truthy("MERGEN_EXPERIMENTAL_OXFMT")
  export const MERGEN_EXPERIMENTAL_LSP_TY = truthy("MERGEN_EXPERIMENTAL_LSP_TY")
  export const MERGEN_EXPERIMENTAL_LSP_TOOL =
    MERGEN_EXPERIMENTAL || truthy("MERGEN_EXPERIMENTAL_LSP_TOOL")
  export const MERGEN_DISABLE_FILETIME_CHECK = truthy("MERGEN_DISABLE_FILETIME_CHECK")
  export const MERGEN_EXPERIMENTAL_PLAN_MODE =
    MERGEN_EXPERIMENTAL || truthy("MERGEN_EXPERIMENTAL_PLAN_MODE")
  export const MERGEN_EXPERIMENTAL_MARKDOWN = truthy("MERGEN_EXPERIMENTAL_MARKDOWN")
  export const MERGEN_MODELS_URL = process.env["MERGEN_MODELS_URL"]
  export const MERGEN_MODELS_PATH = process.env["MERGEN_MODELS_PATH"]

  function number(key: string) {
    const value = process.env[key]
    if (!value) return undefined
    const parsed = Number(value)
    return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined
  }
}

// Dynamic getter for MERGEN_DISABLE_PROJECT_CONFIG
// This must be evaluated at access time, not module load time,
// because external tooling may set this env var at runtime
Object.defineProperty(Flag, "MERGEN_DISABLE_PROJECT_CONFIG", {
  get() {
    return truthy("MERGEN_DISABLE_PROJECT_CONFIG")
  },
  enumerable: true,
  configurable: false,
})

// Dynamic getter for MERGEN_CONFIG_DIR
// This must be evaluated at access time, not module load time,
// because external tooling may set this env var at runtime
Object.defineProperty(Flag, "MERGEN_CONFIG_DIR", {
  get() {
    return process.env["MERGEN_CONFIG_DIR"]
  },
  enumerable: true,
  configurable: false,
})

// Dynamic getter for MERGEN_CLIENT
// This must be evaluated at access time, not module load time,
// because some commands override the client at runtime
Object.defineProperty(Flag, "MERGEN_CLIENT", {
  get() {
    return process.env["MERGEN_CLIENT"] ?? "cli"
  },
  enumerable: true,
  configurable: false,
})
