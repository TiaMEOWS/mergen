export const deepLinkEvent = "mergen:deep-link"

export const parseDeepLink = (input: string) => {
  if (!input.startsWith("mergen://")) return
  if (typeof URL.canParse === "function" && !URL.canParse(input)) return
  const url = (() => {
    try {
      return new URL(input)
    } catch {
      return undefined
    }
  })()
  if (!url) return
  if (url.hostname !== "open-project") return
  const directory = url.searchParams.get("directory")
  if (!directory) return
  return directory
}

export const collectOpenProjectDeepLinks = (urls: string[]) =>
  urls.map(parseDeepLink).filter((directory): directory is string => !!directory)

type MergenWindow = Window & {
  __MERGEN__?: {
    deepLinks?: string[]
  }
}

export const drainPendingDeepLinks = (target: MergenWindow) => {
  const pending = target.__MERGEN__?.deepLinks ?? []
  if (pending.length === 0) return []
  if (target.__MERGEN__) target.__MERGEN__.deepLinks = []
  return pending
}
