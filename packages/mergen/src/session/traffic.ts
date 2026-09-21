import { createHash } from "crypto"

// ============================================================
// TRAFFIC IMPORT -- parse HAR (browser/devtools) and Burp Suite
// XML exports into structural Request rows the agent can reason
// over. Pure parsing + deterministic hashing (no DB, no LLM):
// the ingest command maps entries -> Request.add inputs, and the
// key_hash conflict target dedups re-imports for free.
// ============================================================

export namespace Traffic {
  export const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const
  export type Method = (typeof METHODS)[number]

  export interface Entry {
    method: string
    url: string
    status?: number
    reqHeaders?: Record<string, string>
    resHeaders?: Record<string, string>
    reqBody?: string
    resBody?: string
  }

  export type Format = "har" | "burp"

  export function detect(filename: string, text: string): Format | undefined {
    const lower = filename.toLowerCase()
    if (lower.endsWith(".har")) return "har"
    if (lower.endsWith(".xml")) return "burp"
    const head = text.trimStart().slice(0, 200)
    if (head.startsWith("{") && text.includes('"log"')) return "har"
    if (head.startsWith("<") && /<items[\s>]/.test(text)) return "burp"
    return undefined
  }

  function headerMap(list: { name: string; value: string }[] | undefined): Record<string, string> {
    const out: Record<string, string> = {}
    for (const h of list ?? []) {
      if (!h?.name) continue
      out[h.name.toLowerCase()] = h.value ?? ""
    }
    return out
  }

  export function parseHAR(text: string): Entry[] {
    const doc = JSON.parse(text) as {
      log?: { entries?: unknown[] }
    }
    const entries = doc.log?.entries
    if (!Array.isArray(entries)) throw new Error("not a HAR file: log.entries missing")

    const out: Entry[] = []
    for (const raw of entries) {
      const e = raw as {
        request?: {
          method?: string
          url?: string
          headers?: { name: string; value: string }[]
          postData?: { text?: string; encoding?: string }
        }
        response?: {
          status?: number
          headers?: { name: string; value: string }[]
          content?: { text?: string; encoding?: string }
        }
      }
      if (!e.request?.method || !e.request.url) continue

      let reqBody = e.request.postData?.text
      if (reqBody && e.request.postData?.encoding === "base64") {
        reqBody = Buffer.from(reqBody, "base64").toString("utf8")
      }
      let resBody = e.response?.content?.text
      if (resBody && e.response?.content?.encoding === "base64") {
        resBody = Buffer.from(resBody, "base64").toString("utf8")
      }

      out.push({
        method: e.request.method,
        url: e.request.url,
        status: typeof e.response?.status === "number" ? e.response.status : undefined,
        reqHeaders: headerMap(e.request.headers),
        resHeaders: headerMap(e.response?.headers),
        reqBody,
        resBody,
      })
    }
    return out
  }

  function xmlUnescape(text: string): string {
    return text
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&amp;/g, "&")
  }

  function tag(block: string, name: string): { value: string; base64: boolean } | undefined {
    const match = block.match(new RegExp(`<${name}(\\s[^>]*)?>([\\s\\S]*?)<\\/${name}>`))
    if (!match) return undefined
    let value = match[2].trim()
    // Real Burp exports wrap text nodes in CDATA (literal -- never xml-unescape those).
    const cdata = value.match(/^<!\[CDATA\[([\s\S]*?)\]\]>$/)
    value = cdata ? cdata[1] : xmlUnescape(value)
    return { value, base64: /base64="true"/.test(match[1] ?? "") }
  }

  /** Split a raw HTTP message into statusLine/headers/body ( tolerant, \\r\\n or \\n ). */
  export function splitRaw(raw: string): { head: string; headers: Record<string, string>; body: string } {
    const idx = raw.search(/\r?\n\r?\n/)
    const head = idx < 0 ? raw : raw.slice(0, idx)
    const body = idx < 0 ? "" : raw.slice(idx).replace(/^\r?\n\r?\n/, "")
    const lines = head.split(/\r?\n/)
    const headers: Record<string, string> = {}
    for (const line of lines.slice(1)) {
      const colon = line.indexOf(":")
      if (colon <= 0) continue
      headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim()
    }
    return { head: lines[0] ?? "", headers, body }
  }

  function decode(value: string, base64: boolean): string {
    if (!base64) return value
    try {
      return Buffer.from(value.replace(/\s+/g, ""), "base64").toString("utf8")
    } catch {
      return ""
    }
  }

  export function parseBurp(text: string): Entry[] {
    if (!/<items[\s>]/.test(text)) throw new Error("not a Burp XML export: <items> missing")
    const items = text.match(/<item>[\s\S]*?<\/item>/g) ?? []
    const out: Entry[] = []
    for (const item of items) {
      const url = tag(item, "url")?.value
      const req = tag(item, "request")
      const res = tag(item, "response")
      const statusTag = tag(item, "status")?.value
      if (!req) continue

      const rawReq = decode(req.value, req.base64)
      const parsed = splitRaw(rawReq)
      const methodLine = parsed.head.match(/^([A-Z]+)\s+\S+\s+HTTP\/[\d.]+/i)
      const method = methodLine?.[1] ?? tag(item, "method")?.value
      const target = url ?? (parsed.headers["host"] ? `http://${parsed.headers["host"]}${tag(item, "path")?.value ?? "/"}` : undefined)
      if (!method || !target) continue

      let resBody: string | undefined
      let resHeaders: Record<string, string> | undefined
      let status = statusTag ? Number(statusTag) : undefined
      if (res) {
        const rawRes = decode(res.value, res.base64)
        if (rawRes) {
          const parsedRes = splitRaw(rawRes)
          resBody = parsedRes.body
          resHeaders = parsedRes.headers
          if (status === undefined || Number.isNaN(status)) {
            const code = parsedRes.head.match(/^HTTP\/[\d.]+\s+(\d{3})/)?.[1]
            status = code ? Number(code) : undefined
          }
        }
      }

      out.push({
        method,
        url: target,
        status: status !== undefined && !Number.isNaN(status) ? status : undefined,
        reqHeaders: parsed.headers,
        resHeaders,
        reqBody: parsed.body || undefined,
        resBody,
      })
    }
    return out
  }

  /** Numeric / uuid-ish path segments template to {id} (light tier-1 normalization). */
  export function templatePath(pathname: string): string {
    const templated = pathname
      .split("/")
      .map((seg) => (/^\d+$/.test(seg) || (/^[0-9a-fA-F-]{16,}$/.test(seg) && /\d/.test(seg)) ? "{id}" : seg))
      .join("/")
    return templated || "/"
  }

  const hash16 = (input: string) => createHash("sha256").update(input).digest("hex").slice(0, 16)

  export interface RowInput {
    sessionID: string
    method: Method
    normalizedPath: string
    rawRequest?: string
    bodyHash?: string
    queryHash?: string
    response?: { status: number; headers: Record<string, string>; body: string }
    scheme?: "http" | "https"
    host?: string
    port?: number
    origin?: string
    canonicalPath?: string
    normSource?: "tier1"
    keyHash?: string
  }

  const RAW_REQUEST_CAP = 16_000
  const RES_BODY_CAP = 262_144

  /** Map a parsed entry to a Request.add input. Returns undefined for non-HTTP/unsupported rows. */
  export function toRowInput(entry: Entry, sessionID: string): RowInput | undefined {
    const method = entry.method.toUpperCase() as Method
    if (!(METHODS as readonly string[]).includes(method)) return undefined

    let url: URL
    try {
      url = new URL(entry.url)
    } catch {
      return undefined
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined

    const scheme = url.protocol.replace(":", "") as "http" | "https"
    const normalizedPath = templatePath(url.pathname)
    const queryKeys = [...url.searchParams.keys()].sort()
    const queryHash = queryKeys.length > 0 ? hash16(queryKeys.join(",")) : undefined
    const bodyHash = entry.reqBody ? hash16(entry.reqBody) : undefined
    // Mirrors the normalize recipe: method || origin || normalized_path || (bodyHash) || queryKeyHash
    const keyHash = hash16([method, url.origin, normalizedPath, bodyHash ?? "", queryHash ?? ""].join(" "))

    const head = [`${method} ${url.pathname}${url.search} HTTP/1.1`, `Host: ${url.host}`]
    for (const [name, value] of Object.entries(entry.reqHeaders ?? {})) {
      if (name === "host") continue
      head.push(`${name}: ${value}`)
    }
    let rawRequest = head.join("\n") + "\n\n" + (entry.reqBody ?? "")
    if (rawRequest.length > RAW_REQUEST_CAP) rawRequest = rawRequest.slice(0, RAW_REQUEST_CAP) + "\n[truncated]"

    return {
      sessionID,
      method,
      normalizedPath,
      rawRequest,
      bodyHash,
      queryHash,
      response:
        entry.status !== undefined
          ? {
              status: entry.status,
              headers: entry.resHeaders ?? {},
              body: (entry.resBody ?? "").slice(0, RES_BODY_CAP),
            }
          : undefined,
      scheme,
      host: url.hostname,
      port: url.port ? Number(url.port) : scheme === "https" ? 443 : 80,
      origin: url.origin,
      canonicalPath: normalizedPath,
      normSource: "tier1",
      keyHash,
    }
  }
}