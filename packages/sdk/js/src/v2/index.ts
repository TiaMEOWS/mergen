export * from "./client.js"
export * from "./server.js"

import { createMergenClient } from "./client.js"
import { createMergenServer } from "./server.js"
import type { ServerOptions } from "./server.js"

export async function createMergen(options?: ServerOptions) {
  const server = await createMergenServer({
    ...options,
  })

  const client = createMergenClient({
    baseUrl: server.url,
  })

  return {
    client,
    server,
  }
}
