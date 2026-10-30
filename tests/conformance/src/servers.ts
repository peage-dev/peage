import type { RequestListener, Server } from 'node:http'

import { listenOnLoopback, portOf } from '@peage/tests'

const openServers: Server[] = []

/** Serves on a loopback port until `closeServers` and returns the base URL. */
export async function serve(listener: RequestListener): Promise<string> {
  const server = await listenOnLoopback(listener)
  openServers.push(server)
  return `http://127.0.0.1:${portOf(server)}`
}

export function closeServers(): void {
  for (const server of openServers.splice(0)) {
    server.closeAllConnections()
    server.close()
  }
}
