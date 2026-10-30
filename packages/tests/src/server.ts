import { createServer, type RequestListener, type Server } from 'node:http'

import { assertTcpAddress } from './asserters.ts'

/**
 * Listens on a free 127.0.0.1 port. macOS routes 127.0.0.1 connections to a
 * program bound to 127.0.0.1 over one bound to all addresses on the same port.
 */
export async function listenOnLoopback(listener: RequestListener): Promise<Server> {
  const server = createServer(listener)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return server
}

export function portOf(server: Server): number {
  const address = server.address()
  assertTcpAddress(address)
  return address.port
}
