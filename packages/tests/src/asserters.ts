import type { AddressInfo } from 'node:net'

export function assertTcpAddress(
  address: AddressInfo | string | null,
): asserts address is AddressInfo {
  if (address === null || typeof address === 'string') {
    throw new Error('server is not listening on a TCP port')
  }
}
