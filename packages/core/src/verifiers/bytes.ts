import { createHash } from 'node:crypto'

export function sha256(input: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(input).digest())
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  return a.every((byte, index) => byte === b[index])
}
