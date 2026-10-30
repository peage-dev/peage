import { fromBase64 } from '@peage/protocol'
import { type KeyObject, createPublicKey } from 'node:crypto'

export function importSpkiPublicKey(base64: string): KeyObject {
  return createPublicKey({ key: Buffer.from(fromBase64(base64)), format: 'der', type: 'spki' })
}
