import { toBase64 } from '@peage/protocol'
import { generateKeyPairSync, type KeyObject } from 'node:crypto'

import { sha256 } from './hashing.ts'

/** The public half of a fresh P-256 device key. */
export function newDeviceKey(): KeyObject {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey
}

/** A keyId as Péage clients compute it: base64 SHA-256 of the uncompressed P-256 point. */
export function keyIdFor(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: 'jwk' })
  const point = Buffer.concat([
    Buffer.of(0x04),
    Buffer.from(jwk.x ?? '', 'base64url'),
    Buffer.from(jwk.y ?? '', 'base64url'),
  ])
  return toBase64(sha256(point))
}
