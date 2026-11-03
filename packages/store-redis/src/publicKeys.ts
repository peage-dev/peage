import { concatBytes, fromBase64, fromBase64url, toBase64 } from '@peage/protocol'
import { ECDH, createPublicKey } from 'node:crypto'

import { assertConvertedPoint, assertP256Jwk } from './asserters.ts'
import { P256_SPKI_HEADER } from './constants.ts'

const CURVE = 'prime256v1'

function convertPoint(point: Uint8Array, format: 'compressed' | 'uncompressed'): Uint8Array {
  const converted = ECDH.convertKey(point, CURVE, undefined, undefined, format)
  assertConvertedPoint(converted)
  return converted
}

/** The 33-byte compressed point of a base64 SPKI P-256 key, in base64. */
export function compressPublicKey(spki: string): string {
  const jwk = createPublicKey({
    key: Buffer.from(fromBase64(spki)),
    format: 'der',
    type: 'spki',
  }).export({ format: 'jwk' })
  assertP256Jwk(jwk)
  const point = concatBytes(Uint8Array.of(0x04), fromBase64url(jwk.x), fromBase64url(jwk.y))
  return toBase64(convertPoint(point, 'compressed'))
}

/** The base64 SPKI of a P-256 key from its compressed point in base64. */
export function decompressPublicKey(compressedPoint: string): string {
  const point = convertPoint(fromBase64(compressedPoint), 'uncompressed')
  return toBase64(concatBytes(P256_SPKI_HEADER, point))
}
