import type { JsonWebKey } from 'node:crypto'

/** `ECDH.convertKey` returns bytes when no output encoding is given. */
export function assertConvertedPoint(point: string | Uint8Array): asserts point is Uint8Array {
  if (typeof point === 'string') {
    throw new TypeError('Expected the converted point as bytes')
  }
}

export function assertP256Jwk(
  jwk: JsonWebKey,
): asserts jwk is JsonWebKey & { x: string; y: string } {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new TypeError('Key record public key is not P-256')
  }
}
