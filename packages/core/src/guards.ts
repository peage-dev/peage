import { fromBase64, toBase64 } from '@peage/protocol'

import type { AttestationEnvironment } from './types.ts'

/** Whether the value is an attestation environment Péage supports. */
export function isAttestationEnvironment(value: unknown): value is AttestationEnvironment {
  return value === 'production' || value === 'development'
}

/** One spelling per key: padded standard base64 of 32 bytes, as Apple emits it. */
export function isCanonicalKeyId(keyId: string): boolean {
  return /^[A-Za-z0-9+/]{43}=$/.test(keyId) && toBase64(fromBase64(keyId)) === keyId
}
