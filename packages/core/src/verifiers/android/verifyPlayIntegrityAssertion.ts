import { verify } from 'node:crypto'

import type { AssertionInput } from '../types.ts'

import { assertSignatureMatchesRecentBucket } from '../asserters.ts'

/** The device's SHA256withECDSA hashes once: the ECDSA digest is SHA256(clientDataHash). */
export function verifyPlayIntegrityAssertion(input: AssertionInput): void {
  assertSignatureMatchesRecentBucket(input, (clientDataHash) =>
    verify('sha256', clientDataHash, input.publicKey, input.assertion),
  )
}
