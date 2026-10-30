import { concatBytes } from '@peage/protocol'
import { verify } from 'node:crypto'

import type { AppAttestConfig } from '../../types.ts'
import type { AssertionInput } from '../types.ts'
import type { AssertionEnvelope } from './types.ts'

import { assertSignatureMatchesRecentBucket } from '../asserters.ts'
import { sha256 } from '../bytes.ts'
import { assertRpIdHash, assertValidAssertionEnvelope } from './asserters.ts'
import { APP_ATTEST_AUTH_DATA_HEADER_LENGTH, SHA256_BYTES } from './constants.ts'
import { decodeStrictCbor } from './decodeStrictCbor.ts'

function decodeAssertion(blob: Uint8Array): AssertionEnvelope {
  const decoded = decodeStrictCbor(blob)
  assertValidAssertionEnvelope(decoded)
  return { authenticatorData: decoded.authenticatorData, signature: decoded.signature }
}

/**
 * Apple signs with CryptoKit, which hashes its input: the ECDSA digest is
 * SHA256(SHA256(authenticatorData ‖ clientDataHash)).
 */
function verifySignature(
  envelope: AssertionEnvelope,
  input: AssertionInput,
  clientDataHash: Uint8Array,
): boolean {
  const nonce = sha256(concatBytes(envelope.authenticatorData, clientDataHash))
  return verify('sha256', nonce, input.publicKey, envelope.signature)
}

export function verifyAppAttestAssertion(input: AssertionInput, config: AppAttestConfig): void {
  const envelope = decodeAssertion(input.assertion)
  if (envelope.authenticatorData.length < APP_ATTEST_AUTH_DATA_HEADER_LENGTH) {
    throw new Error('App Attest assertion authenticatorData is too short')
  }
  assertRpIdHash(envelope.authenticatorData.subarray(0, SHA256_BYTES), config.appId)
  assertSignatureMatchesRecentBucket(input, (clientDataHash) =>
    verifySignature(envelope, input, clientDataHash),
  )
}
