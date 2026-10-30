import {
  ASSERTION_BUCKET_SECONDS,
  assertionBucket,
  canonicalRequestBytes,
  concatBytes,
  fromBase64,
  fromBase64url,
} from '@peage/protocol'
import { type KeyObject, X509Certificate } from 'node:crypto'

import type { AssertionInput } from './types.ts'

import { bytesEqual, sha256 } from './bytes.ts'
import { CLOCK_SKEW_MS } from './constants.ts'

export function assertValidityStarted(certificate: X509Certificate): void {
  if (Date.now() < certificate.validFromDate.getTime() - CLOCK_SKEW_MS) {
    throw new Error('Certificate is not valid yet')
  }
}

export function assertNotExpired(certificate: X509Certificate): void {
  if (Date.now() > certificate.validToDate.getTime()) {
    throw new Error('Certificate has expired')
  }
}

export function assertIssuedBy(certificate: X509Certificate, issuer: X509Certificate): void {
  if (!issuer.ca) {
    throw new Error('Certificate is issued by a certificate that is not a CA')
  }
  if (!certificate.checkIssued(issuer) || !certificate.verify(issuer.publicKey)) {
    throw new Error('Certificate is not signed by the next certificate in the chain')
  }
}

/** keyId = SHA-256 of the uncompressed P-256 point (0x04 ‖ x ‖ y), as Apple defines it. */
export function assertKeyIdMatches(publicKey: KeyObject, keyId: string): void {
  const jwk = publicKey.export({ format: 'jwk' })
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new Error('Attested key is not P-256')
  }
  const uncompressedPoint = concatBytes(
    Uint8Array.of(0x04),
    fromBase64url(jwk.x),
    fromBase64url(jwk.y),
  )
  if (!bytesEqual(sha256(uncompressedPoint), fromBase64(keyId))) {
    throw new Error('Key id does not match the attested public key')
  }
}

export function assertSignatureMatchesRecentBucket(
  input: AssertionInput,
  verifySignature: (clientDataHash: Uint8Array) => boolean,
): void {
  const bodyDigest = sha256(input.body)
  const currentBucket = assertionBucket(Math.floor(Date.now() / 1000))
  const buckets = [
    currentBucket,
    currentBucket - ASSERTION_BUCKET_SECONDS,
    currentBucket + ASSERTION_BUCKET_SECONDS,
  ]
  const isSigned = buckets.some((bucket) => {
    const request = { bucket, bodyDigest, method: input.method, path: input.path }
    return verifySignature(sha256(canonicalRequestBytes(request)))
  })
  if (!isSigned) {
    throw new Error('Assertion signature does not match any recent time bucket')
  }
}
