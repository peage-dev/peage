import type { KeyObject, X509Certificate } from 'node:crypto'

import { isRecord } from '@peage/protocol'

import type { PlayIntegrityProof, PlayIntegrityVerdict } from './types.ts'

import {
  PLAY_INTEGRITY_JWE_ALGORITHM,
  PLAY_INTEGRITY_JWE_ENCRYPTION,
  PLAY_INTEGRITY_JWS_ALGORITHM,
  REVOCATION_SERIAL_NUMBER_PATTERN,
  SECURITY_LEVEL_STRONGBOX,
  SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
} from './constants.ts'
import { isStringList } from './guards.ts'

type RevocationListResponse = { entries: Record<string, unknown> }

export function assertHardwareBacked(securityLevel: number, failureMessage: string): void {
  if (
    securityLevel !== SECURITY_LEVEL_TRUSTED_ENVIRONMENT &&
    securityLevel !== SECURITY_LEVEL_STRONGBOX
  ) {
    throw new Error(failureMessage)
  }
}

export function assertRootOnlyLast(chain: X509Certificate[], trustedRoot: X509Certificate): void {
  const belowRoot = chain.slice(0, -1)
  if (belowRoot.some((certificate) => certificate.publicKey.equals(trustedRoot.publicKey))) {
    throw new Error('Key attestation chain repeats its root')
  }
}

export function assertValidRevocationList(value: unknown): asserts value is RevocationListResponse {
  if (!isRecord(value) || !isRecord(value.entries)) {
    throw new Error('Key attestation revocation list has no entries')
  }
  const serialNumbers = Object.keys(value.entries)
  if (!serialNumbers.every((serial) => REVOCATION_SERIAL_NUMBER_PATTERN.test(serial))) {
    throw new Error('Key attestation revocation list has a malformed serial number')
  }
}

export function assertNotRevoked(
  serialNumbers: string[],
  revokedSerialNumbers: ReadonlySet<string>,
): void {
  if (serialNumbers.some((serialNumber) => revokedSerialNumbers.has(serialNumber))) {
    throw new Error('Key attestation chain contains a revoked certificate')
  }
}

export function assertValidPlayIntegrityProof(value: unknown): asserts value is PlayIntegrityProof {
  if (!isRecord(value)) {
    throw new Error('Play Integrity proof is not a JSON object')
  }
  if (typeof value.integrityToken !== 'string') {
    throw new Error('Play Integrity proof integrityToken is missing')
  }
  if (!isStringList(value.certificateChain)) {
    throw new Error('Play Integrity proof certificateChain is missing')
  }
}

export function assertValidPlayIntegrityVerdict(
  value: unknown,
): asserts value is PlayIntegrityVerdict {
  if (!isRecord(value)) {
    throw new Error('Play Integrity verdict is not a JSON object')
  }

  const { requestDetails } = value
  if (!isRecord(requestDetails)) {
    throw new Error('Play Integrity verdict requestDetails is missing')
  }
  if (typeof requestDetails.requestPackageName !== 'string') {
    throw new Error('Play Integrity verdict requestPackageName is missing')
  }
  if (typeof requestDetails.nonce !== 'string') {
    throw new Error('Play Integrity verdict nonce is missing')
  }
  if (typeof requestDetails.timestampMillis !== 'string') {
    throw new Error('Play Integrity verdict timestampMillis is missing')
  }
  if (!/^\d+$/.test(requestDetails.timestampMillis)) {
    throw new Error('Play Integrity verdict timestampMillis is not a number')
  }

  const { appIntegrity } = value
  if (!isRecord(appIntegrity)) {
    throw new Error('Play Integrity verdict appIntegrity is missing')
  }
  if (typeof appIntegrity.appRecognitionVerdict !== 'string') {
    throw new Error('Play Integrity verdict appRecognitionVerdict is missing')
  }
  if (appIntegrity.packageName !== undefined && typeof appIntegrity.packageName !== 'string') {
    throw new Error('Play Integrity verdict packageName is not a string')
  }
  const { certificateSha256Digest } = appIntegrity
  if (certificateSha256Digest !== undefined && !isStringList(certificateSha256Digest)) {
    throw new Error('Play Integrity verdict certificateSha256Digest is not a list of digests')
  }

  const { deviceIntegrity } = value
  if (!isRecord(deviceIntegrity)) {
    throw new Error('Play Integrity verdict deviceIntegrity is missing')
  }
  const { deviceRecognitionVerdict } = deviceIntegrity
  if (deviceRecognitionVerdict !== undefined && !isStringList(deviceRecognitionVerdict)) {
    throw new Error('Play Integrity verdict deviceRecognitionVerdict is not a list of labels')
  }
}

export function assertJweHeader(header: unknown): void {
  if (!isRecord(header)) {
    throw new Error('Play Integrity token header is not a JSON object')
  }
  if (header.alg !== PLAY_INTEGRITY_JWE_ALGORITHM || header.enc !== PLAY_INTEGRITY_JWE_ENCRYPTION) {
    throw new Error('Play Integrity token uses an unexpected JWE algorithm')
  }
}

export function assertJwsHeader(header: unknown): void {
  if (!isRecord(header) || header.alg !== PLAY_INTEGRITY_JWS_ALGORITHM) {
    throw new Error('Play Integrity verdict uses an unexpected JWS algorithm')
  }
}

export function assertMeetsDeviceIntegrity(
  deviceIntegrity: PlayIntegrityVerdict['deviceIntegrity'],
): void {
  if (!deviceIntegrity.deviceRecognitionVerdict?.includes('MEETS_DEVICE_INTEGRITY')) {
    throw new Error('Play Integrity device verdict does not meet device integrity')
  }
}

export function assertValidDecryptionKey(decryptionKey: Uint8Array): void {
  if (decryptionKey.length !== 32) {
    throw new Error('Play Integrity decryptionKey must be a base64 AES-256 key')
  }
}

export function assertValidVerificationKey(verificationKey: KeyObject): void {
  if (verificationKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('Play Integrity verificationKey must be an EC P-256 public key')
  }
}
