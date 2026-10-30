import { concatBytes, fromBase64 } from '@peage/protocol'
import { type KeyObject, X509Certificate } from 'node:crypto'

import type { AppAttestConfig, RegistrationRequest } from '../../types.ts'
import type { AppAttestObject } from './types.ts'

import { assertKeyIdMatches, assertNotExpired, assertValidityStarted } from '../asserters.ts'
import { bytesEqual, sha256 } from '../bytes.ts'
import { getCertificateExtension, verifyCertificateSignatures } from '../certificates.ts'
import { assertExpectedAaguid, assertRpIdHash, assertValidAppAttestObject } from './asserters.ts'
import {
  APP_ATTEST_AUTH_DATA_HEADER_LENGTH,
  APP_ATTEST_CREDENTIAL_DATA_FLAG,
  APP_ATTEST_CREDENTIAL_ID_LENGTH_OFFSET,
  APP_ATTEST_CREDENTIAL_OFFSET,
  APP_ATTEST_FLAGS_OFFSET,
  APP_ATTEST_NONCE_OID,
  APP_ATTEST_NONCE_PREFIX,
  APP_ATTEST_PROOF_MAX_BYTES,
  APP_ATTEST_PROOF_MIN_BYTES,
  APP_ATTEST_ROOT_CA,
  APP_ATTEST_SIGN_COUNT_OFFSET,
  SHA256_BYTES,
} from './constants.ts'
import { decodeStrictCbor } from './decodeStrictCbor.ts'

/**
 * authData layout:
 *
 *   [0,32)  rpIdHash           — SHA-256 of the App ID
 *   [32]    flags              — bit 0x40 marks attested credential data
 *   [33,37) signCount          — always 0 for an attestation
 *   [37,53) aaguid             — App Attest environment marker
 *   [53,55) credentialIdLength — uint16, big-endian
 *   [55,..) credentialId       — the attested key id
 *
 * The credentialPublicKey and, since iOS 27, a CBOR extensions map follow;
 * they aren't parsed, but the challenge nonce covers them.
 */
type AttestationAuthData = {
  rpIdHash: Uint8Array
  flags: number
  signCount: Uint8Array
  aaguid: Uint8Array
  credentialId: Uint8Array
}

export function decodeAttestation(proof: Uint8Array): AppAttestObject {
  if (proof.length < APP_ATTEST_PROOF_MIN_BYTES || proof.length > APP_ATTEST_PROOF_MAX_BYTES) {
    throw new Error('App Attest proof length is outside the expected byte range')
  }

  const decoded = decodeStrictCbor(proof)
  assertValidAppAttestObject(decoded)

  return {
    fmt: decoded.fmt,
    attStmt: { x5c: decoded.attStmt.x5c },
    authData: decoded.authData,
  }
}

function parseAuthData(authData: Uint8Array): AttestationAuthData {
  if (authData.length < APP_ATTEST_CREDENTIAL_OFFSET) {
    throw new Error('App Attest authData is too short to contain attested credential data')
  }

  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength)
  const credentialIdLength = view.getUint16(APP_ATTEST_CREDENTIAL_ID_LENGTH_OFFSET)
  const credentialId = authData.subarray(
    APP_ATTEST_CREDENTIAL_OFFSET,
    APP_ATTEST_CREDENTIAL_OFFSET + credentialIdLength,
  )
  if (credentialId.length !== credentialIdLength) {
    throw new Error('App Attest authData credentialId is truncated')
  }

  return {
    rpIdHash: authData.subarray(0, APP_ATTEST_FLAGS_OFFSET),
    flags: view.getUint8(APP_ATTEST_FLAGS_OFFSET),
    signCount: authData.subarray(APP_ATTEST_SIGN_COUNT_OFFSET, APP_ATTEST_AUTH_DATA_HEADER_LENGTH),
    aaguid: authData.subarray(
      APP_ATTEST_AUTH_DATA_HEADER_LENGTH,
      APP_ATTEST_CREDENTIAL_ID_LENGTH_OFFSET,
    ),
    credentialId,
  }
}

/** Leaf first, trusted root last. */
export function verifyCertificateChain(certificates: X509Certificate[]): X509Certificate {
  const leaf = verifyCertificateSignatures(certificates)
  certificates.forEach(assertValidityStarted)
  certificates.forEach(assertNotExpired)
  return leaf
}

export function parseNonceExtension(extension: Uint8Array): Uint8Array {
  if (extension.length !== APP_ATTEST_NONCE_PREFIX.length + SHA256_BYTES) {
    throw new Error('App Attest nonce extension has an unexpected length')
  }
  if (!bytesEqual(extension.subarray(0, APP_ATTEST_NONCE_PREFIX.length), APP_ATTEST_NONCE_PREFIX)) {
    throw new Error('App Attest nonce extension has an unexpected structure')
  }
  return extension.subarray(APP_ATTEST_NONCE_PREFIX.length)
}

export function getAppAttestExpectedNonce(challenge: string, authData: Uint8Array): Uint8Array {
  return sha256(concatBytes(authData, sha256(challenge)))
}

export function verifyChallenge(
  leaf: X509Certificate,
  authData: Uint8Array,
  challenge: string,
): void {
  const extension = getCertificateExtension(leaf.raw, APP_ATTEST_NONCE_OID)
  if (!extension) {
    throw new Error('Certificate is missing the nonce extension')
  }

  const certificateNonce = parseNonceExtension(extension)
  if (!bytesEqual(certificateNonce, getAppAttestExpectedNonce(challenge, authData))) {
    throw new Error('App Attest nonce does not bind the issued challenge')
  }
}

export function verifyAuthData(authData: Uint8Array, keyId: string, config: AppAttestConfig): void {
  const { rpIdHash, flags, signCount, aaguid, credentialId } = parseAuthData(authData)

  if ((flags & APP_ATTEST_CREDENTIAL_DATA_FLAG) === 0) {
    throw new Error('App Attest authData does not carry attested credential data')
  }
  assertRpIdHash(rpIdHash, config.appId)
  if (signCount.some((byte) => byte !== 0)) {
    throw new Error('App Attest authData signCount must be zero for an attestation')
  }
  assertExpectedAaguid(aaguid, config.environment)
  if (!bytesEqual(credentialId, fromBase64(keyId))) {
    throw new Error('App Attest authData credentialId does not match the client key id')
  }
}

export function verifyAppAttestAttestation(
  { proof, challenge, keyId }: RegistrationRequest,
  config: AppAttestConfig,
): KeyObject {
  const decoded = decodeAttestation(proof)
  const attestationCertificates = decoded.attStmt.x5c.map((der) => new X509Certificate(der))
  const leaf = verifyCertificateChain([...attestationCertificates, APP_ATTEST_ROOT_CA])
  assertKeyIdMatches(leaf.publicKey, keyId)
  verifyChallenge(leaf, decoded.authData, challenge)
  verifyAuthData(decoded.authData, keyId, config)
  return leaf.publicKey
}
