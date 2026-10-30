import { concatBytes, fromBase64, fromBase64url } from '@peage/protocol'
import { createDecipheriv, verify } from 'node:crypto'

import type { AttestationEnvironment, RegistrationRequest } from '../../types.ts'
import type { AttestedKey } from '../types.ts'
import type {
  AttestationApplicationId,
  PlayIntegrityProof,
  PlayIntegrityVerdict,
  ResolvedPlayIntegrityConfig,
} from './types.ts'

import { assertKeyIdMatches } from '../asserters.ts'
import { bytesEqual, sha256 } from '../bytes.ts'
import { CLOCK_SKEW_MS } from '../constants.ts'
import {
  assertJweHeader,
  assertJwsHeader,
  assertMeetsDeviceIntegrity,
  assertNotRevoked,
  assertValidPlayIntegrityProof,
  assertValidPlayIntegrityVerdict,
} from './asserters.ts'
import {
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
  AES_KEY_WRAP_IV,
  PLAY_INTEGRITY_MAX_TOKEN_AGE_MS,
  PLAY_INTEGRITY_PROOF_MAX_BYTES,
} from './constants.ts'
import { revocationSerialOf } from './revocationList.ts'
import { decodeCertificateChain, verifyKeyAttestation } from './verifyKeyAttestation.ts'

function decodeSegment(segment: string, name: string): Uint8Array {
  try {
    return fromBase64url(segment)
  } catch {
    throw new Error(`${name} is not base64url`)
  }
}

function parseJson(bytes: Uint8Array, name: string): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    throw new Error(`${name} is not valid JSON`)
  }
}

function decodePlayIntegrityProof(proof: Uint8Array): PlayIntegrityProof {
  if (proof.length > PLAY_INTEGRITY_PROOF_MAX_BYTES) {
    throw new Error('Play Integrity proof is too large')
  }

  const decoded = parseJson(proof, 'Play Integrity proof')
  assertValidPlayIntegrityProof(decoded)

  return { integrityToken: decoded.integrityToken, certificateChain: decoded.certificateChain }
}

function unwrapContentKey(encryptedKey: Uint8Array, config: ResolvedPlayIntegrityConfig): Buffer {
  try {
    const keyUnwrap = createDecipheriv('id-aes256-wrap', config.decryptionKey, AES_KEY_WRAP_IV)
    return Buffer.concat([keyUnwrap.update(encryptedKey), keyUnwrap.final()])
  } catch {
    throw new Error('Play Integrity token was not encrypted for the configured decryption key')
  }
}

function decryptJweContent(
  contentKey: Buffer,
  protectedHeader: string,
  segments: { iv: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array },
): string {
  if (segments.iv.length !== AES_GCM_IV_BYTES) {
    throw new Error('Play Integrity token has a malformed IV')
  }
  if (segments.tag.length !== AES_GCM_TAG_BYTES) {
    throw new Error('Play Integrity token has a malformed authentication tag')
  }

  const decipher = createDecipheriv('aes-256-gcm', contentKey, segments.iv, {
    authTagLength: AES_GCM_TAG_BYTES,
  })
  decipher.setAAD(Buffer.from(protectedHeader, 'ascii'))
  decipher.setAuthTag(segments.tag)
  try {
    return Buffer.concat([decipher.update(segments.ciphertext), decipher.final()]).toString('utf8')
  } catch {
    throw new Error('Play Integrity token failed authentication')
  }
}

function splitJwe(token: string) {
  const [protectedHeader, encryptedKey, iv, ciphertext, tag, ...extra] = token.split('.')
  if (
    protectedHeader === undefined ||
    encryptedKey === undefined ||
    iv === undefined ||
    ciphertext === undefined ||
    tag === undefined ||
    extra.length > 0
  ) {
    throw new Error('Play Integrity token is not a compact JWE')
  }
  return { protectedHeader, encryptedKey, iv, ciphertext, tag }
}

function splitJws(jws: string) {
  const [protectedHeader, payload, signature, ...extra] = jws.split('.')
  if (
    protectedHeader === undefined ||
    payload === undefined ||
    signature === undefined ||
    extra.length > 0
  ) {
    throw new Error('Play Integrity verdict is not a compact JWS')
  }
  return { protectedHeader, payload, signature }
}

function decryptIntegrityToken(token: string, config: ResolvedPlayIntegrityConfig): string {
  const { protectedHeader, encryptedKey, iv, ciphertext, tag } = splitJwe(token)

  assertJweHeader(parseJson(decodeSegment(protectedHeader, 'JWE header'), 'JWE header'))
  const contentKey = unwrapContentKey(decodeSegment(encryptedKey, 'JWE key'), config)
  return decryptJweContent(contentKey, protectedHeader, {
    iv: decodeSegment(iv, 'JWE IV'),
    ciphertext: decodeSegment(ciphertext, 'JWE ciphertext'),
    tag: decodeSegment(tag, 'JWE tag'),
  })
}

function decodeSignedVerdict(
  jws: string,
  config: ResolvedPlayIntegrityConfig,
): PlayIntegrityVerdict {
  const { protectedHeader, payload, signature } = splitJws(jws)

  assertJwsHeader(parseJson(decodeSegment(protectedHeader, 'JWS header'), 'JWS header'))

  const isSigned = verify(
    'sha256',
    Buffer.from(`${protectedHeader}.${payload}`, 'ascii'),
    { key: config.verificationKey, dsaEncoding: 'ieee-p1363' },
    decodeSegment(signature, 'JWS signature'),
  )
  if (!isSigned) {
    throw new Error('Play Integrity verdict signature is invalid')
  }

  const verdict = parseJson(decodeSegment(payload, 'JWS payload'), 'Play Integrity verdict')
  assertValidPlayIntegrityVerdict(verdict)
  return verdict
}

function getPlayIntegrityExpectedNonce(challenge: string, publicKey: Uint8Array): Uint8Array {
  return sha256(concatBytes(sha256(challenge), publicKey))
}

function verifyRequestDetails(
  requestDetails: PlayIntegrityVerdict['requestDetails'],
  challenge: string,
  publicKey: Uint8Array,
  config: ResolvedPlayIntegrityConfig,
): void {
  if (requestDetails.requestPackageName !== config.packageName) {
    throw new Error('Play Integrity verdict was requested by a different package')
  }

  const expectedNonce = getPlayIntegrityExpectedNonce(challenge, publicKey)
  if (!bytesEqual(decodeSegment(requestDetails.nonce, 'Verdict nonce'), expectedNonce)) {
    throw new Error('Play Integrity nonce does not bind the issued challenge and key')
  }

  const tokenAgeMs = Date.now() - Number(requestDetails.timestampMillis)
  if (tokenAgeMs > PLAY_INTEGRITY_MAX_TOKEN_AGE_MS) {
    throw new Error('Play Integrity verdict is too old')
  }
  if (tokenAgeMs < -CLOCK_SKEW_MS) {
    throw new Error('Play Integrity verdict is from the future')
  }
}

/**
 * The verdict names the signing certificate of the app that requested the
 * token; the key attestation names the one of the app that generated the key.
 */
function verifyAppIntegrity(
  appIntegrity: PlayIntegrityVerdict['appIntegrity'],
  attestedApplication: AttestationApplicationId,
  config: ResolvedPlayIntegrityConfig,
): void {
  const { appRecognitionVerdict } = appIntegrity
  const isAllowedUnrecognized =
    config.allowUnrecognizedApps && appRecognitionVerdict === 'UNRECOGNIZED_VERSION'
  if (appRecognitionVerdict !== 'PLAY_RECOGNIZED' && !isAllowedUnrecognized) {
    throw new Error(`Play Integrity app verdict is ${appRecognitionVerdict}, not PLAY_RECOGNIZED`)
  }

  if (appIntegrity.packageName !== config.packageName) {
    throw new Error('Play Integrity verdict names a different package')
  }

  const verdictDigests = (appIntegrity.certificateSha256Digest ?? []).map((digest) =>
    decodeSegment(digest, 'Verdict certificate digest'),
  )
  const isSameSigner = verdictDigests.some((verdictDigest) =>
    attestedApplication.signatureDigests.some((attested) => bytesEqual(verdictDigest, attested)),
  )
  if (!isSameSigner) {
    throw new Error(
      'Play Integrity verdict and key attestation name different signing certificates',
    )
  }
}

function environmentOf(appIntegrity: PlayIntegrityVerdict['appIntegrity']): AttestationEnvironment {
  return appIntegrity.appRecognitionVerdict === 'PLAY_RECOGNIZED' ? 'production' : 'development'
}

export function verifyPlayIntegrityAttestation(
  { proof, challenge, keyId }: RegistrationRequest,
  config: ResolvedPlayIntegrityConfig,
  revokedSerialNumbers: ReadonlySet<string>,
): AttestedKey {
  const decoded = decodePlayIntegrityProof(proof)
  const certificates = decodeCertificateChain(decoded.certificateChain.map(fromBase64))
  const { leaf, chain, application } = verifyKeyAttestation(
    certificates,
    { challenge, packageName: config.packageName },
    config.keyAttestationRoots,
  )
  assertKeyIdMatches(leaf.publicKey, keyId)

  const spki = new Uint8Array(leaf.publicKey.export({ format: 'der', type: 'spki' }))
  const jws = decryptIntegrityToken(decoded.integrityToken, config)
  const verdict = decodeSignedVerdict(jws, config)
  verifyRequestDetails(verdict.requestDetails, challenge, spki, config)
  verifyAppIntegrity(verdict.appIntegrity, application, config)
  assertMeetsDeviceIntegrity(verdict.deviceIntegrity)

  const attestationCertificateSerialNumbers = chain.map(revocationSerialOf)
  assertNotRevoked(attestationCertificateSerialNumbers, revokedSerialNumbers)
  return {
    publicKey: leaf.publicKey,
    appId: config.packageName,
    environment: environmentOf(verdict.appIntegrity),
    attestationCertificateSerialNumbers,
  }
}
