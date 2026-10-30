import { concatBytes } from '@peage/protocol'
import {
  createCipheriv,
  createSign,
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
  sign,
} from 'node:crypto'

import type {
  PlayIntegrityTestKeys,
  PlayIntegrityVerdictParams,
  PlayIntegrityVerdictPayload,
  RequestToSign,
} from './types.ts'

import { clientDataHashOf } from './canonicalRequest.ts'
import { sha256 } from './hashing.ts'

/** RFC 3394's default initial value for AES key wrap. */
const AES_KEY_WRAP_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex')

/** SHA-256 of the genuine test app's signing certificate, in verdicts and key attestations alike. */
export const APP_SIGNING_CERTIFICATE_DIGEST: Uint8Array = sha256(
  'Péage test app signing certificate',
)

export function createPlayIntegrityKeys(): PlayIntegrityTestKeys {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  return {
    decryptionKey: randomBytes(32).toString('base64'),
    verificationKey: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    signingKey: privateKey,
  }
}

function base64url(input: Uint8Array | string): string {
  return Buffer.from(input).toString('base64url')
}

/** Signs a verdict as Google does: a compact ES256 JWS. */
export function signPlayIntegrityVerdict(
  payload: unknown,
  keys: PlayIntegrityTestKeys,
  header: object = { alg: 'ES256' },
): string {
  const jwsHeader = base64url(JSON.stringify(header))
  const jwsPayload = base64url(JSON.stringify(payload))
  const jwsSignature = sign('sha256', Buffer.from(`${jwsHeader}.${jwsPayload}`), {
    key: keys.signingKey,
    dsaEncoding: 'ieee-p1363',
  })
  return `${jwsHeader}.${jwsPayload}.${base64url(jwsSignature)}`
}

/** Encrypts a signed verdict as Google does: a compact A256KW/A256GCM JWE. */
export function encryptPlayIntegrityVerdict(
  jws: string,
  keys: PlayIntegrityTestKeys,
  header: object = { alg: 'A256KW', enc: 'A256GCM' },
): string {
  const jweHeader = base64url(JSON.stringify(header))
  const contentKey = randomBytes(32)
  const keyWrap = createCipheriv(
    'id-aes256-wrap',
    Buffer.from(keys.decryptionKey, 'base64'),
    AES_KEY_WRAP_IV,
  )
  const encryptedKey = Buffer.concat([keyWrap.update(contentKey), keyWrap.final()])

  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', contentKey, iv)
  cipher.setAAD(Buffer.from(jweHeader, 'ascii'))
  const ciphertext = Buffer.concat([cipher.update(jws, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()

  return [jweHeader, encryptedKey, iv, ciphertext, tag]
    .map((part) => (typeof part === 'string' ? part : base64url(part)))
    .join('.')
}

/** Encodes a verdict as Google does for classic requests: an ES256 JWS in an A256KW/A256GCM JWE. */
export function encodePlayIntegrityToken(payload: unknown, keys: PlayIntegrityTestKeys): string {
  return encryptPlayIntegrityVerdict(signPlayIntegrityVerdict(payload, keys), keys)
}

/**
 * The nonce a Péage Android client hands to Play Integrity:
 * base64url(SHA-256(SHA-256(challenge) ‖ SPKI DER of the device key)).
 */
export function playIntegrityNonce(challenge: string, publicKey: KeyObject): string {
  const spki = publicKey.export({ format: 'der', type: 'spki' })
  return base64url(sha256(concatBytes(sha256(challenge), spki)))
}

/** A classic-request verdict that passes every Péage check, unless overridden. */
export function playIntegrityVerdict(
  params: PlayIntegrityVerdictParams,
): PlayIntegrityVerdictPayload {
  const signingCertificateDigests = params.signingCertificateDigests ?? [
    APP_SIGNING_CERTIFICATE_DIGEST,
  ]
  return {
    requestDetails: {
      requestPackageName: params.packageName,
      nonce: params.nonce,
      timestampMillis: String(params.timestampMillis ?? Date.now()),
    },
    appIntegrity: {
      appRecognitionVerdict: params.appRecognitionVerdict ?? 'PLAY_RECOGNIZED',
      packageName: params.packageName,
      certificateSha256Digest: signingCertificateDigests.map((digest) => base64url(digest)),
      versionCode: '1',
    },
    deviceIntegrity: {
      deviceRecognitionVerdict: params.deviceRecognitionVerdict ?? ['MEETS_DEVICE_INTEGRITY'],
    },
    accountDetails: { appLicensingVerdict: 'LICENSED' },
  }
}

/** The `proof` bytes an Android client submits: UTF-8 JSON `{ integrityToken, certificateChain }`. */
export function playIntegrityProof(integrityToken: string, certificateChain: string[]): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ integrityToken, certificateChain }))
}

/** Signs as the Android Keystore's SHA256withECDSA does. */
export function signPlayIntegrityClientDataHash(
  privateKey: KeyObject,
  clientDataHash: Uint8Array,
): Uint8Array {
  return new Uint8Array(createSign('sha256').update(clientDataHash).sign(privateKey))
}

/** Signs a request as a Péage Android client does. */
export function signPlayIntegrityRequest(
  params: { privateKey: KeyObject } & RequestToSign,
): Uint8Array {
  return signPlayIntegrityClientDataHash(params.privateKey, clientDataHashOf(params))
}
