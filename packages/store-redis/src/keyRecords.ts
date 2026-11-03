import type { AttestedKeyRecord } from '@peage/core'

import { fromBase64, toBase64 } from '@peage/protocol'

import type { EncodedKeyRecord } from './types.ts'

import { ENVIRONMENTS, KEY_RECORD_FORMAT_VERSION, PLATFORMS } from './constants.ts'
import { isEncodedKeyRecord } from './guards.ts'
import { compressPublicKey, decompressPublicKey } from './publicKeys.ts'

function withoutPadding(base64: string): string {
  return base64.replace(/=+$/, '')
}

/** Revocation-list hex, e.g. `-7fff`, as a sign and the unpadded base64 of its bytes. */
function encodeSerialNumber(serialNumber: string): string {
  const isNegative = serialNumber.startsWith('-')
  const magnitude = isNegative ? serialNumber.slice(1) : serialNumber
  const bytes = Buffer.from(magnitude.length % 2 === 0 ? magnitude : `0${magnitude}`, 'hex')
  return `${isNegative ? '-' : ''}${withoutPadding(toBase64(bytes))}`
}

function decodeSerialNumber(encoded: string): string {
  const isNegative = encoded.startsWith('-')
  const bytes = fromBase64(isNegative ? encoded.slice(1) : encoded)
  const magnitude = BigInt(`0x${Buffer.from(bytes).toString('hex')}`).toString(16)
  return isNegative ? `-${magnitude}` : magnitude
}

function withoutTrailingNulls(values: unknown[]): unknown[] {
  let length = values.length
  while (length > 0 && values[length - 1] === null) {
    length -= 1
  }
  return values.slice(0, length)
}

/**
 * `[version, platform, appId, environment, publicKey, attestedAt, expiresAt, serialNumbers]`,
 * without the keyId, which is in the Redis key, and without trailing absent fields.
 */
export function encodeAttestedKeyRecord(record: AttestedKeyRecord): unknown[] {
  const encoded: EncodedKeyRecord = [
    KEY_RECORD_FORMAT_VERSION,
    PLATFORMS.indexOf(record.platform),
    record.appId,
    ENVIRONMENTS.indexOf(record.environment),
    compressPublicKey(record.publicKey),
    record.attestedAt,
    record.expiresAt ?? null,
    record.attestationCertificateSerialNumbers?.map(encodeSerialNumber) ?? null,
  ]
  return withoutTrailingNulls(encoded)
}

function decodeFields(keyId: string, encoded: EncodedKeyRecord): AttestedKeyRecord | null {
  const [
    _version,
    platformIndex,
    appId,
    environmentIndex,
    publicKey,
    attestedAt,
    expiresAt,
    serialNumbers,
  ] = encoded
  const platform = PLATFORMS[platformIndex]
  const environment = ENVIRONMENTS[environmentIndex]
  if (platform === undefined || environment === undefined) {
    return null
  }
  const record: AttestedKeyRecord = {
    keyId,
    platform,
    appId,
    environment,
    publicKey: decompressPublicKey(publicKey),
    attestedAt,
  }
  if (typeof expiresAt === 'number') {
    record.expiresAt = expiresAt
  }
  if (Array.isArray(serialNumbers)) {
    record.attestationCertificateSerialNumbers = serialNumbers.map(decodeSerialNumber)
  }
  return record
}

/** The record stored under `keyId`, or null when it isn't in the current format. */
export function decodeAttestedKeyRecord(keyId: string, encoded: unknown): AttestedKeyRecord | null {
  if (!isEncodedKeyRecord(encoded)) {
    return null
  }
  try {
    return decodeFields(keyId, encoded)
  } catch {
    return null
  }
}
