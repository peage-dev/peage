import type { AttestedKeyRecord, IssuedChallenge } from '@peage/core'

import { isAttestationEnvironment } from '@peage/core'
import { isPlatform, isRecord } from '@peage/protocol'

export function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

export function isIssuedChallenge(value: unknown): value is IssuedChallenge {
  return (
    isRecord(value) &&
    typeof value.value === 'string' &&
    isPlatform(value.platform) &&
    typeof value.expiresAt === 'number'
  )
}

export function isAttestedKeyRecord(value: unknown): value is AttestedKeyRecord {
  return (
    isRecord(value) &&
    typeof value.keyId === 'string' &&
    isPlatform(value.platform) &&
    typeof value.appId === 'string' &&
    isAttestationEnvironment(value.environment) &&
    typeof value.publicKey === 'string' &&
    typeof value.attestedAt === 'number' &&
    (value.attestationCertificateSerialNumbers === undefined ||
      isStringList(value.attestationCertificateSerialNumbers))
  )
}
