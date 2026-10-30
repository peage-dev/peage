import type { AttestedKeyRecord, IssuedChallenge } from '@peage/core'

import { isAttestationEnvironment } from '@peage/core'
import { isPlatform, isRecord } from '@peage/protocol'

import { isStringList } from './guards.ts'

export function assertIssuedChallenge(value: unknown): asserts value is IssuedChallenge {
  if (
    !isRecord(value) ||
    typeof value.value !== 'string' ||
    !isPlatform(value.platform) ||
    typeof value.expiresAt !== 'number'
  ) {
    throw new Error('Péage found a malformed challenge in Redis')
  }
}

export function assertAttestedKeyRecord(value: unknown): asserts value is AttestedKeyRecord {
  if (
    !isRecord(value) ||
    typeof value.keyId !== 'string' ||
    !isPlatform(value.platform) ||
    typeof value.appId !== 'string' ||
    !isAttestationEnvironment(value.environment) ||
    typeof value.publicKey !== 'string' ||
    typeof value.attestedAt !== 'number' ||
    (value.attestationCertificateSerialNumbers !== undefined &&
      !isStringList(value.attestationCertificateSerialNumbers))
  ) {
    throw new Error('Péage found a malformed key record in Redis')
  }
}
