import type { IssuedChallenge } from '@peage/core'

import { isPlatform, isRecord } from '@peage/protocol'

import type { EncodedKeyRecord } from './types.ts'

import { KEY_RECORD_FORMAT_VERSION } from './constants.ts'

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

function isAbsentOr(value: unknown, isPresentValid: (value: unknown) => boolean): boolean {
  return value === undefined || value === null || isPresentValid(value)
}

export function isEncodedKeyRecord(value: unknown): value is EncodedKeyRecord {
  return (
    Array.isArray(value) &&
    value.length >= 6 &&
    value.length <= 8 &&
    value[0] === KEY_RECORD_FORMAT_VERSION &&
    Number.isInteger(value[1]) &&
    typeof value[2] === 'string' &&
    Number.isInteger(value[3]) &&
    typeof value[4] === 'string' &&
    typeof value[5] === 'number' &&
    isAbsentOr(value[6], (expiresAt) => typeof expiresAt === 'number') &&
    isAbsentOr(value[7], isStringList)
  )
}
