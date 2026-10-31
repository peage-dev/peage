import { fromBase64 } from '@peage/protocol'
import { type KeyObject, createPublicKey } from 'node:crypto'

import type { AttestedKeyRecord } from '../types.ts'

import { PeageError } from '../errors.ts'

export function importSpkiPublicKey(base64: string): KeyObject {
  return createPublicKey({ key: Buffer.from(fromBase64(base64)), format: 'der', type: 'spki' })
}

export function importStoredPublicKey(record: AttestedKeyRecord): KeyObject {
  try {
    return importSpkiPublicKey(record.publicKey)
  } catch (error) {
    throw new PeageError('KEY_UNKNOWN', 'Stored key record is malformed', { cause: error })
  }
}
